package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.Path;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.InflateException;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.ListView;
import androidx.collection.ArrayMap;
import androidx.collection.LongSparseArray;
import androidx.collection.SimpleArrayMap;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.view.ViewCompat;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

public abstract class Transition implements Cloneable {
    static final boolean DBG = false;
    private static final int[] DEFAULT_MATCH_ORDER = {2, 1, 3, 4};
    private static final String LOG_TAG = "Transition";
    private static final int MATCH_FIRST = 1;
    public static final int MATCH_ID = 3;
    private static final String MATCH_ID_STR = "id";
    public static final int MATCH_INSTANCE = 1;
    private static final String MATCH_INSTANCE_STR = "instance";
    public static final int MATCH_ITEM_ID = 4;
    private static final String MATCH_ITEM_ID_STR = "itemId";
    private static final int MATCH_LAST = 4;
    public static final int MATCH_NAME = 2;
    private static final String MATCH_NAME_STR = "name";
    private static final PathMotion STRAIGHT_PATH_MOTION = new PathMotion() {
        public Path getPath(float startX, float startY, float endX, float endY) {
            Path path = new Path();
            path.moveTo(startX, startY);
            path.lineTo(endX, endY);
            return path;
        }
    };
    private static ThreadLocal<ArrayMap<Animator, AnimationInfo>> sRunningAnimators = new ThreadLocal<>();
    private ArrayList<Animator> mAnimators = new ArrayList<>();
    boolean mCanRemoveViews = false;
    ArrayList<Animator> mCurrentAnimators = new ArrayList<>();
    long mDuration = -1;
    private TransitionValuesMaps mEndValues = new TransitionValuesMaps();
    private ArrayList<TransitionValues> mEndValuesList;
    private boolean mEnded = false;
    private EpicenterCallback mEpicenterCallback;
    private TimeInterpolator mInterpolator = null;
    private ArrayList<TransitionListener> mListeners = null;
    private int[] mMatchOrder = DEFAULT_MATCH_ORDER;
    private String mName = getClass().getName();
    private ArrayMap<String, String> mNameOverrides;
    private int mNumInstances = 0;
    TransitionSet mParent = null;
    private PathMotion mPathMotion = STRAIGHT_PATH_MOTION;
    private boolean mPaused = false;
    TransitionPropagation mPropagation;
    private ViewGroup mSceneRoot = null;
    private long mStartDelay = -1;
    private TransitionValuesMaps mStartValues = new TransitionValuesMaps();
    private ArrayList<TransitionValues> mStartValuesList;
    private ArrayList<View> mTargetChildExcludes = null;
    private ArrayList<View> mTargetExcludes = null;
    private ArrayList<Integer> mTargetIdChildExcludes = null;
    private ArrayList<Integer> mTargetIdExcludes = null;
    ArrayList<Integer> mTargetIds = new ArrayList<>();
    private ArrayList<String> mTargetNameExcludes = null;
    private ArrayList<String> mTargetNames = null;
    private ArrayList<Class> mTargetTypeChildExcludes = null;
    private ArrayList<Class> mTargetTypeExcludes = null;
    private ArrayList<Class> mTargetTypes = null;
    ArrayList<View> mTargets = new ArrayList<>();

    private static class AnimationInfo {
        String mName;
        Transition mTransition;
        TransitionValues mValues;
        View mView;
        WindowIdImpl mWindowId;

        AnimationInfo(View view, String name, Transition transition, WindowIdImpl windowId, TransitionValues values) {
            this.mView = view;
            this.mName = name;
            this.mValues = values;
            this.mWindowId = windowId;
            this.mTransition = transition;
        }
    }

    private static class ArrayListManager {
        private ArrayListManager() {
        }

        static <T> ArrayList<T> add(ArrayList<T> list, T item) {
            if (list == null) {
                list = new ArrayList<>();
            }
            if (!list.contains(item)) {
                list.add(item);
            }
            return list;
        }

        static <T> ArrayList<T> remove(ArrayList<T> list, T item) {
            if (list == null) {
                return list;
            }
            list.remove(item);
            if (list.isEmpty()) {
                return null;
            }
            return list;
        }
    }

    public static abstract class EpicenterCallback {
        public abstract Rect onGetEpicenter(Transition transition);
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface MatchOrder {
    }

    public interface TransitionListener {
        void onTransitionCancel(Transition transition);

        void onTransitionEnd(Transition transition);

        void onTransitionPause(Transition transition);

        void onTransitionResume(Transition transition);

        void onTransitionStart(Transition transition);
    }

    public abstract void captureEndValues(TransitionValues transitionValues);

    public abstract void captureStartValues(TransitionValues transitionValues);

    public Transition() {
    }

    public Transition(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.TRANSITION);
        XmlResourceParser parser = (XmlResourceParser) attrs;
        long duration = (long) TypedArrayUtils.getNamedInt(a, parser, "duration", 1, -1);
        if (duration >= 0) {
            setDuration(duration);
        }
        long startDelay = (long) TypedArrayUtils.getNamedInt(a, parser, "startDelay", 2, -1);
        if (startDelay > 0) {
            setStartDelay(startDelay);
        }
        int resId = TypedArrayUtils.getNamedResourceId(a, parser, "interpolator", 0, 0);
        if (resId > 0) {
            setInterpolator(AnimationUtils.loadInterpolator(context, resId));
        }
        String matchOrder = TypedArrayUtils.getNamedString(a, parser, "matchOrder", 3);
        if (matchOrder != null) {
            setMatchOrder(parseMatchOrder(matchOrder));
        }
        a.recycle();
    }

    private static int[] parseMatchOrder(String matchOrderString) {
        StringTokenizer st = new StringTokenizer(matchOrderString, ",");
        int[] matches = new int[st.countTokens()];
        int index = 0;
        while (st.hasMoreTokens()) {
            String token = st.nextToken().trim();
            if (MATCH_ID_STR.equalsIgnoreCase(token)) {
                matches[index] = 3;
            } else if (MATCH_INSTANCE_STR.equalsIgnoreCase(token)) {
                matches[index] = 1;
            } else if (MATCH_NAME_STR.equalsIgnoreCase(token)) {
                matches[index] = 2;
            } else if (MATCH_ITEM_ID_STR.equalsIgnoreCase(token)) {
                matches[index] = 4;
            } else if (token.isEmpty()) {
                int[] smallerMatches = new int[(matches.length - 1)];
                System.arraycopy(matches, 0, smallerMatches, 0, index);
                matches = smallerMatches;
                index--;
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append("Unknown match type in matchOrder: '");
                sb.append(token);
                sb.append("'");
                throw new InflateException(sb.toString());
            }
            index++;
        }
        return matches;
    }

    public Transition setDuration(long duration) {
        this.mDuration = duration;
        return this;
    }

    public long getDuration() {
        return this.mDuration;
    }

    public Transition setStartDelay(long startDelay) {
        this.mStartDelay = startDelay;
        return this;
    }

    public long getStartDelay() {
        return this.mStartDelay;
    }

    public Transition setInterpolator(TimeInterpolator interpolator) {
        this.mInterpolator = interpolator;
        return this;
    }

    public TimeInterpolator getInterpolator() {
        return this.mInterpolator;
    }

    public String[] getTransitionProperties() {
        return null;
    }

    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        return null;
    }

    public void setMatchOrder(int... matches) {
        if (matches == null || matches.length == 0) {
            this.mMatchOrder = DEFAULT_MATCH_ORDER;
            return;
        }
        int i = 0;
        while (i < matches.length) {
            if (!isValidMatch(matches[i])) {
                throw new IllegalArgumentException("matches contains invalid value");
            } else if (!alreadyContains(matches, i)) {
                i++;
            } else {
                throw new IllegalArgumentException("matches contains a duplicate value");
            }
        }
        this.mMatchOrder = (int[]) matches.clone();
    }

    private static boolean isValidMatch(int match) {
        return match >= 1 && match <= 4;
    }

    private static boolean alreadyContains(int[] array, int searchIndex) {
        int value = array[searchIndex];
        for (int i = 0; i < searchIndex; i++) {
            if (array[i] == value) {
                return true;
            }
        }
        return false;
    }

    private void matchInstances(ArrayMap<View, TransitionValues> unmatchedStart, ArrayMap<View, TransitionValues> unmatchedEnd) {
        for (int i = unmatchedStart.size() - 1; i >= 0; i--) {
            View view = (View) unmatchedStart.keyAt(i);
            if (view != null && isValidTarget(view)) {
                TransitionValues end = (TransitionValues) unmatchedEnd.remove(view);
                if (!(end == null || end.view == null || !isValidTarget(end.view))) {
                    this.mStartValuesList.add((TransitionValues) unmatchedStart.removeAt(i));
                    this.mEndValuesList.add(end);
                }
            }
        }
    }

    private void matchItemIds(ArrayMap<View, TransitionValues> unmatchedStart, ArrayMap<View, TransitionValues> unmatchedEnd, LongSparseArray<View> startItemIds, LongSparseArray<View> endItemIds) {
        int numStartIds = startItemIds.size();
        for (int i = 0; i < numStartIds; i++) {
            View startView = (View) startItemIds.valueAt(i);
            if (startView != null && isValidTarget(startView)) {
                View endView = (View) endItemIds.get(startItemIds.keyAt(i));
                if (endView != null && isValidTarget(endView)) {
                    TransitionValues startValues = (TransitionValues) unmatchedStart.get(startView);
                    TransitionValues endValues = (TransitionValues) unmatchedEnd.get(endView);
                    if (!(startValues == null || endValues == null)) {
                        this.mStartValuesList.add(startValues);
                        this.mEndValuesList.add(endValues);
                        unmatchedStart.remove(startView);
                        unmatchedEnd.remove(endView);
                    }
                }
            }
        }
    }

    private void matchIds(ArrayMap<View, TransitionValues> unmatchedStart, ArrayMap<View, TransitionValues> unmatchedEnd, SparseArray<View> startIds, SparseArray<View> endIds) {
        int numStartIds = startIds.size();
        for (int i = 0; i < numStartIds; i++) {
            View startView = (View) startIds.valueAt(i);
            if (startView != null && isValidTarget(startView)) {
                View endView = (View) endIds.get(startIds.keyAt(i));
                if (endView != null && isValidTarget(endView)) {
                    TransitionValues startValues = (TransitionValues) unmatchedStart.get(startView);
                    TransitionValues endValues = (TransitionValues) unmatchedEnd.get(endView);
                    if (!(startValues == null || endValues == null)) {
                        this.mStartValuesList.add(startValues);
                        this.mEndValuesList.add(endValues);
                        unmatchedStart.remove(startView);
                        unmatchedEnd.remove(endView);
                    }
                }
            }
        }
    }

    private void matchNames(ArrayMap<View, TransitionValues> unmatchedStart, ArrayMap<View, TransitionValues> unmatchedEnd, ArrayMap<String, View> startNames, ArrayMap<String, View> endNames) {
        int numStartNames = startNames.size();
        for (int i = 0; i < numStartNames; i++) {
            View startView = (View) startNames.valueAt(i);
            if (startView != null && isValidTarget(startView)) {
                View endView = (View) endNames.get(startNames.keyAt(i));
                if (endView != null && isValidTarget(endView)) {
                    TransitionValues startValues = (TransitionValues) unmatchedStart.get(startView);
                    TransitionValues endValues = (TransitionValues) unmatchedEnd.get(endView);
                    if (!(startValues == null || endValues == null)) {
                        this.mStartValuesList.add(startValues);
                        this.mEndValuesList.add(endValues);
                        unmatchedStart.remove(startView);
                        unmatchedEnd.remove(endView);
                    }
                }
            }
        }
    }

    private void addUnmatched(ArrayMap<View, TransitionValues> unmatchedStart, ArrayMap<View, TransitionValues> unmatchedEnd) {
        for (int i = 0; i < unmatchedStart.size(); i++) {
            TransitionValues start = (TransitionValues) unmatchedStart.valueAt(i);
            if (isValidTarget(start.view)) {
                this.mStartValuesList.add(start);
                this.mEndValuesList.add(null);
            }
        }
        for (int i2 = 0; i2 < unmatchedEnd.size(); i2++) {
            TransitionValues end = (TransitionValues) unmatchedEnd.valueAt(i2);
            if (isValidTarget(end.view)) {
                this.mEndValuesList.add(end);
                this.mStartValuesList.add(null);
            }
        }
    }

    private void matchStartAndEnd(TransitionValuesMaps startValues, TransitionValuesMaps endValues) {
        ArrayMap<View, TransitionValues> unmatchedStart = new ArrayMap<>((SimpleArrayMap) startValues.mViewValues);
        ArrayMap<View, TransitionValues> unmatchedEnd = new ArrayMap<>((SimpleArrayMap) endValues.mViewValues);
        int i = 0;
        while (true) {
            int[] iArr = this.mMatchOrder;
            if (i < iArr.length) {
                int i2 = iArr[i];
                if (i2 == 1) {
                    matchInstances(unmatchedStart, unmatchedEnd);
                } else if (i2 == 2) {
                    matchNames(unmatchedStart, unmatchedEnd, startValues.mNameValues, endValues.mNameValues);
                } else if (i2 == 3) {
                    matchIds(unmatchedStart, unmatchedEnd, startValues.mIdValues, endValues.mIdValues);
                } else if (i2 == 4) {
                    matchItemIds(unmatchedStart, unmatchedEnd, startValues.mItemIdValues, endValues.mItemIdValues);
                }
                i++;
            } else {
                addUnmatched(unmatchedStart, unmatchedEnd);
                return;
            }
        }
    }

    /* access modifiers changed from: protected */
    public void createAnimators(ViewGroup sceneRoot, TransitionValuesMaps startValues, TransitionValuesMaps endValues, ArrayList<TransitionValues> startValuesList, ArrayList<TransitionValues> endValuesList) {
        TransitionValues start;
        TransitionValues end;
        int i;
        int startValuesListCount;
        View view;
        TransitionValues infoValues;
        Animator animator;
        long minStartDelay;
        Animator animator2;
        Animator animator3;
        int i2;
        int numExistingAnims;
        ViewGroup viewGroup = sceneRoot;
        ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
        long minStartDelay2 = Long.MAX_VALUE;
        SparseIntArray startDelays = new SparseIntArray();
        int startValuesListCount2 = startValuesList.size();
        int i3 = 0;
        while (i3 < startValuesListCount2) {
            TransitionValues start2 = (TransitionValues) startValuesList.get(i3);
            TransitionValues end2 = (TransitionValues) endValuesList.get(i3);
            if (start2 == null || start2.mTargetedTransitions.contains(this)) {
                start = start2;
            } else {
                start = null;
            }
            if (end2 == null || end2.mTargetedTransitions.contains(this)) {
                end = end2;
            } else {
                end = null;
            }
            if (start == null && end == null) {
                startValuesListCount = startValuesListCount2;
                i = i3;
            } else {
                if (start == null || end == null || isTransitionRequired(start, end)) {
                    Animator animator4 = createAnimator(viewGroup, start, end);
                    if (animator4 != null) {
                        TransitionValues infoValues2 = null;
                        if (end != null) {
                            View view2 = end.view;
                            String[] properties = getTransitionProperties();
                            if (view2 == null || properties == null) {
                                animator3 = animator4;
                                startValuesListCount = startValuesListCount2;
                                i2 = i3;
                            } else {
                                animator3 = animator4;
                                if (properties.length > 0) {
                                    TransitionValues infoValues3 = new TransitionValues();
                                    infoValues3.view = view2;
                                    startValuesListCount = startValuesListCount2;
                                    TransitionValues newValues = (TransitionValues) endValues.mViewValues.get(view2);
                                    if (newValues != null) {
                                        int j = 0;
                                        while (j < properties.length) {
                                            int i4 = i3;
                                            TransitionValues newValues2 = newValues;
                                            infoValues3.values.put(properties[j], newValues.values.get(properties[j]));
                                            j++;
                                            ArrayList<TransitionValues> arrayList = startValuesList;
                                            ArrayList<TransitionValues> arrayList2 = endValuesList;
                                            i3 = i4;
                                            newValues = newValues2;
                                        }
                                        i = i3;
                                    } else {
                                        i = i3;
                                    }
                                    int numExistingAnims2 = runningAnimators.size();
                                    int j2 = 0;
                                    while (true) {
                                        if (j2 >= numExistingAnims2) {
                                            infoValues2 = infoValues3;
                                            animator2 = animator3;
                                            break;
                                        }
                                        AnimationInfo info = (AnimationInfo) runningAnimators.get((Animator) runningAnimators.keyAt(j2));
                                        if (info.mValues != null && info.mView == view2) {
                                            numExistingAnims = numExistingAnims2;
                                            if (info.mName.equals(getName()) && info.mValues.equals(infoValues3)) {
                                                infoValues2 = infoValues3;
                                                animator2 = null;
                                                break;
                                            }
                                        } else {
                                            numExistingAnims = numExistingAnims2;
                                        }
                                        j2++;
                                        numExistingAnims2 = numExistingAnims;
                                    }
                                    animator = animator2;
                                    infoValues = infoValues2;
                                    view = view2;
                                } else {
                                    startValuesListCount = startValuesListCount2;
                                    i2 = i3;
                                }
                            }
                            animator2 = animator3;
                            animator = animator2;
                            infoValues = infoValues2;
                            view = view2;
                        } else {
                            Animator animator5 = animator4;
                            startValuesListCount = startValuesListCount2;
                            i = i3;
                            infoValues = null;
                            view = start.view;
                            animator = animator5;
                        }
                        if (animator != null) {
                            TransitionPropagation transitionPropagation = this.mPropagation;
                            if (transitionPropagation != null) {
                                long delay = transitionPropagation.getStartDelay(viewGroup, this, start, end);
                                startDelays.put(this.mAnimators.size(), (int) delay);
                                minStartDelay = Math.min(delay, minStartDelay2);
                            } else {
                                minStartDelay = minStartDelay2;
                            }
                            AnimationInfo info2 = new AnimationInfo(view, getName(), this, ViewUtils.getWindowId(sceneRoot), infoValues);
                            runningAnimators.put(animator, info2);
                            this.mAnimators.add(animator);
                            minStartDelay2 = minStartDelay;
                        }
                    } else {
                        Animator animator6 = animator4;
                        startValuesListCount = startValuesListCount2;
                        i = i3;
                    }
                } else {
                    startValuesListCount = startValuesListCount2;
                    i = i3;
                }
            }
            i3 = i + 1;
            startValuesListCount2 = startValuesListCount;
        }
        int i5 = i3;
        if (minStartDelay2 != 0) {
            for (int i6 = 0; i6 < startDelays.size(); i6++) {
                Animator animator7 = (Animator) this.mAnimators.get(startDelays.keyAt(i6));
                animator7.setStartDelay((((long) startDelays.valueAt(i6)) - minStartDelay2) + animator7.getStartDelay());
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isValidTarget(View target) {
        int targetId = target.getId();
        ArrayList<Integer> arrayList = this.mTargetIdExcludes;
        if (arrayList != null && arrayList.contains(Integer.valueOf(targetId))) {
            return false;
        }
        ArrayList<View> arrayList2 = this.mTargetExcludes;
        if (arrayList2 != null && arrayList2.contains(target)) {
            return false;
        }
        ArrayList<Class> arrayList3 = this.mTargetTypeExcludes;
        if (arrayList3 != null) {
            int numTypes = arrayList3.size();
            for (int i = 0; i < numTypes; i++) {
                if (((Class) this.mTargetTypeExcludes.get(i)).isInstance(target)) {
                    return false;
                }
            }
        }
        if (this.mTargetNameExcludes != null && ViewCompat.getTransitionName(target) != null && this.mTargetNameExcludes.contains(ViewCompat.getTransitionName(target))) {
            return false;
        }
        if (this.mTargetIds.size() == 0 && this.mTargets.size() == 0) {
            ArrayList<Class> arrayList4 = this.mTargetTypes;
            if (arrayList4 == null || arrayList4.isEmpty()) {
                ArrayList<String> arrayList5 = this.mTargetNames;
                if (arrayList5 == null || arrayList5.isEmpty()) {
                    return true;
                }
            }
        }
        if (this.mTargetIds.contains(Integer.valueOf(targetId)) || this.mTargets.contains(target)) {
            return true;
        }
        ArrayList<String> arrayList6 = this.mTargetNames;
        if (arrayList6 != null && arrayList6.contains(ViewCompat.getTransitionName(target))) {
            return true;
        }
        if (this.mTargetTypes != null) {
            for (int i2 = 0; i2 < this.mTargetTypes.size(); i2++) {
                if (((Class) this.mTargetTypes.get(i2)).isInstance(target)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static ArrayMap<Animator, AnimationInfo> getRunningAnimators() {
        ArrayMap<Animator, AnimationInfo> runningAnimators = (ArrayMap) sRunningAnimators.get();
        if (runningAnimators != null) {
            return runningAnimators;
        }
        ArrayMap arrayMap = new ArrayMap();
        sRunningAnimators.set(arrayMap);
        return arrayMap;
    }

    /* access modifiers changed from: protected */
    public void runAnimators() {
        start();
        ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
        Iterator it = this.mAnimators.iterator();
        while (it.hasNext()) {
            Animator anim = (Animator) it.next();
            if (runningAnimators.containsKey(anim)) {
                start();
                runAnimator(anim, runningAnimators);
            }
        }
        this.mAnimators.clear();
        end();
    }

    private void runAnimator(Animator animator, final ArrayMap<Animator, AnimationInfo> runningAnimators) {
        if (animator != null) {
            animator.addListener(new AnimatorListenerAdapter() {
                public void onAnimationStart(Animator animation) {
                    Transition.this.mCurrentAnimators.add(animation);
                }

                public void onAnimationEnd(Animator animation) {
                    runningAnimators.remove(animation);
                    Transition.this.mCurrentAnimators.remove(animation);
                }
            });
            animate(animator);
        }
    }

    public Transition addTarget(View target) {
        this.mTargets.add(target);
        return this;
    }

    public Transition addTarget(int targetId) {
        if (targetId != 0) {
            this.mTargetIds.add(Integer.valueOf(targetId));
        }
        return this;
    }

    public Transition addTarget(String targetName) {
        if (this.mTargetNames == null) {
            this.mTargetNames = new ArrayList<>();
        }
        this.mTargetNames.add(targetName);
        return this;
    }

    public Transition addTarget(Class targetType) {
        if (this.mTargetTypes == null) {
            this.mTargetTypes = new ArrayList<>();
        }
        this.mTargetTypes.add(targetType);
        return this;
    }

    public Transition removeTarget(View target) {
        this.mTargets.remove(target);
        return this;
    }

    public Transition removeTarget(int targetId) {
        if (targetId != 0) {
            this.mTargetIds.remove(Integer.valueOf(targetId));
        }
        return this;
    }

    public Transition removeTarget(String targetName) {
        ArrayList<String> arrayList = this.mTargetNames;
        if (arrayList != null) {
            arrayList.remove(targetName);
        }
        return this;
    }

    public Transition removeTarget(Class target) {
        ArrayList<Class> arrayList = this.mTargetTypes;
        if (arrayList != null) {
            arrayList.remove(target);
        }
        return this;
    }

    private static <T> ArrayList<T> excludeObject(ArrayList<T> list, T target, boolean exclude) {
        if (target == null) {
            return list;
        }
        if (exclude) {
            return ArrayListManager.add(list, target);
        }
        return ArrayListManager.remove(list, target);
    }

    public Transition excludeTarget(View target, boolean exclude) {
        this.mTargetExcludes = excludeView(this.mTargetExcludes, target, exclude);
        return this;
    }

    public Transition excludeTarget(int targetId, boolean exclude) {
        this.mTargetIdExcludes = excludeId(this.mTargetIdExcludes, targetId, exclude);
        return this;
    }

    public Transition excludeTarget(String targetName, boolean exclude) {
        this.mTargetNameExcludes = excludeObject(this.mTargetNameExcludes, targetName, exclude);
        return this;
    }

    public Transition excludeChildren(View target, boolean exclude) {
        this.mTargetChildExcludes = excludeView(this.mTargetChildExcludes, target, exclude);
        return this;
    }

    public Transition excludeChildren(int targetId, boolean exclude) {
        this.mTargetIdChildExcludes = excludeId(this.mTargetIdChildExcludes, targetId, exclude);
        return this;
    }

    private ArrayList<Integer> excludeId(ArrayList<Integer> list, int targetId, boolean exclude) {
        if (targetId <= 0) {
            return list;
        }
        if (exclude) {
            return ArrayListManager.add(list, Integer.valueOf(targetId));
        }
        return ArrayListManager.remove(list, Integer.valueOf(targetId));
    }

    private ArrayList<View> excludeView(ArrayList<View> list, View target, boolean exclude) {
        if (target == null) {
            return list;
        }
        if (exclude) {
            return ArrayListManager.add(list, target);
        }
        return ArrayListManager.remove(list, target);
    }

    public Transition excludeTarget(Class type, boolean exclude) {
        this.mTargetTypeExcludes = excludeType(this.mTargetTypeExcludes, type, exclude);
        return this;
    }

    public Transition excludeChildren(Class type, boolean exclude) {
        this.mTargetTypeChildExcludes = excludeType(this.mTargetTypeChildExcludes, type, exclude);
        return this;
    }

    private ArrayList<Class> excludeType(ArrayList<Class> list, Class type, boolean exclude) {
        if (type == null) {
            return list;
        }
        if (exclude) {
            return ArrayListManager.add(list, type);
        }
        return ArrayListManager.remove(list, type);
    }

    public List<Integer> getTargetIds() {
        return this.mTargetIds;
    }

    public List<View> getTargets() {
        return this.mTargets;
    }

    public List<String> getTargetNames() {
        return this.mTargetNames;
    }

    public List<Class> getTargetTypes() {
        return this.mTargetTypes;
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Removed duplicated region for block: B:40:0x00ab  */
    /* JADX WARNING: Removed duplicated region for block: B:62:? A[ORIG_RETURN, RETURN, SYNTHETIC] */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void captureValues(android.view.ViewGroup r7, boolean r8) {
        /*
            r6 = this;
            r6.clearValues(r8)
            java.util.ArrayList<java.lang.Integer> r0 = r6.mTargetIds
            int r0 = r0.size()
            if (r0 > 0) goto L_0x0013
            java.util.ArrayList<android.view.View> r0 = r6.mTargets
            int r0 = r0.size()
            if (r0 <= 0) goto L_0x0028
        L_0x0013:
            java.util.ArrayList<java.lang.String> r0 = r6.mTargetNames
            if (r0 == 0) goto L_0x001d
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto L_0x0028
        L_0x001d:
            java.util.ArrayList<java.lang.Class> r0 = r6.mTargetTypes
            if (r0 == 0) goto L_0x002d
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto L_0x0028
            goto L_0x002d
        L_0x0028:
            r6.captureHierarchy(r7, r8)
            goto L_0x00a9
        L_0x002d:
            r0 = 0
        L_0x002e:
            java.util.ArrayList<java.lang.Integer> r1 = r6.mTargetIds
            int r1 = r1.size()
            if (r0 >= r1) goto L_0x0070
            java.util.ArrayList<java.lang.Integer> r1 = r6.mTargetIds
            java.lang.Object r1 = r1.get(r0)
            java.lang.Integer r1 = (java.lang.Integer) r1
            int r1 = r1.intValue()
            android.view.View r2 = r7.findViewById(r1)
            if (r2 == 0) goto L_0x006d
            androidx.transition.TransitionValues r3 = new androidx.transition.TransitionValues
            r3.<init>()
            r3.view = r2
            if (r8 == 0) goto L_0x0055
            r6.captureStartValues(r3)
            goto L_0x0058
        L_0x0055:
            r6.captureEndValues(r3)
        L_0x0058:
            java.util.ArrayList<androidx.transition.Transition> r4 = r3.mTargetedTransitions
            r4.add(r6)
            r6.capturePropagationValues(r3)
            if (r8 == 0) goto L_0x0068
            androidx.transition.TransitionValuesMaps r4 = r6.mStartValues
            addViewValues(r4, r2, r3)
            goto L_0x006d
        L_0x0068:
            androidx.transition.TransitionValuesMaps r4 = r6.mEndValues
            addViewValues(r4, r2, r3)
        L_0x006d:
            int r0 = r0 + 1
            goto L_0x002e
        L_0x0070:
            r0 = 0
        L_0x0071:
            java.util.ArrayList<android.view.View> r1 = r6.mTargets
            int r1 = r1.size()
            if (r0 >= r1) goto L_0x00a9
            java.util.ArrayList<android.view.View> r1 = r6.mTargets
            java.lang.Object r1 = r1.get(r0)
            android.view.View r1 = (android.view.View) r1
            androidx.transition.TransitionValues r2 = new androidx.transition.TransitionValues
            r2.<init>()
            r2.view = r1
            if (r8 == 0) goto L_0x008e
            r6.captureStartValues(r2)
            goto L_0x0091
        L_0x008e:
            r6.captureEndValues(r2)
        L_0x0091:
            java.util.ArrayList<androidx.transition.Transition> r3 = r2.mTargetedTransitions
            r3.add(r6)
            r6.capturePropagationValues(r2)
            if (r8 == 0) goto L_0x00a1
            androidx.transition.TransitionValuesMaps r3 = r6.mStartValues
            addViewValues(r3, r1, r2)
            goto L_0x00a6
        L_0x00a1:
            androidx.transition.TransitionValuesMaps r3 = r6.mEndValues
            addViewValues(r3, r1, r2)
        L_0x00a6:
            int r0 = r0 + 1
            goto L_0x0071
        L_0x00a9:
            if (r8 != 0) goto L_0x00ee
            androidx.collection.ArrayMap<java.lang.String, java.lang.String> r0 = r6.mNameOverrides
            if (r0 == 0) goto L_0x00ee
            int r0 = r0.size()
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>(r0)
            r2 = 0
        L_0x00b9:
            if (r2 >= r0) goto L_0x00d1
            androidx.collection.ArrayMap<java.lang.String, java.lang.String> r3 = r6.mNameOverrides
            java.lang.Object r3 = r3.keyAt(r2)
            java.lang.String r3 = (java.lang.String) r3
            androidx.transition.TransitionValuesMaps r4 = r6.mStartValues
            androidx.collection.ArrayMap<java.lang.String, android.view.View> r4 = r4.mNameValues
            java.lang.Object r4 = r4.remove(r3)
            r1.add(r4)
            int r2 = r2 + 1
            goto L_0x00b9
        L_0x00d1:
            r2 = 0
        L_0x00d2:
            if (r2 >= r0) goto L_0x00ee
            java.lang.Object r3 = r1.get(r2)
            android.view.View r3 = (android.view.View) r3
            if (r3 == 0) goto L_0x00eb
            androidx.collection.ArrayMap<java.lang.String, java.lang.String> r4 = r6.mNameOverrides
            java.lang.Object r4 = r4.valueAt(r2)
            java.lang.String r4 = (java.lang.String) r4
            androidx.transition.TransitionValuesMaps r5 = r6.mStartValues
            androidx.collection.ArrayMap<java.lang.String, android.view.View> r5 = r5.mNameValues
            r5.put(r4, r3)
        L_0x00eb:
            int r2 = r2 + 1
            goto L_0x00d2
        L_0x00ee:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.Transition.captureValues(android.view.ViewGroup, boolean):void");
    }

    private static void addViewValues(TransitionValuesMaps transitionValuesMaps, View view, TransitionValues transitionValues) {
        transitionValuesMaps.mViewValues.put(view, transitionValues);
        int id = view.getId();
        if (id >= 0) {
            if (transitionValuesMaps.mIdValues.indexOfKey(id) >= 0) {
                transitionValuesMaps.mIdValues.put(id, null);
            } else {
                transitionValuesMaps.mIdValues.put(id, view);
            }
        }
        String name = ViewCompat.getTransitionName(view);
        if (name != null) {
            if (transitionValuesMaps.mNameValues.containsKey(name)) {
                transitionValuesMaps.mNameValues.put(name, null);
            } else {
                transitionValuesMaps.mNameValues.put(name, view);
            }
        }
        if (view.getParent() instanceof ListView) {
            ListView listview = (ListView) view.getParent();
            if (listview.getAdapter().hasStableIds()) {
                long itemId = listview.getItemIdAtPosition(listview.getPositionForView(view));
                if (transitionValuesMaps.mItemIdValues.indexOfKey(itemId) >= 0) {
                    View alreadyMatched = (View) transitionValuesMaps.mItemIdValues.get(itemId);
                    if (alreadyMatched != null) {
                        ViewCompat.setHasTransientState(alreadyMatched, false);
                        transitionValuesMaps.mItemIdValues.put(itemId, null);
                        return;
                    }
                    return;
                }
                ViewCompat.setHasTransientState(view, true);
                transitionValuesMaps.mItemIdValues.put(itemId, view);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void clearValues(boolean start) {
        if (start) {
            this.mStartValues.mViewValues.clear();
            this.mStartValues.mIdValues.clear();
            this.mStartValues.mItemIdValues.clear();
            return;
        }
        this.mEndValues.mViewValues.clear();
        this.mEndValues.mIdValues.clear();
        this.mEndValues.mItemIdValues.clear();
    }

    private void captureHierarchy(View view, boolean start) {
        if (view != null) {
            int id = view.getId();
            ArrayList<Integer> arrayList = this.mTargetIdExcludes;
            if (arrayList == null || !arrayList.contains(Integer.valueOf(id))) {
                ArrayList<View> arrayList2 = this.mTargetExcludes;
                if (arrayList2 == null || !arrayList2.contains(view)) {
                    ArrayList<Class> arrayList3 = this.mTargetTypeExcludes;
                    if (arrayList3 != null) {
                        int numTypes = arrayList3.size();
                        int i = 0;
                        while (i < numTypes) {
                            if (!((Class) this.mTargetTypeExcludes.get(i)).isInstance(view)) {
                                i++;
                            } else {
                                return;
                            }
                        }
                    }
                    if (view.getParent() instanceof ViewGroup) {
                        TransitionValues values = new TransitionValues();
                        values.view = view;
                        if (start) {
                            captureStartValues(values);
                        } else {
                            captureEndValues(values);
                        }
                        values.mTargetedTransitions.add(this);
                        capturePropagationValues(values);
                        if (start) {
                            addViewValues(this.mStartValues, view, values);
                        } else {
                            addViewValues(this.mEndValues, view, values);
                        }
                    }
                    if (view instanceof ViewGroup) {
                        ArrayList<Integer> arrayList4 = this.mTargetIdChildExcludes;
                        if (arrayList4 == null || !arrayList4.contains(Integer.valueOf(id))) {
                            ArrayList<View> arrayList5 = this.mTargetChildExcludes;
                            if (arrayList5 == null || !arrayList5.contains(view)) {
                                ArrayList<Class> arrayList6 = this.mTargetTypeChildExcludes;
                                if (arrayList6 != null) {
                                    int numTypes2 = arrayList6.size();
                                    int i2 = 0;
                                    while (i2 < numTypes2) {
                                        if (!((Class) this.mTargetTypeChildExcludes.get(i2)).isInstance(view)) {
                                            i2++;
                                        } else {
                                            return;
                                        }
                                    }
                                }
                                ViewGroup parent = (ViewGroup) view;
                                for (int i3 = 0; i3 < parent.getChildCount(); i3++) {
                                    captureHierarchy(parent.getChildAt(i3), start);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public TransitionValues getTransitionValues(View view, boolean start) {
        TransitionSet transitionSet = this.mParent;
        if (transitionSet != null) {
            return transitionSet.getTransitionValues(view, start);
        }
        return (TransitionValues) (start ? this.mStartValues : this.mEndValues).mViewValues.get(view);
    }

    /* access modifiers changed from: 0000 */
    public TransitionValues getMatchedTransitionValues(View view, boolean viewInStart) {
        TransitionSet transitionSet = this.mParent;
        if (transitionSet != null) {
            return transitionSet.getMatchedTransitionValues(view, viewInStart);
        }
        ArrayList<TransitionValues> lookIn = viewInStart ? this.mStartValuesList : this.mEndValuesList;
        if (lookIn == null) {
            return null;
        }
        int count = lookIn.size();
        int index = -1;
        int i = 0;
        while (true) {
            if (i >= count) {
                break;
            }
            TransitionValues values = (TransitionValues) lookIn.get(i);
            if (values == null) {
                return null;
            }
            if (values.view == view) {
                index = i;
                break;
            }
            i++;
        }
        TransitionValues values2 = null;
        if (index >= 0) {
            values2 = (TransitionValues) (viewInStart ? this.mEndValuesList : this.mStartValuesList).get(index);
        }
        return values2;
    }

    public void pause(View sceneRoot) {
        if (!this.mEnded) {
            ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
            int numOldAnims = runningAnimators.size();
            WindowIdImpl windowId = ViewUtils.getWindowId(sceneRoot);
            for (int i = numOldAnims - 1; i >= 0; i--) {
                AnimationInfo info = (AnimationInfo) runningAnimators.valueAt(i);
                if (info.mView != null && windowId.equals(info.mWindowId)) {
                    AnimatorUtils.pause((Animator) runningAnimators.keyAt(i));
                }
            }
            ArrayList<TransitionListener> arrayList = this.mListeners;
            if (arrayList != null && arrayList.size() > 0) {
                ArrayList<TransitionListener> tmpListeners = (ArrayList) this.mListeners.clone();
                int numListeners = tmpListeners.size();
                for (int i2 = 0; i2 < numListeners; i2++) {
                    ((TransitionListener) tmpListeners.get(i2)).onTransitionPause(this);
                }
            }
            this.mPaused = true;
        }
    }

    public void resume(View sceneRoot) {
        if (this.mPaused) {
            if (!this.mEnded) {
                ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
                int numOldAnims = runningAnimators.size();
                WindowIdImpl windowId = ViewUtils.getWindowId(sceneRoot);
                for (int i = numOldAnims - 1; i >= 0; i--) {
                    AnimationInfo info = (AnimationInfo) runningAnimators.valueAt(i);
                    if (info.mView != null && windowId.equals(info.mWindowId)) {
                        AnimatorUtils.resume((Animator) runningAnimators.keyAt(i));
                    }
                }
                ArrayList<TransitionListener> arrayList = this.mListeners;
                if (arrayList != null && arrayList.size() > 0) {
                    ArrayList<TransitionListener> tmpListeners = (ArrayList) this.mListeners.clone();
                    int numListeners = tmpListeners.size();
                    for (int i2 = 0; i2 < numListeners; i2++) {
                        ((TransitionListener) tmpListeners.get(i2)).onTransitionResume(this);
                    }
                }
            }
            this.mPaused = false;
        }
    }

    /* access modifiers changed from: 0000 */
    public void playTransition(ViewGroup sceneRoot) {
        this.mStartValuesList = new ArrayList<>();
        this.mEndValuesList = new ArrayList<>();
        matchStartAndEnd(this.mStartValues, this.mEndValues);
        ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
        int numOldAnims = runningAnimators.size();
        WindowIdImpl windowId = ViewUtils.getWindowId(sceneRoot);
        for (int i = numOldAnims - 1; i >= 0; i--) {
            Animator anim = (Animator) runningAnimators.keyAt(i);
            if (anim != null) {
                AnimationInfo oldInfo = (AnimationInfo) runningAnimators.get(anim);
                if (!(oldInfo == null || oldInfo.mView == null || !windowId.equals(oldInfo.mWindowId))) {
                    TransitionValues oldValues = oldInfo.mValues;
                    View oldView = oldInfo.mView;
                    boolean cancel = true;
                    TransitionValues startValues = getTransitionValues(oldView, true);
                    TransitionValues endValues = getMatchedTransitionValues(oldView, true);
                    if ((startValues == null && endValues == null) || !oldInfo.mTransition.isTransitionRequired(oldValues, endValues)) {
                        cancel = false;
                    }
                    if (cancel) {
                        if (anim.isRunning() || anim.isStarted()) {
                            anim.cancel();
                        } else {
                            runningAnimators.remove(anim);
                        }
                    }
                }
            }
        }
        createAnimators(sceneRoot, this.mStartValues, this.mEndValues, this.mStartValuesList, this.mEndValuesList);
        runAnimators();
    }

    public boolean isTransitionRequired(TransitionValues startValues, TransitionValues endValues) {
        if (startValues == null || endValues == null) {
            return false;
        }
        String[] properties = getTransitionProperties();
        if (properties != null) {
            for (String property : properties) {
                if (isValueChanged(startValues, endValues, property)) {
                    return true;
                }
            }
            return false;
        }
        for (String key : startValues.values.keySet()) {
            if (isValueChanged(startValues, endValues, key)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isValueChanged(TransitionValues oldValues, TransitionValues newValues, String key) {
        Object oldValue = oldValues.values.get(key);
        Object newValue = newValues.values.get(key);
        if (oldValue == null && newValue == null) {
            return false;
        }
        if (oldValue == null || newValue == null) {
            return true;
        }
        return !oldValue.equals(newValue);
    }

    /* access modifiers changed from: protected */
    public void animate(Animator animator) {
        if (animator == null) {
            end();
            return;
        }
        if (getDuration() >= 0) {
            animator.setDuration(getDuration());
        }
        if (getStartDelay() >= 0) {
            animator.setStartDelay(getStartDelay());
        }
        if (getInterpolator() != null) {
            animator.setInterpolator(getInterpolator());
        }
        animator.addListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animation) {
                Transition.this.end();
                animation.removeListener(this);
            }
        });
        animator.start();
    }

    /* access modifiers changed from: protected */
    public void start() {
        if (this.mNumInstances == 0) {
            ArrayList<TransitionListener> arrayList = this.mListeners;
            if (arrayList != null && arrayList.size() > 0) {
                ArrayList<TransitionListener> tmpListeners = (ArrayList) this.mListeners.clone();
                int numListeners = tmpListeners.size();
                for (int i = 0; i < numListeners; i++) {
                    ((TransitionListener) tmpListeners.get(i)).onTransitionStart(this);
                }
            }
            this.mEnded = false;
        }
        this.mNumInstances++;
    }

    /* access modifiers changed from: protected */
    public void end() {
        int i = this.mNumInstances - 1;
        this.mNumInstances = i;
        if (i == 0) {
            ArrayList<TransitionListener> arrayList = this.mListeners;
            if (arrayList != null && arrayList.size() > 0) {
                ArrayList<TransitionListener> tmpListeners = (ArrayList) this.mListeners.clone();
                int numListeners = tmpListeners.size();
                for (int i2 = 0; i2 < numListeners; i2++) {
                    ((TransitionListener) tmpListeners.get(i2)).onTransitionEnd(this);
                }
            }
            for (int i3 = 0; i3 < this.mStartValues.mItemIdValues.size(); i3++) {
                View view = (View) this.mStartValues.mItemIdValues.valueAt(i3);
                if (view != null) {
                    ViewCompat.setHasTransientState(view, false);
                }
            }
            for (int i4 = 0; i4 < this.mEndValues.mItemIdValues.size(); i4++) {
                View view2 = (View) this.mEndValues.mItemIdValues.valueAt(i4);
                if (view2 != null) {
                    ViewCompat.setHasTransientState(view2, false);
                }
            }
            this.mEnded = true;
        }
    }

    /* access modifiers changed from: 0000 */
    public void forceToEnd(ViewGroup sceneRoot) {
        ArrayMap<Animator, AnimationInfo> runningAnimators = getRunningAnimators();
        int numOldAnims = runningAnimators.size();
        if (sceneRoot != null) {
            WindowIdImpl windowId = ViewUtils.getWindowId(sceneRoot);
            for (int i = numOldAnims - 1; i >= 0; i--) {
                AnimationInfo info = (AnimationInfo) runningAnimators.valueAt(i);
                if (!(info.mView == null || windowId == null || !windowId.equals(info.mWindowId))) {
                    ((Animator) runningAnimators.keyAt(i)).end();
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void cancel() {
        for (int i = this.mCurrentAnimators.size() - 1; i >= 0; i--) {
            ((Animator) this.mCurrentAnimators.get(i)).cancel();
        }
        ArrayList<TransitionListener> arrayList = this.mListeners;
        if (arrayList != null && arrayList.size() > 0) {
            ArrayList<TransitionListener> tmpListeners = (ArrayList) this.mListeners.clone();
            int numListeners = tmpListeners.size();
            for (int i2 = 0; i2 < numListeners; i2++) {
                ((TransitionListener) tmpListeners.get(i2)).onTransitionCancel(this);
            }
        }
    }

    public Transition addListener(TransitionListener listener) {
        if (this.mListeners == null) {
            this.mListeners = new ArrayList<>();
        }
        this.mListeners.add(listener);
        return this;
    }

    public Transition removeListener(TransitionListener listener) {
        ArrayList<TransitionListener> arrayList = this.mListeners;
        if (arrayList == null) {
            return this;
        }
        arrayList.remove(listener);
        if (this.mListeners.size() == 0) {
            this.mListeners = null;
        }
        return this;
    }

    public void setPathMotion(PathMotion pathMotion) {
        if (pathMotion == null) {
            this.mPathMotion = STRAIGHT_PATH_MOTION;
        } else {
            this.mPathMotion = pathMotion;
        }
    }

    public PathMotion getPathMotion() {
        return this.mPathMotion;
    }

    public void setEpicenterCallback(EpicenterCallback epicenterCallback) {
        this.mEpicenterCallback = epicenterCallback;
    }

    public EpicenterCallback getEpicenterCallback() {
        return this.mEpicenterCallback;
    }

    public Rect getEpicenter() {
        EpicenterCallback epicenterCallback = this.mEpicenterCallback;
        if (epicenterCallback == null) {
            return null;
        }
        return epicenterCallback.onGetEpicenter(this);
    }

    public void setPropagation(TransitionPropagation transitionPropagation) {
        this.mPropagation = transitionPropagation;
    }

    public TransitionPropagation getPropagation() {
        return this.mPropagation;
    }

    /* access modifiers changed from: 0000 */
    public void capturePropagationValues(TransitionValues transitionValues) {
        if (this.mPropagation != null && !transitionValues.values.isEmpty()) {
            String[] propertyNames = this.mPropagation.getPropagationProperties();
            if (propertyNames != null) {
                boolean containsAll = true;
                int i = 0;
                while (true) {
                    if (i >= propertyNames.length) {
                        break;
                    } else if (!transitionValues.values.containsKey(propertyNames[i])) {
                        containsAll = false;
                        break;
                    } else {
                        i++;
                    }
                }
                if (!containsAll) {
                    this.mPropagation.captureValues(transitionValues);
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public Transition setSceneRoot(ViewGroup sceneRoot) {
        this.mSceneRoot = sceneRoot;
        return this;
    }

    /* access modifiers changed from: 0000 */
    public void setCanRemoveViews(boolean canRemoveViews) {
        this.mCanRemoveViews = canRemoveViews;
    }

    public String toString() {
        return toString("");
    }

    public Transition clone() {
        try {
            Transition clone = (Transition) super.clone();
            clone.mAnimators = new ArrayList<>();
            clone.mStartValues = new TransitionValuesMaps();
            clone.mEndValues = new TransitionValuesMaps();
            clone.mStartValuesList = null;
            clone.mEndValuesList = null;
            return clone;
        } catch (CloneNotSupportedException e) {
            return null;
        }
    }

    public String getName() {
        return this.mName;
    }

    /* access modifiers changed from: 0000 */
    public String toString(String indent) {
        StringBuilder sb = new StringBuilder();
        sb.append(indent);
        sb.append(getClass().getSimpleName());
        sb.append("@");
        sb.append(Integer.toHexString(hashCode()));
        sb.append(": ");
        String result = sb.toString();
        String str = ") ";
        if (this.mDuration != -1) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(result);
            sb2.append("dur(");
            sb2.append(this.mDuration);
            sb2.append(str);
            result = sb2.toString();
        }
        if (this.mStartDelay != -1) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(result);
            sb3.append("dly(");
            sb3.append(this.mStartDelay);
            sb3.append(str);
            result = sb3.toString();
        }
        if (this.mInterpolator != null) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append(result);
            sb4.append("interp(");
            sb4.append(this.mInterpolator);
            sb4.append(str);
            result = sb4.toString();
        }
        if (this.mTargetIds.size() <= 0 && this.mTargets.size() <= 0) {
            return result;
        }
        StringBuilder sb5 = new StringBuilder();
        sb5.append(result);
        sb5.append("tgts(");
        String result2 = sb5.toString();
        String str2 = ", ";
        if (this.mTargetIds.size() > 0) {
            for (int i = 0; i < this.mTargetIds.size(); i++) {
                if (i > 0) {
                    StringBuilder sb6 = new StringBuilder();
                    sb6.append(result2);
                    sb6.append(str2);
                    result2 = sb6.toString();
                }
                StringBuilder sb7 = new StringBuilder();
                sb7.append(result2);
                sb7.append(this.mTargetIds.get(i));
                result2 = sb7.toString();
            }
        }
        if (this.mTargets.size() > 0) {
            for (int i2 = 0; i2 < this.mTargets.size(); i2++) {
                if (i2 > 0) {
                    StringBuilder sb8 = new StringBuilder();
                    sb8.append(result2);
                    sb8.append(str2);
                    result2 = sb8.toString();
                }
                StringBuilder sb9 = new StringBuilder();
                sb9.append(result2);
                sb9.append(this.mTargets.get(i2));
                result2 = sb9.toString();
            }
        }
        StringBuilder sb10 = new StringBuilder();
        sb10.append(result2);
        sb10.append(")");
        return sb10.toString();
    }
}
