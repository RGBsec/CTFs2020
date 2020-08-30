package androidx.fragment.app;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources.NotFoundException;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.os.Looper;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.LayoutInflater.Factory2;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.Animation.AnimationListener;
import android.view.animation.AnimationSet;
import android.view.animation.AnimationUtils;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.ScaleAnimation;
import android.view.animation.Transformation;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.OnBackPressedDispatcher;
import androidx.collection.ArraySet;
import androidx.core.util.DebugUtils;
import androidx.core.util.LogWriter;
import androidx.core.view.OneShotPreDrawListener;
import androidx.fragment.app.Fragment.SavedState;
import androidx.fragment.app.FragmentManager.BackStackEntry;
import androidx.fragment.app.FragmentManager.FragmentLifecycleCallbacks;
import androidx.fragment.app.FragmentManager.OnBackStackChangedListener;
import androidx.lifecycle.Lifecycle.State;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

final class FragmentManagerImpl extends FragmentManager implements Factory2 {
    static final int ANIM_DUR = 220;
    public static final int ANIM_STYLE_CLOSE_ENTER = 3;
    public static final int ANIM_STYLE_CLOSE_EXIT = 4;
    public static final int ANIM_STYLE_FADE_ENTER = 5;
    public static final int ANIM_STYLE_FADE_EXIT = 6;
    public static final int ANIM_STYLE_OPEN_ENTER = 1;
    public static final int ANIM_STYLE_OPEN_EXIT = 2;
    static boolean DEBUG = false;
    static final Interpolator DECELERATE_CUBIC = new DecelerateInterpolator(1.5f);
    static final Interpolator DECELERATE_QUINT = new DecelerateInterpolator(2.5f);
    static final String TAG = "FragmentManager";
    static final String TARGET_REQUEST_CODE_STATE_TAG = "android:target_req_state";
    static final String TARGET_STATE_TAG = "android:target_state";
    static final String USER_VISIBLE_HINT_TAG = "android:user_visible_hint";
    static final String VIEW_STATE_TAG = "android:view_state";
    final HashMap<String, Fragment> mActive = new HashMap<>();
    final ArrayList<Fragment> mAdded = new ArrayList<>();
    ArrayList<Integer> mAvailBackStackIndices;
    ArrayList<BackStackRecord> mBackStack;
    ArrayList<OnBackStackChangedListener> mBackStackChangeListeners;
    ArrayList<BackStackRecord> mBackStackIndices;
    FragmentContainer mContainer;
    ArrayList<Fragment> mCreatedMenus;
    int mCurState = 0;
    boolean mDestroyed;
    Runnable mExecCommit = new Runnable() {
        public void run() {
            FragmentManagerImpl.this.execPendingActions();
        }
    };
    boolean mExecutingActions;
    boolean mHavePendingDeferredStart;
    FragmentHostCallback mHost;
    private final CopyOnWriteArrayList<FragmentLifecycleCallbacksHolder> mLifecycleCallbacks = new CopyOnWriteArrayList<>();
    boolean mNeedMenuInvalidate;
    int mNextFragmentIndex = 0;
    private FragmentManagerViewModel mNonConfig;
    private final OnBackPressedCallback mOnBackPressedCallback = new OnBackPressedCallback(false) {
        public void handleOnBackPressed() {
            FragmentManagerImpl.this.handleOnBackPressed();
        }
    };
    private OnBackPressedDispatcher mOnBackPressedDispatcher;
    Fragment mParent;
    ArrayList<OpGenerator> mPendingActions;
    ArrayList<StartEnterTransitionListener> mPostponedTransactions;
    Fragment mPrimaryNav;
    SparseArray<Parcelable> mStateArray = null;
    Bundle mStateBundle = null;
    boolean mStateSaved;
    boolean mStopped;
    ArrayList<Fragment> mTmpAddedFragments;
    ArrayList<Boolean> mTmpIsPop;
    ArrayList<BackStackRecord> mTmpRecords;

    private static class AnimationOrAnimator {
        public final Animation animation;
        public final Animator animator;

        AnimationOrAnimator(Animation animation2) {
            this.animation = animation2;
            this.animator = null;
            if (animation2 == null) {
                throw new IllegalStateException("Animation cannot be null");
            }
        }

        AnimationOrAnimator(Animator animator2) {
            this.animation = null;
            this.animator = animator2;
            if (animator2 == null) {
                throw new IllegalStateException("Animator cannot be null");
            }
        }
    }

    private static class EndViewTransitionAnimation extends AnimationSet implements Runnable {
        private boolean mAnimating = true;
        private final View mChild;
        private boolean mEnded;
        private final ViewGroup mParent;
        private boolean mTransitionEnded;

        EndViewTransitionAnimation(Animation animation, ViewGroup viewGroup, View view) {
            super(false);
            this.mParent = viewGroup;
            this.mChild = view;
            addAnimation(animation);
            this.mParent.post(this);
        }

        public boolean getTransformation(long j, Transformation transformation) {
            this.mAnimating = true;
            if (this.mEnded) {
                return !this.mTransitionEnded;
            }
            if (!super.getTransformation(j, transformation)) {
                this.mEnded = true;
                OneShotPreDrawListener.add(this.mParent, this);
            }
            return true;
        }

        public boolean getTransformation(long j, Transformation transformation, float f) {
            this.mAnimating = true;
            if (this.mEnded) {
                return !this.mTransitionEnded;
            }
            if (!super.getTransformation(j, transformation, f)) {
                this.mEnded = true;
                OneShotPreDrawListener.add(this.mParent, this);
            }
            return true;
        }

        public void run() {
            if (this.mEnded || !this.mAnimating) {
                this.mParent.endViewTransition(this.mChild);
                this.mTransitionEnded = true;
                return;
            }
            this.mAnimating = false;
            this.mParent.post(this);
        }
    }

    private static final class FragmentLifecycleCallbacksHolder {
        final FragmentLifecycleCallbacks mCallback;
        final boolean mRecursive;

        FragmentLifecycleCallbacksHolder(FragmentLifecycleCallbacks fragmentLifecycleCallbacks, boolean z) {
            this.mCallback = fragmentLifecycleCallbacks;
            this.mRecursive = z;
        }
    }

    static class FragmentTag {
        public static final int[] Fragment = {16842755, 16842960, 16842961};
        public static final int Fragment_id = 1;
        public static final int Fragment_name = 0;
        public static final int Fragment_tag = 2;

        private FragmentTag() {
        }
    }

    interface OpGenerator {
        boolean generateOps(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2);
    }

    private class PopBackStackState implements OpGenerator {
        final int mFlags;
        final int mId;
        final String mName;

        PopBackStackState(String str, int i, int i2) {
            this.mName = str;
            this.mId = i;
            this.mFlags = i2;
        }

        public boolean generateOps(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2) {
            if (FragmentManagerImpl.this.mPrimaryNav != null && this.mId < 0 && this.mName == null && FragmentManagerImpl.this.mPrimaryNav.getChildFragmentManager().popBackStackImmediate()) {
                return false;
            }
            return FragmentManagerImpl.this.popBackStackState(arrayList, arrayList2, this.mName, this.mId, this.mFlags);
        }
    }

    static class StartEnterTransitionListener implements OnStartEnterTransitionListener {
        final boolean mIsBack;
        private int mNumPostponed;
        final BackStackRecord mRecord;

        StartEnterTransitionListener(BackStackRecord backStackRecord, boolean z) {
            this.mIsBack = z;
            this.mRecord = backStackRecord;
        }

        public void onStartEnterTransition() {
            int i = this.mNumPostponed - 1;
            this.mNumPostponed = i;
            if (i == 0) {
                this.mRecord.mManager.scheduleCommit();
            }
        }

        public void startListening() {
            this.mNumPostponed++;
        }

        public boolean isReady() {
            return this.mNumPostponed == 0;
        }

        public void completeTransaction() {
            boolean z = this.mNumPostponed > 0;
            FragmentManagerImpl fragmentManagerImpl = this.mRecord.mManager;
            int size = fragmentManagerImpl.mAdded.size();
            for (int i = 0; i < size; i++) {
                Fragment fragment = (Fragment) fragmentManagerImpl.mAdded.get(i);
                fragment.setOnStartEnterTransitionListener(null);
                if (z && fragment.isPostponed()) {
                    fragment.startPostponedEnterTransition();
                }
            }
            this.mRecord.mManager.completeExecute(this.mRecord, this.mIsBack, !z, true);
        }

        public void cancelTransaction() {
            this.mRecord.mManager.completeExecute(this.mRecord, this.mIsBack, false, false);
        }
    }

    public static int reverseTransit(int i) {
        if (i == 4097) {
            return 8194;
        }
        if (i == 4099) {
            return FragmentTransaction.TRANSIT_FRAGMENT_FADE;
        }
        if (i != 8194) {
            return 0;
        }
        return FragmentTransaction.TRANSIT_FRAGMENT_OPEN;
    }

    public static int transitToStyleIndex(int i, boolean z) {
        if (i == 4097) {
            return z ? 1 : 2;
        }
        if (i == 4099) {
            return z ? 5 : 6;
        }
        if (i != 8194) {
            return -1;
        }
        return z ? 3 : 4;
    }

    /* access modifiers changed from: 0000 */
    public Factory2 getLayoutInflaterFactory() {
        return this;
    }

    FragmentManagerImpl() {
    }

    private void throwException(RuntimeException runtimeException) {
        String message = runtimeException.getMessage();
        String str = TAG;
        Log.e(str, message);
        Log.e(str, "Activity state:");
        PrintWriter printWriter = new PrintWriter(new LogWriter(str));
        FragmentHostCallback fragmentHostCallback = this.mHost;
        String str2 = "Failed dumping state";
        String str3 = "  ";
        if (fragmentHostCallback != null) {
            try {
                fragmentHostCallback.onDump(str3, null, printWriter, new String[0]);
            } catch (Exception e) {
                Log.e(str, str2, e);
            }
        } else {
            try {
                dump(str3, null, printWriter, new String[0]);
            } catch (Exception e2) {
                Log.e(str, str2, e2);
            }
        }
        throw runtimeException;
    }

    public FragmentTransaction beginTransaction() {
        return new BackStackRecord(this);
    }

    public boolean executePendingTransactions() {
        boolean execPendingActions = execPendingActions();
        forcePostponedTransactions();
        return execPendingActions;
    }

    private void updateOnBackPressedCallbackEnabled() {
        ArrayList<OpGenerator> arrayList = this.mPendingActions;
        boolean z = true;
        if (arrayList == null || arrayList.isEmpty()) {
            OnBackPressedCallback onBackPressedCallback = this.mOnBackPressedCallback;
            if (getBackStackEntryCount() <= 0 || !isPrimaryNavigation(this.mParent)) {
                z = false;
            }
            onBackPressedCallback.setEnabled(z);
            return;
        }
        this.mOnBackPressedCallback.setEnabled(true);
    }

    /* access modifiers changed from: 0000 */
    public boolean isPrimaryNavigation(Fragment fragment) {
        boolean z = true;
        if (fragment == null) {
            return true;
        }
        FragmentManagerImpl fragmentManagerImpl = fragment.mFragmentManager;
        if (fragment != fragmentManagerImpl.getPrimaryNavigationFragment() || !isPrimaryNavigation(fragmentManagerImpl.mParent)) {
            z = false;
        }
        return z;
    }

    /* access modifiers changed from: 0000 */
    public void handleOnBackPressed() {
        execPendingActions();
        if (this.mOnBackPressedCallback.isEnabled()) {
            popBackStackImmediate();
        } else {
            this.mOnBackPressedDispatcher.onBackPressed();
        }
    }

    public void popBackStack() {
        enqueueAction(new PopBackStackState(null, -1, 0), false);
    }

    public boolean popBackStackImmediate() {
        checkStateLoss();
        return popBackStackImmediate(null, -1, 0);
    }

    public void popBackStack(String str, int i) {
        enqueueAction(new PopBackStackState(str, -1, i), false);
    }

    public boolean popBackStackImmediate(String str, int i) {
        checkStateLoss();
        return popBackStackImmediate(str, -1, i);
    }

    public void popBackStack(int i, int i2) {
        if (i >= 0) {
            enqueueAction(new PopBackStackState(null, i, i2), false);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Bad id: ");
        sb.append(i);
        throw new IllegalArgumentException(sb.toString());
    }

    public boolean popBackStackImmediate(int i, int i2) {
        checkStateLoss();
        execPendingActions();
        if (i >= 0) {
            return popBackStackImmediate(null, i, i2);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Bad id: ");
        sb.append(i);
        throw new IllegalArgumentException(sb.toString());
    }

    private boolean popBackStackImmediate(String str, int i, int i2) {
        execPendingActions();
        ensureExecReady(true);
        Fragment fragment = this.mPrimaryNav;
        if (fragment != null && i < 0 && str == null && fragment.getChildFragmentManager().popBackStackImmediate()) {
            return true;
        }
        boolean popBackStackState = popBackStackState(this.mTmpRecords, this.mTmpIsPop, str, i, i2);
        if (popBackStackState) {
            this.mExecutingActions = true;
            try {
                removeRedundantOperationsAndExecute(this.mTmpRecords, this.mTmpIsPop);
            } finally {
                cleanupExec();
            }
        }
        updateOnBackPressedCallbackEnabled();
        doPendingDeferredStart();
        burpActive();
        return popBackStackState;
    }

    public int getBackStackEntryCount() {
        ArrayList<BackStackRecord> arrayList = this.mBackStack;
        if (arrayList != null) {
            return arrayList.size();
        }
        return 0;
    }

    public BackStackEntry getBackStackEntryAt(int i) {
        return (BackStackEntry) this.mBackStack.get(i);
    }

    public void addOnBackStackChangedListener(OnBackStackChangedListener onBackStackChangedListener) {
        if (this.mBackStackChangeListeners == null) {
            this.mBackStackChangeListeners = new ArrayList<>();
        }
        this.mBackStackChangeListeners.add(onBackStackChangedListener);
    }

    public void removeOnBackStackChangedListener(OnBackStackChangedListener onBackStackChangedListener) {
        ArrayList<OnBackStackChangedListener> arrayList = this.mBackStackChangeListeners;
        if (arrayList != null) {
            arrayList.remove(onBackStackChangedListener);
        }
    }

    public void putFragment(Bundle bundle, String str, Fragment fragment) {
        if (fragment.mFragmentManager != this) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(fragment);
            sb.append(" is not currently in the FragmentManager");
            throwException(new IllegalStateException(sb.toString()));
        }
        bundle.putString(str, fragment.mWho);
    }

    public Fragment getFragment(Bundle bundle, String str) {
        String string = bundle.getString(str);
        if (string == null) {
            return null;
        }
        Fragment fragment = (Fragment) this.mActive.get(string);
        if (fragment == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment no longer exists for key ");
            sb.append(str);
            sb.append(": unique id ");
            sb.append(string);
            throwException(new IllegalStateException(sb.toString()));
        }
        return fragment;
    }

    public List<Fragment> getFragments() {
        List<Fragment> list;
        if (this.mAdded.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (this.mAdded) {
            list = (List) this.mAdded.clone();
        }
        return list;
    }

    /* access modifiers changed from: 0000 */
    public ViewModelStore getViewModelStore(Fragment fragment) {
        return this.mNonConfig.getViewModelStore(fragment);
    }

    /* access modifiers changed from: 0000 */
    public FragmentManagerViewModel getChildNonConfig(Fragment fragment) {
        return this.mNonConfig.getChildNonConfig(fragment);
    }

    /* access modifiers changed from: 0000 */
    public void addRetainedFragment(Fragment fragment) {
        boolean isStateSaved = isStateSaved();
        String str = TAG;
        if (isStateSaved) {
            if (DEBUG) {
                Log.v(str, "Ignoring addRetainedFragment as the state is already saved");
            }
            return;
        }
        if (this.mNonConfig.addRetainedFragment(fragment) && DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("Updating retained Fragments: Added ");
            sb.append(fragment);
            Log.v(str, sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void removeRetainedFragment(Fragment fragment) {
        boolean isStateSaved = isStateSaved();
        String str = TAG;
        if (isStateSaved) {
            if (DEBUG) {
                Log.v(str, "Ignoring removeRetainedFragment as the state is already saved");
            }
            return;
        }
        if (this.mNonConfig.removeRetainedFragment(fragment) && DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("Updating retained Fragments: Removed ");
            sb.append(fragment);
            Log.v(str, sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public List<Fragment> getActiveFragments() {
        return new ArrayList(this.mActive.values());
    }

    /* access modifiers changed from: 0000 */
    public int getActiveFragmentCount() {
        return this.mActive.size();
    }

    public SavedState saveFragmentInstanceState(Fragment fragment) {
        if (fragment.mFragmentManager != this) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(fragment);
            sb.append(" is not currently in the FragmentManager");
            throwException(new IllegalStateException(sb.toString()));
        }
        if (fragment.mState <= 0) {
            return null;
        }
        Bundle saveFragmentBasicState = saveFragmentBasicState(fragment);
        if (saveFragmentBasicState != null) {
            return new SavedState(saveFragmentBasicState);
        }
        return null;
    }

    public boolean isDestroyed() {
        return this.mDestroyed;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("FragmentManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        Fragment fragment = this.mParent;
        if (fragment != null) {
            DebugUtils.buildShortClassTag(fragment, sb);
        } else {
            DebugUtils.buildShortClassTag(this.mHost, sb);
        }
        sb.append("}}");
        return sb.toString();
    }

    public void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append("    ");
        String sb2 = sb.toString();
        if (!this.mActive.isEmpty()) {
            printWriter.print(str);
            printWriter.print("Active Fragments in ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this)));
            printWriter.println(":");
            for (Fragment fragment : this.mActive.values()) {
                printWriter.print(str);
                printWriter.println(fragment);
                if (fragment != null) {
                    fragment.dump(sb2, fileDescriptor, printWriter, strArr);
                }
            }
        }
        int size = this.mAdded.size();
        if (size > 0) {
            printWriter.print(str);
            printWriter.println("Added Fragments:");
            for (int i = 0; i < size; i++) {
                Fragment fragment2 = (Fragment) this.mAdded.get(i);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i);
                printWriter.print(": ");
                printWriter.println(fragment2.toString());
            }
        }
        ArrayList<Fragment> arrayList = this.mCreatedMenus;
        if (arrayList != null) {
            int size2 = arrayList.size();
            if (size2 > 0) {
                printWriter.print(str);
                printWriter.println("Fragments Created Menus:");
                for (int i2 = 0; i2 < size2; i2++) {
                    Fragment fragment3 = (Fragment) this.mCreatedMenus.get(i2);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i2);
                    printWriter.print(": ");
                    printWriter.println(fragment3.toString());
                }
            }
        }
        ArrayList<BackStackRecord> arrayList2 = this.mBackStack;
        if (arrayList2 != null) {
            int size3 = arrayList2.size();
            if (size3 > 0) {
                printWriter.print(str);
                printWriter.println("Back Stack:");
                for (int i3 = 0; i3 < size3; i3++) {
                    BackStackRecord backStackRecord = (BackStackRecord) this.mBackStack.get(i3);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i3);
                    printWriter.print(": ");
                    printWriter.println(backStackRecord.toString());
                    backStackRecord.dump(sb2, printWriter);
                }
            }
        }
        synchronized (this) {
            if (this.mBackStackIndices != null) {
                int size4 = this.mBackStackIndices.size();
                if (size4 > 0) {
                    printWriter.print(str);
                    printWriter.println("Back Stack Indices:");
                    for (int i4 = 0; i4 < size4; i4++) {
                        BackStackRecord backStackRecord2 = (BackStackRecord) this.mBackStackIndices.get(i4);
                        printWriter.print(str);
                        printWriter.print("  #");
                        printWriter.print(i4);
                        printWriter.print(": ");
                        printWriter.println(backStackRecord2);
                    }
                }
            }
            if (this.mAvailBackStackIndices != null && this.mAvailBackStackIndices.size() > 0) {
                printWriter.print(str);
                printWriter.print("mAvailBackStackIndices: ");
                printWriter.println(Arrays.toString(this.mAvailBackStackIndices.toArray()));
            }
        }
        ArrayList<OpGenerator> arrayList3 = this.mPendingActions;
        if (arrayList3 != null) {
            int size5 = arrayList3.size();
            if (size5 > 0) {
                printWriter.print(str);
                printWriter.println("Pending Actions:");
                for (int i5 = 0; i5 < size5; i5++) {
                    OpGenerator opGenerator = (OpGenerator) this.mPendingActions.get(i5);
                    printWriter.print(str);
                    printWriter.print("  #");
                    printWriter.print(i5);
                    printWriter.print(": ");
                    printWriter.println(opGenerator);
                }
            }
        }
        printWriter.print(str);
        printWriter.println("FragmentManager misc state:");
        printWriter.print(str);
        printWriter.print("  mHost=");
        printWriter.println(this.mHost);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.mContainer);
        if (this.mParent != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.mParent);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.mCurState);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.mStateSaved);
        printWriter.print(" mStopped=");
        printWriter.print(this.mStopped);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.mDestroyed);
        if (this.mNeedMenuInvalidate) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.mNeedMenuInvalidate);
        }
    }

    static AnimationOrAnimator makeOpenCloseAnimation(float f, float f2, float f3, float f4) {
        AnimationSet animationSet = new AnimationSet(false);
        ScaleAnimation scaleAnimation = new ScaleAnimation(f, f2, f, f2, 1, 0.5f, 1, 0.5f);
        scaleAnimation.setInterpolator(DECELERATE_QUINT);
        scaleAnimation.setDuration(220);
        animationSet.addAnimation(scaleAnimation);
        AlphaAnimation alphaAnimation = new AlphaAnimation(f3, f4);
        alphaAnimation.setInterpolator(DECELERATE_CUBIC);
        alphaAnimation.setDuration(220);
        animationSet.addAnimation(alphaAnimation);
        return new AnimationOrAnimator((Animation) animationSet);
    }

    static AnimationOrAnimator makeFadeAnimation(float f, float f2) {
        AlphaAnimation alphaAnimation = new AlphaAnimation(f, f2);
        alphaAnimation.setInterpolator(DECELERATE_CUBIC);
        alphaAnimation.setDuration(220);
        return new AnimationOrAnimator((Animation) alphaAnimation);
    }

    /* access modifiers changed from: 0000 */
    public AnimationOrAnimator loadAnimation(Fragment fragment, int i, boolean z, int i2) {
        int nextAnim = fragment.getNextAnim();
        boolean z2 = false;
        fragment.setNextAnim(0);
        if (fragment.mContainer != null && fragment.mContainer.getLayoutTransition() != null) {
            return null;
        }
        Animation onCreateAnimation = fragment.onCreateAnimation(i, z, nextAnim);
        if (onCreateAnimation != null) {
            return new AnimationOrAnimator(onCreateAnimation);
        }
        Animator onCreateAnimator = fragment.onCreateAnimator(i, z, nextAnim);
        if (onCreateAnimator != null) {
            return new AnimationOrAnimator(onCreateAnimator);
        }
        if (nextAnim != 0) {
            boolean equals = "anim".equals(this.mHost.getContext().getResources().getResourceTypeName(nextAnim));
            if (equals) {
                try {
                    Animation loadAnimation = AnimationUtils.loadAnimation(this.mHost.getContext(), nextAnim);
                    if (loadAnimation != null) {
                        return new AnimationOrAnimator(loadAnimation);
                    }
                    z2 = true;
                } catch (NotFoundException e) {
                    throw e;
                } catch (RuntimeException unused) {
                }
            }
            if (!z2) {
                try {
                    Animator loadAnimator = AnimatorInflater.loadAnimator(this.mHost.getContext(), nextAnim);
                    if (loadAnimator != null) {
                        return new AnimationOrAnimator(loadAnimator);
                    }
                } catch (RuntimeException e2) {
                    if (!equals) {
                        Animation loadAnimation2 = AnimationUtils.loadAnimation(this.mHost.getContext(), nextAnim);
                        if (loadAnimation2 != null) {
                            return new AnimationOrAnimator(loadAnimation2);
                        }
                    } else {
                        throw e2;
                    }
                }
            }
        }
        if (i == 0) {
            return null;
        }
        int transitToStyleIndex = transitToStyleIndex(i, z);
        if (transitToStyleIndex < 0) {
            return null;
        }
        switch (transitToStyleIndex) {
            case 1:
                return makeOpenCloseAnimation(1.125f, 1.0f, 0.0f, 1.0f);
            case 2:
                return makeOpenCloseAnimation(1.0f, 0.975f, 1.0f, 0.0f);
            case 3:
                return makeOpenCloseAnimation(0.975f, 1.0f, 0.0f, 1.0f);
            case 4:
                return makeOpenCloseAnimation(1.0f, 1.075f, 1.0f, 0.0f);
            case 5:
                return makeFadeAnimation(0.0f, 1.0f);
            case 6:
                return makeFadeAnimation(1.0f, 0.0f);
            default:
                if (i2 == 0 && this.mHost.onHasWindowAnimations()) {
                    i2 = this.mHost.onGetWindowAnimations();
                }
                if (i2 == 0) {
                }
                return null;
        }
    }

    public void performPendingDeferredStart(Fragment fragment) {
        if (fragment.mDeferStart) {
            if (this.mExecutingActions) {
                this.mHavePendingDeferredStart = true;
                return;
            }
            fragment.mDeferStart = false;
            moveToState(fragment, this.mCurState, 0, 0, false);
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isStateAtLeast(int i) {
        return this.mCurState >= i;
    }

    /* JADX WARNING: type inference failed for: r8v0 */
    /* JADX WARNING: type inference failed for: r8v1, types: [int] */
    /* JADX WARNING: type inference failed for: r11v1 */
    /* JADX WARNING: type inference failed for: r8v2 */
    /* JADX WARNING: type inference failed for: r8v3 */
    /* JADX WARNING: type inference failed for: r8v5, types: [boolean] */
    /* JADX WARNING: type inference failed for: r11v2 */
    /* JADX WARNING: type inference failed for: r11v3 */
    /* JADX WARNING: type inference failed for: r11v4 */
    /* JADX WARNING: type inference failed for: r8v6, types: [boolean] */
    /* JADX WARNING: type inference failed for: r8v7 */
    /* JADX WARNING: type inference failed for: r11v5 */
    /* JADX WARNING: type inference failed for: r11v6 */
    /* JADX WARNING: type inference failed for: r8v8 */
    /* JADX WARNING: type inference failed for: r8v9 */
    /* JADX WARNING: type inference failed for: r11v7 */
    /* JADX WARNING: type inference failed for: r11v8 */
    /* JADX WARNING: type inference failed for: r11v9 */
    /* JADX WARNING: type inference failed for: r11v10 */
    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r11v5
      assigns: []
      uses: []
      mth insns count: 518
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:99)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:92)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.core.ProcessClass.lambda$processDependencies$0(ProcessClass.java:49)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.ProcessClass.processDependencies(ProcessClass.java:49)
    	at jadx.core.ProcessClass.process(ProcessClass.java:35)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:217)
     */
    /* JADX WARNING: Removed duplicated region for block: B:146:0x02fa  */
    /* JADX WARNING: Removed duplicated region for block: B:152:0x031b  */
    /* JADX WARNING: Removed duplicated region for block: B:267:0x0503  */
    /* JADX WARNING: Unknown variable types count: 3 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void moveToState(androidx.fragment.app.Fragment r19, int r20, int r21, int r22, boolean r23) {
        /*
            r18 = this;
            r6 = r18
            r7 = r19
            boolean r0 = r7.mAdded
            r8 = 1
            if (r0 == 0) goto L_0x0011
            boolean r0 = r7.mDetached
            if (r0 == 0) goto L_0x000e
            goto L_0x0011
        L_0x000e:
            r0 = r20
            goto L_0x0016
        L_0x0011:
            r0 = r20
            if (r0 <= r8) goto L_0x0016
            r0 = r8
        L_0x0016:
            boolean r1 = r7.mRemoving
            if (r1 == 0) goto L_0x002c
            int r1 = r7.mState
            if (r0 <= r1) goto L_0x002c
            int r0 = r7.mState
            if (r0 != 0) goto L_0x002a
            boolean r0 = r19.isInBackStack()
            if (r0 == 0) goto L_0x002a
            r0 = r8
            goto L_0x002c
        L_0x002a:
            int r0 = r7.mState
        L_0x002c:
            boolean r1 = r7.mDeferStart
            r9 = 3
            r10 = 2
            if (r1 == 0) goto L_0x0039
            int r1 = r7.mState
            if (r1 >= r9) goto L_0x0039
            if (r0 <= r10) goto L_0x0039
            r0 = r10
        L_0x0039:
            androidx.lifecycle.Lifecycle$State r1 = r7.mMaxState
            androidx.lifecycle.Lifecycle$State r2 = androidx.lifecycle.Lifecycle.State.CREATED
            if (r1 != r2) goto L_0x0044
            int r0 = java.lang.Math.min(r0, r8)
            goto L_0x004e
        L_0x0044:
            androidx.lifecycle.Lifecycle$State r1 = r7.mMaxState
            int r1 = r1.ordinal()
            int r0 = java.lang.Math.min(r0, r1)
        L_0x004e:
            r11 = r0
            int r0 = r7.mState
            java.lang.String r12 = "FragmentManager"
            r13 = 0
            r14 = 0
            if (r0 > r11) goto L_0x033f
            boolean r0 = r7.mFromLayout
            if (r0 == 0) goto L_0x0060
            boolean r0 = r7.mInLayout
            if (r0 != 0) goto L_0x0060
            return
        L_0x0060:
            android.view.View r0 = r19.getAnimatingAway()
            if (r0 != 0) goto L_0x006c
            android.animation.Animator r0 = r19.getAnimator()
            if (r0 == 0) goto L_0x0080
        L_0x006c:
            r7.setAnimatingAway(r14)
            r7.setAnimator(r14)
            int r2 = r19.getStateAfterAnimating()
            r3 = 0
            r4 = 0
            r5 = 1
            r0 = r18
            r1 = r19
            r0.moveToState(r1, r2, r3, r4, r5)
        L_0x0080:
            int r0 = r7.mState
            if (r0 == 0) goto L_0x0092
            if (r0 == r8) goto L_0x01fd
            if (r0 == r10) goto L_0x008f
            if (r0 == r9) goto L_0x008c
            goto L_0x04fe
        L_0x008c:
            r0 = r9
            goto L_0x0319
        L_0x008f:
            r0 = r10
            goto L_0x02f8
        L_0x0092:
            if (r11 <= 0) goto L_0x01fd
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x00ac
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "moveto CREATED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x00ac:
            android.os.Bundle r0 = r7.mSavedFragmentState
            if (r0 == 0) goto L_0x0109
            android.os.Bundle r0 = r7.mSavedFragmentState
            androidx.fragment.app.FragmentHostCallback r1 = r6.mHost
            android.content.Context r1 = r1.getContext()
            java.lang.ClassLoader r1 = r1.getClassLoader()
            r0.setClassLoader(r1)
            android.os.Bundle r0 = r7.mSavedFragmentState
            java.lang.String r1 = "android:view_state"
            android.util.SparseArray r0 = r0.getSparseParcelableArray(r1)
            r7.mSavedViewState = r0
            android.os.Bundle r0 = r7.mSavedFragmentState
            java.lang.String r1 = "android:target_state"
            androidx.fragment.app.Fragment r0 = r6.getFragment(r0, r1)
            if (r0 == 0) goto L_0x00d6
            java.lang.String r0 = r0.mWho
            goto L_0x00d7
        L_0x00d6:
            r0 = r14
        L_0x00d7:
            r7.mTargetWho = r0
            java.lang.String r0 = r7.mTargetWho
            if (r0 == 0) goto L_0x00e7
            android.os.Bundle r0 = r7.mSavedFragmentState
            java.lang.String r1 = "android:target_req_state"
            int r0 = r0.getInt(r1, r13)
            r7.mTargetRequestCode = r0
        L_0x00e7:
            java.lang.Boolean r0 = r7.mSavedUserVisibleHint
            if (r0 == 0) goto L_0x00f6
            java.lang.Boolean r0 = r7.mSavedUserVisibleHint
            boolean r0 = r0.booleanValue()
            r7.mUserVisibleHint = r0
            r7.mSavedUserVisibleHint = r14
            goto L_0x0100
        L_0x00f6:
            android.os.Bundle r0 = r7.mSavedFragmentState
            java.lang.String r1 = "android:user_visible_hint"
            boolean r0 = r0.getBoolean(r1, r8)
            r7.mUserVisibleHint = r0
        L_0x0100:
            boolean r0 = r7.mUserVisibleHint
            if (r0 != 0) goto L_0x0109
            r7.mDeferStart = r8
            if (r11 <= r10) goto L_0x0109
            r11 = r10
        L_0x0109:
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            r7.mHost = r0
            androidx.fragment.app.Fragment r0 = r6.mParent
            r7.mParentFragment = r0
            androidx.fragment.app.Fragment r0 = r6.mParent
            if (r0 == 0) goto L_0x0118
            androidx.fragment.app.FragmentManagerImpl r0 = r0.mChildFragmentManager
            goto L_0x011c
        L_0x0118:
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            androidx.fragment.app.FragmentManagerImpl r0 = r0.mFragmentManager
        L_0x011c:
            r7.mFragmentManager = r0
            androidx.fragment.app.Fragment r0 = r7.mTarget
            java.lang.String r15 = " that does not belong to this FragmentManager!"
            java.lang.String r5 = " declared target fragment "
            java.lang.String r4 = "Fragment "
            if (r0 == 0) goto L_0x017d
            java.util.HashMap<java.lang.String, androidx.fragment.app.Fragment> r0 = r6.mActive
            androidx.fragment.app.Fragment r1 = r7.mTarget
            java.lang.String r1 = r1.mWho
            java.lang.Object r0 = r0.get(r1)
            androidx.fragment.app.Fragment r1 = r7.mTarget
            if (r0 != r1) goto L_0x015b
            androidx.fragment.app.Fragment r0 = r7.mTarget
            int r0 = r0.mState
            if (r0 >= r8) goto L_0x0150
            androidx.fragment.app.Fragment r1 = r7.mTarget
            r2 = 1
            r3 = 0
            r16 = 0
            r17 = 1
            r0 = r18
            r9 = r4
            r4 = r16
            r10 = r5
            r5 = r17
            r0.moveToState(r1, r2, r3, r4, r5)
            goto L_0x0152
        L_0x0150:
            r9 = r4
            r10 = r5
        L_0x0152:
            androidx.fragment.app.Fragment r0 = r7.mTarget
            java.lang.String r0 = r0.mWho
            r7.mTargetWho = r0
            r7.mTarget = r14
            goto L_0x017f
        L_0x015b:
            r9 = r4
            r10 = r5
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            r1.append(r9)
            r1.append(r7)
            r1.append(r10)
            androidx.fragment.app.Fragment r2 = r7.mTarget
            r1.append(r2)
            r1.append(r15)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L_0x017d:
            r9 = r4
            r10 = r5
        L_0x017f:
            java.lang.String r0 = r7.mTargetWho
            if (r0 == 0) goto L_0x01be
            java.util.HashMap<java.lang.String, androidx.fragment.app.Fragment> r0 = r6.mActive
            java.lang.String r1 = r7.mTargetWho
            java.lang.Object r0 = r0.get(r1)
            r1 = r0
            androidx.fragment.app.Fragment r1 = (androidx.fragment.app.Fragment) r1
            if (r1 == 0) goto L_0x019e
            int r0 = r1.mState
            if (r0 >= r8) goto L_0x01be
            r2 = 1
            r3 = 0
            r4 = 0
            r5 = 1
            r0 = r18
            r0.moveToState(r1, r2, r3, r4, r5)
            goto L_0x01be
        L_0x019e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            r1.append(r9)
            r1.append(r7)
            r1.append(r10)
            java.lang.String r2 = r7.mTargetWho
            r1.append(r2)
            r1.append(r15)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L_0x01be:
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            android.content.Context r0 = r0.getContext()
            r6.dispatchOnFragmentPreAttached(r7, r0, r13)
            r19.performAttach()
            androidx.fragment.app.Fragment r0 = r7.mParentFragment
            if (r0 != 0) goto L_0x01d4
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            r0.onAttachFragment(r7)
            goto L_0x01d9
        L_0x01d4:
            androidx.fragment.app.Fragment r0 = r7.mParentFragment
            r0.onAttachFragment(r7)
        L_0x01d9:
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            android.content.Context r0 = r0.getContext()
            r6.dispatchOnFragmentAttached(r7, r0, r13)
            boolean r0 = r7.mIsCreated
            if (r0 != 0) goto L_0x01f6
            android.os.Bundle r0 = r7.mSavedFragmentState
            r6.dispatchOnFragmentPreCreated(r7, r0, r13)
            android.os.Bundle r0 = r7.mSavedFragmentState
            r7.performCreate(r0)
            android.os.Bundle r0 = r7.mSavedFragmentState
            r6.dispatchOnFragmentCreated(r7, r0, r13)
            goto L_0x01fd
        L_0x01f6:
            android.os.Bundle r0 = r7.mSavedFragmentState
            r7.restoreChildFragmentState(r0)
            r7.mState = r8
        L_0x01fd:
            if (r11 <= 0) goto L_0x0202
            r18.ensureInflatedFragmentView(r19)
        L_0x0202:
            if (r11 <= r8) goto L_0x02f7
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x021c
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "moveto ACTIVITY_CREATED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x021c:
            boolean r0 = r7.mFromLayout
            if (r0 != 0) goto L_0x02e2
            int r0 = r7.mContainerId
            if (r0 == 0) goto L_0x0294
            int r0 = r7.mContainerId
            r1 = -1
            if (r0 != r1) goto L_0x0247
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "Cannot create fragment "
            r1.append(r2)
            r1.append(r7)
            java.lang.String r2 = " for a container view with no id"
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            r6.throwException(r0)
        L_0x0247:
            androidx.fragment.app.FragmentContainer r0 = r6.mContainer
            int r1 = r7.mContainerId
            android.view.View r0 = r0.onFindViewById(r1)
            android.view.ViewGroup r0 = (android.view.ViewGroup) r0
            if (r0 != 0) goto L_0x0295
            boolean r1 = r7.mRestored
            if (r1 != 0) goto L_0x0295
            android.content.res.Resources r1 = r19.getResources()     // Catch:{ NotFoundException -> 0x0262 }
            int r2 = r7.mContainerId     // Catch:{ NotFoundException -> 0x0262 }
            java.lang.String r1 = r1.getResourceName(r2)     // Catch:{ NotFoundException -> 0x0262 }
            goto L_0x0264
        L_0x0262:
            java.lang.String r1 = "unknown"
        L_0x0264:
            java.lang.IllegalArgumentException r2 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            r3.<init>()
            java.lang.String r4 = "No view found for id 0x"
            r3.append(r4)
            int r4 = r7.mContainerId
            java.lang.String r4 = java.lang.Integer.toHexString(r4)
            r3.append(r4)
            java.lang.String r4 = " ("
            r3.append(r4)
            r3.append(r1)
            java.lang.String r1 = ") for fragment "
            r3.append(r1)
            r3.append(r7)
            java.lang.String r1 = r3.toString()
            r2.<init>(r1)
            r6.throwException(r2)
            goto L_0x0295
        L_0x0294:
            r0 = r14
        L_0x0295:
            r7.mContainer = r0
            android.os.Bundle r1 = r7.mSavedFragmentState
            android.view.LayoutInflater r1 = r7.performGetLayoutInflater(r1)
            android.os.Bundle r2 = r7.mSavedFragmentState
            r7.performCreateView(r1, r0, r2)
            android.view.View r1 = r7.mView
            if (r1 == 0) goto L_0x02e0
            android.view.View r1 = r7.mView
            r7.mInnerView = r1
            android.view.View r1 = r7.mView
            r1.setSaveFromParentEnabled(r13)
            if (r0 == 0) goto L_0x02b6
            android.view.View r1 = r7.mView
            r0.addView(r1)
        L_0x02b6:
            boolean r0 = r7.mHidden
            if (r0 == 0) goto L_0x02c1
            android.view.View r0 = r7.mView
            r1 = 8
            r0.setVisibility(r1)
        L_0x02c1:
            android.view.View r0 = r7.mView
            android.os.Bundle r1 = r7.mSavedFragmentState
            r7.onViewCreated(r0, r1)
            android.view.View r0 = r7.mView
            android.os.Bundle r1 = r7.mSavedFragmentState
            r6.dispatchOnFragmentViewCreated(r7, r0, r1, r13)
            android.view.View r0 = r7.mView
            int r0 = r0.getVisibility()
            if (r0 != 0) goto L_0x02dc
            android.view.ViewGroup r0 = r7.mContainer
            if (r0 == 0) goto L_0x02dc
            goto L_0x02dd
        L_0x02dc:
            r8 = r13
        L_0x02dd:
            r7.mIsNewlyAdded = r8
            goto L_0x02e2
        L_0x02e0:
            r7.mInnerView = r14
        L_0x02e2:
            android.os.Bundle r0 = r7.mSavedFragmentState
            r7.performActivityCreated(r0)
            android.os.Bundle r0 = r7.mSavedFragmentState
            r6.dispatchOnFragmentActivityCreated(r7, r0, r13)
            android.view.View r0 = r7.mView
            if (r0 == 0) goto L_0x02f5
            android.os.Bundle r0 = r7.mSavedFragmentState
            r7.restoreViewState(r0)
        L_0x02f5:
            r7.mSavedFragmentState = r14
        L_0x02f7:
            r0 = 2
        L_0x02f8:
            if (r11 <= r0) goto L_0x0318
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x0312
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "moveto STARTED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x0312:
            r19.performStart()
            r6.dispatchOnFragmentStarted(r7, r13)
        L_0x0318:
            r0 = 3
        L_0x0319:
            if (r11 <= r0) goto L_0x04fe
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x0333
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "moveto RESUMED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x0333:
            r19.performResume()
            r6.dispatchOnFragmentResumed(r7, r13)
            r7.mSavedFragmentState = r14
            r7.mSavedViewState = r14
            goto L_0x04fe
        L_0x033f:
            int r0 = r7.mState
            if (r0 <= r11) goto L_0x04fe
            int r0 = r7.mState
            if (r0 == r8) goto L_0x042b
            r1 = 2
            if (r0 == r1) goto L_0x0397
            r1 = 3
            if (r0 == r1) goto L_0x0374
            r1 = 4
            if (r0 == r1) goto L_0x0352
            goto L_0x04fe
        L_0x0352:
            if (r11 >= r1) goto L_0x0372
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x036c
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "movefrom RESUMED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x036c:
            r19.performPause()
            r6.dispatchOnFragmentPaused(r7, r13)
        L_0x0372:
            r0 = 3
            goto L_0x0375
        L_0x0374:
            r0 = r1
        L_0x0375:
            if (r11 >= r0) goto L_0x0395
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x038f
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "movefrom STARTED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x038f:
            r19.performStop()
            r6.dispatchOnFragmentStopped(r7, r13)
        L_0x0395:
            r0 = 2
            goto L_0x0398
        L_0x0397:
            r0 = r1
        L_0x0398:
            if (r11 >= r0) goto L_0x042b
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x03b2
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "movefrom ACTIVITY_CREATED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x03b2:
            android.view.View r0 = r7.mView
            if (r0 == 0) goto L_0x03c5
            androidx.fragment.app.FragmentHostCallback r0 = r6.mHost
            boolean r0 = r0.onShouldSaveFragmentState(r7)
            if (r0 == 0) goto L_0x03c5
            android.util.SparseArray<android.os.Parcelable> r0 = r7.mSavedViewState
            if (r0 != 0) goto L_0x03c5
            r18.saveFragmentViewState(r19)
        L_0x03c5:
            r19.performDestroyView()
            r6.dispatchOnFragmentViewDestroyed(r7, r13)
            android.view.View r0 = r7.mView
            if (r0 == 0) goto L_0x041c
            android.view.ViewGroup r0 = r7.mContainer
            if (r0 == 0) goto L_0x041c
            android.view.ViewGroup r0 = r7.mContainer
            android.view.View r1 = r7.mView
            r0.endViewTransition(r1)
            android.view.View r0 = r7.mView
            r0.clearAnimation()
            androidx.fragment.app.Fragment r0 = r19.getParentFragment()
            if (r0 == 0) goto L_0x03ed
            androidx.fragment.app.Fragment r0 = r19.getParentFragment()
            boolean r0 = r0.mRemoving
            if (r0 != 0) goto L_0x041c
        L_0x03ed:
            int r0 = r6.mCurState
            r1 = 0
            if (r0 <= 0) goto L_0x040d
            boolean r0 = r6.mDestroyed
            if (r0 != 0) goto L_0x040d
            android.view.View r0 = r7.mView
            int r0 = r0.getVisibility()
            if (r0 != 0) goto L_0x040d
            float r0 = r7.mPostponedAlpha
            int r0 = (r0 > r1 ? 1 : (r0 == r1 ? 0 : -1))
            if (r0 < 0) goto L_0x040d
            r0 = r21
            r2 = r22
            androidx.fragment.app.FragmentManagerImpl$AnimationOrAnimator r0 = r6.loadAnimation(r7, r0, r13, r2)
            goto L_0x040e
        L_0x040d:
            r0 = r14
        L_0x040e:
            r7.mPostponedAlpha = r1
            if (r0 == 0) goto L_0x0415
            r6.animateRemoveFragment(r7, r0, r11)
        L_0x0415:
            android.view.ViewGroup r0 = r7.mContainer
            android.view.View r1 = r7.mView
            r0.removeView(r1)
        L_0x041c:
            r7.mContainer = r14
            r7.mView = r14
            r7.mViewLifecycleOwner = r14
            androidx.lifecycle.MutableLiveData<androidx.lifecycle.LifecycleOwner> r0 = r7.mViewLifecycleOwnerLiveData
            r0.setValue(r14)
            r7.mInnerView = r14
            r7.mInLayout = r13
        L_0x042b:
            if (r11 >= r8) goto L_0x04fe
            boolean r0 = r6.mDestroyed
            if (r0 == 0) goto L_0x0452
            android.view.View r0 = r19.getAnimatingAway()
            if (r0 == 0) goto L_0x0442
            android.view.View r0 = r19.getAnimatingAway()
            r7.setAnimatingAway(r14)
            r0.clearAnimation()
            goto L_0x0452
        L_0x0442:
            android.animation.Animator r0 = r19.getAnimator()
            if (r0 == 0) goto L_0x0452
            android.animation.Animator r0 = r19.getAnimator()
            r7.setAnimator(r14)
            r0.cancel()
        L_0x0452:
            android.view.View r0 = r19.getAnimatingAway()
            if (r0 != 0) goto L_0x04fa
            android.animation.Animator r0 = r19.getAnimator()
            if (r0 == 0) goto L_0x0460
            goto L_0x04fa
        L_0x0460:
            boolean r0 = DEBUG
            if (r0 == 0) goto L_0x0478
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "movefrom CREATED: "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r0 = r0.toString()
            android.util.Log.v(r12, r0)
        L_0x0478:
            boolean r0 = r7.mRemoving
            if (r0 == 0) goto L_0x0484
            boolean r0 = r19.isInBackStack()
            if (r0 != 0) goto L_0x0484
            r0 = r8
            goto L_0x0485
        L_0x0484:
            r0 = r13
        L_0x0485:
            if (r0 != 0) goto L_0x0493
            androidx.fragment.app.FragmentManagerViewModel r1 = r6.mNonConfig
            boolean r1 = r1.shouldDestroy(r7)
            if (r1 == 0) goto L_0x0490
            goto L_0x0493
        L_0x0490:
            r7.mState = r13
            goto L_0x04c4
        L_0x0493:
            androidx.fragment.app.FragmentHostCallback r1 = r6.mHost
            boolean r2 = r1 instanceof androidx.lifecycle.ViewModelStoreOwner
            if (r2 == 0) goto L_0x04a0
            androidx.fragment.app.FragmentManagerViewModel r1 = r6.mNonConfig
            boolean r8 = r1.isCleared()
            goto L_0x04b5
        L_0x04a0:
            android.content.Context r1 = r1.getContext()
            boolean r1 = r1 instanceof android.app.Activity
            if (r1 == 0) goto L_0x04b5
            androidx.fragment.app.FragmentHostCallback r1 = r6.mHost
            android.content.Context r1 = r1.getContext()
            android.app.Activity r1 = (android.app.Activity) r1
            boolean r1 = r1.isChangingConfigurations()
            r8 = r8 ^ r1
        L_0x04b5:
            if (r0 != 0) goto L_0x04b9
            if (r8 == 0) goto L_0x04be
        L_0x04b9:
            androidx.fragment.app.FragmentManagerViewModel r1 = r6.mNonConfig
            r1.clearNonConfigState(r7)
        L_0x04be:
            r19.performDestroy()
            r6.dispatchOnFragmentDestroyed(r7, r13)
        L_0x04c4:
            r19.performDetach()
            r6.dispatchOnFragmentDetached(r7, r13)
            if (r23 != 0) goto L_0x04fe
            if (r0 != 0) goto L_0x04f6
            androidx.fragment.app.FragmentManagerViewModel r0 = r6.mNonConfig
            boolean r0 = r0.shouldDestroy(r7)
            if (r0 == 0) goto L_0x04d7
            goto L_0x04f6
        L_0x04d7:
            r7.mHost = r14
            r7.mParentFragment = r14
            r7.mFragmentManager = r14
            java.lang.String r0 = r7.mTargetWho
            if (r0 == 0) goto L_0x04fe
            java.util.HashMap<java.lang.String, androidx.fragment.app.Fragment> r0 = r6.mActive
            java.lang.String r1 = r7.mTargetWho
            java.lang.Object r0 = r0.get(r1)
            androidx.fragment.app.Fragment r0 = (androidx.fragment.app.Fragment) r0
            if (r0 == 0) goto L_0x04fe
            boolean r1 = r0.getRetainInstance()
            if (r1 == 0) goto L_0x04fe
            r7.mTarget = r0
            goto L_0x04fe
        L_0x04f6:
            r18.makeInactive(r19)
            goto L_0x04fe
        L_0x04fa:
            r7.setStateAfterAnimating(r11)
            goto L_0x04ff
        L_0x04fe:
            r8 = r11
        L_0x04ff:
            int r0 = r7.mState
            if (r0 == r8) goto L_0x052b
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = "moveToState: Fragment state for "
            r0.append(r1)
            r0.append(r7)
            java.lang.String r1 = " not updated inline; expected state "
            r0.append(r1)
            r0.append(r8)
            java.lang.String r1 = " found "
            r0.append(r1)
            int r1 = r7.mState
            r0.append(r1)
            java.lang.String r0 = r0.toString()
            android.util.Log.w(r12, r0)
            r7.mState = r8
        L_0x052b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.FragmentManagerImpl.moveToState(androidx.fragment.app.Fragment, int, int, int, boolean):void");
    }

    private void animateRemoveFragment(final Fragment fragment, AnimationOrAnimator animationOrAnimator, int i) {
        final View view = fragment.mView;
        final ViewGroup viewGroup = fragment.mContainer;
        viewGroup.startViewTransition(view);
        fragment.setStateAfterAnimating(i);
        if (animationOrAnimator.animation != null) {
            EndViewTransitionAnimation endViewTransitionAnimation = new EndViewTransitionAnimation(animationOrAnimator.animation, viewGroup, view);
            fragment.setAnimatingAway(fragment.mView);
            endViewTransitionAnimation.setAnimationListener(new AnimationListener() {
                public void onAnimationRepeat(Animation animation) {
                }

                public void onAnimationStart(Animation animation) {
                }

                public void onAnimationEnd(Animation animation) {
                    viewGroup.post(new Runnable() {
                        public void run() {
                            if (fragment.getAnimatingAway() != null) {
                                fragment.setAnimatingAway(null);
                                FragmentManagerImpl.this.moveToState(fragment, fragment.getStateAfterAnimating(), 0, 0, false);
                            }
                        }
                    });
                }
            });
            fragment.mView.startAnimation(endViewTransitionAnimation);
            return;
        }
        Animator animator = animationOrAnimator.animator;
        fragment.setAnimator(animationOrAnimator.animator);
        animator.addListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animator) {
                viewGroup.endViewTransition(view);
                Animator animator2 = fragment.getAnimator();
                fragment.setAnimator(null);
                if (animator2 != null && viewGroup.indexOfChild(view) < 0) {
                    FragmentManagerImpl fragmentManagerImpl = FragmentManagerImpl.this;
                    Fragment fragment = fragment;
                    fragmentManagerImpl.moveToState(fragment, fragment.getStateAfterAnimating(), 0, 0, false);
                }
            }
        });
        animator.setTarget(fragment.mView);
        animator.start();
    }

    /* access modifiers changed from: 0000 */
    public void moveToState(Fragment fragment) {
        moveToState(fragment, this.mCurState, 0, 0, false);
    }

    /* access modifiers changed from: 0000 */
    public void ensureInflatedFragmentView(Fragment fragment) {
        if (fragment.mFromLayout && !fragment.mPerformedCreateView) {
            fragment.performCreateView(fragment.performGetLayoutInflater(fragment.mSavedFragmentState), null, fragment.mSavedFragmentState);
            if (fragment.mView != null) {
                fragment.mInnerView = fragment.mView;
                fragment.mView.setSaveFromParentEnabled(false);
                if (fragment.mHidden) {
                    fragment.mView.setVisibility(8);
                }
                fragment.onViewCreated(fragment.mView, fragment.mSavedFragmentState);
                dispatchOnFragmentViewCreated(fragment, fragment.mView, fragment.mSavedFragmentState, false);
                return;
            }
            fragment.mInnerView = null;
        }
    }

    /* access modifiers changed from: 0000 */
    public void completeShowHideFragment(final Fragment fragment) {
        if (fragment.mView != null) {
            AnimationOrAnimator loadAnimation = loadAnimation(fragment, fragment.getNextTransition(), !fragment.mHidden, fragment.getNextTransitionStyle());
            if (loadAnimation == null || loadAnimation.animator == null) {
                if (loadAnimation != null) {
                    fragment.mView.startAnimation(loadAnimation.animation);
                    loadAnimation.animation.start();
                }
                fragment.mView.setVisibility((!fragment.mHidden || fragment.isHideReplaced()) ? 0 : 8);
                if (fragment.isHideReplaced()) {
                    fragment.setHideReplaced(false);
                }
            } else {
                loadAnimation.animator.setTarget(fragment.mView);
                if (!fragment.mHidden) {
                    fragment.mView.setVisibility(0);
                } else if (fragment.isHideReplaced()) {
                    fragment.setHideReplaced(false);
                } else {
                    final ViewGroup viewGroup = fragment.mContainer;
                    final View view = fragment.mView;
                    viewGroup.startViewTransition(view);
                    loadAnimation.animator.addListener(new AnimatorListenerAdapter() {
                        public void onAnimationEnd(Animator animator) {
                            viewGroup.endViewTransition(view);
                            animator.removeListener(this);
                            if (fragment.mView != null && fragment.mHidden) {
                                fragment.mView.setVisibility(8);
                            }
                        }
                    });
                }
                loadAnimation.animator.start();
            }
        }
        if (fragment.mAdded && isMenuAvailable(fragment)) {
            this.mNeedMenuInvalidate = true;
        }
        fragment.mHiddenChanged = false;
        fragment.onHiddenChanged(fragment.mHidden);
    }

    /* access modifiers changed from: 0000 */
    public void moveFragmentToExpectedState(Fragment fragment) {
        if (fragment != null) {
            if (!this.mActive.containsKey(fragment.mWho)) {
                if (DEBUG) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Ignoring moving ");
                    sb.append(fragment);
                    sb.append(" to state ");
                    sb.append(this.mCurState);
                    sb.append("since it is not added to ");
                    sb.append(this);
                    Log.v(TAG, sb.toString());
                }
                return;
            }
            int i = this.mCurState;
            if (fragment.mRemoving) {
                if (fragment.isInBackStack()) {
                    i = Math.min(i, 1);
                } else {
                    i = Math.min(i, 0);
                }
            }
            moveToState(fragment, i, fragment.getNextTransition(), fragment.getNextTransitionStyle(), false);
            if (fragment.mView != null) {
                Fragment findFragmentUnder = findFragmentUnder(fragment);
                if (findFragmentUnder != null) {
                    View view = findFragmentUnder.mView;
                    ViewGroup viewGroup = fragment.mContainer;
                    int indexOfChild = viewGroup.indexOfChild(view);
                    int indexOfChild2 = viewGroup.indexOfChild(fragment.mView);
                    if (indexOfChild2 < indexOfChild) {
                        viewGroup.removeViewAt(indexOfChild2);
                        viewGroup.addView(fragment.mView, indexOfChild);
                    }
                }
                if (fragment.mIsNewlyAdded && fragment.mContainer != null) {
                    if (fragment.mPostponedAlpha > 0.0f) {
                        fragment.mView.setAlpha(fragment.mPostponedAlpha);
                    }
                    fragment.mPostponedAlpha = 0.0f;
                    fragment.mIsNewlyAdded = false;
                    AnimationOrAnimator loadAnimation = loadAnimation(fragment, fragment.getNextTransition(), true, fragment.getNextTransitionStyle());
                    if (loadAnimation != null) {
                        if (loadAnimation.animation != null) {
                            fragment.mView.startAnimation(loadAnimation.animation);
                        } else {
                            loadAnimation.animator.setTarget(fragment.mView);
                            loadAnimation.animator.start();
                        }
                    }
                }
            }
            if (fragment.mHiddenChanged) {
                completeShowHideFragment(fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void moveToState(int i, boolean z) {
        if (this.mHost == null && i != 0) {
            throw new IllegalStateException("No activity");
        } else if (z || i != this.mCurState) {
            this.mCurState = i;
            int size = this.mAdded.size();
            for (int i2 = 0; i2 < size; i2++) {
                moveFragmentToExpectedState((Fragment) this.mAdded.get(i2));
            }
            for (Fragment fragment : this.mActive.values()) {
                if (fragment != null && ((fragment.mRemoving || fragment.mDetached) && !fragment.mIsNewlyAdded)) {
                    moveFragmentToExpectedState(fragment);
                }
            }
            startPendingDeferredFragments();
            if (this.mNeedMenuInvalidate) {
                FragmentHostCallback fragmentHostCallback = this.mHost;
                if (fragmentHostCallback != null && this.mCurState == 4) {
                    fragmentHostCallback.onSupportInvalidateOptionsMenu();
                    this.mNeedMenuInvalidate = false;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void startPendingDeferredFragments() {
        for (Fragment fragment : this.mActive.values()) {
            if (fragment != null) {
                performPendingDeferredStart(fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void makeActive(Fragment fragment) {
        if (this.mActive.get(fragment.mWho) == null) {
            this.mActive.put(fragment.mWho, fragment);
            if (fragment.mRetainInstanceChangedWhileDetached) {
                if (fragment.mRetainInstance) {
                    addRetainedFragment(fragment);
                } else {
                    removeRetainedFragment(fragment);
                }
                fragment.mRetainInstanceChangedWhileDetached = false;
            }
            if (DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("Added fragment to active set ");
                sb.append(fragment);
                Log.v(TAG, sb.toString());
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void makeInactive(Fragment fragment) {
        if (this.mActive.get(fragment.mWho) != null) {
            if (DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("Removed fragment from active set ");
                sb.append(fragment);
                Log.v(TAG, sb.toString());
            }
            for (Fragment fragment2 : this.mActive.values()) {
                if (fragment2 != null && fragment.mWho.equals(fragment2.mTargetWho)) {
                    fragment2.mTarget = fragment;
                    fragment2.mTargetWho = null;
                }
            }
            this.mActive.put(fragment.mWho, null);
            removeRetainedFragment(fragment);
            if (fragment.mTargetWho != null) {
                fragment.mTarget = (Fragment) this.mActive.get(fragment.mTargetWho);
            }
            fragment.initState();
        }
    }

    public void addFragment(Fragment fragment, boolean z) {
        if (DEBUG) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("add: ");
            sb.append(fragment);
            Log.v(str, sb.toString());
        }
        makeActive(fragment);
        if (fragment.mDetached) {
            return;
        }
        if (!this.mAdded.contains(fragment)) {
            synchronized (this.mAdded) {
                this.mAdded.add(fragment);
            }
            fragment.mAdded = true;
            fragment.mRemoving = false;
            if (fragment.mView == null) {
                fragment.mHiddenChanged = false;
            }
            if (isMenuAvailable(fragment)) {
                this.mNeedMenuInvalidate = true;
            }
            if (z) {
                moveToState(fragment);
                return;
            }
            return;
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append("Fragment already added: ");
        sb2.append(fragment);
        throw new IllegalStateException(sb2.toString());
    }

    public void removeFragment(Fragment fragment) {
        if (DEBUG) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("remove: ");
            sb.append(fragment);
            sb.append(" nesting=");
            sb.append(fragment.mBackStackNesting);
            Log.v(str, sb.toString());
        }
        boolean z = !fragment.isInBackStack();
        if (!fragment.mDetached || z) {
            synchronized (this.mAdded) {
                this.mAdded.remove(fragment);
            }
            if (isMenuAvailable(fragment)) {
                this.mNeedMenuInvalidate = true;
            }
            fragment.mAdded = false;
            fragment.mRemoving = true;
        }
    }

    public void hideFragment(Fragment fragment) {
        if (DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("hide: ");
            sb.append(fragment);
            Log.v(TAG, sb.toString());
        }
        if (!fragment.mHidden) {
            fragment.mHidden = true;
            fragment.mHiddenChanged = true ^ fragment.mHiddenChanged;
        }
    }

    public void showFragment(Fragment fragment) {
        if (DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("show: ");
            sb.append(fragment);
            Log.v(TAG, sb.toString());
        }
        if (fragment.mHidden) {
            fragment.mHidden = false;
            fragment.mHiddenChanged = !fragment.mHiddenChanged;
        }
    }

    public void detachFragment(Fragment fragment) {
        if (DEBUG) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("detach: ");
            sb.append(fragment);
            Log.v(str, sb.toString());
        }
        if (!fragment.mDetached) {
            fragment.mDetached = true;
            if (fragment.mAdded) {
                if (DEBUG) {
                    String str2 = TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("remove from detach: ");
                    sb2.append(fragment);
                    Log.v(str2, sb2.toString());
                }
                synchronized (this.mAdded) {
                    this.mAdded.remove(fragment);
                }
                if (isMenuAvailable(fragment)) {
                    this.mNeedMenuInvalidate = true;
                }
                fragment.mAdded = false;
            }
        }
    }

    public void attachFragment(Fragment fragment) {
        if (DEBUG) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("attach: ");
            sb.append(fragment);
            Log.v(str, sb.toString());
        }
        if (fragment.mDetached) {
            fragment.mDetached = false;
            if (fragment.mAdded) {
                return;
            }
            if (!this.mAdded.contains(fragment)) {
                if (DEBUG) {
                    String str2 = TAG;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("add from attach: ");
                    sb2.append(fragment);
                    Log.v(str2, sb2.toString());
                }
                synchronized (this.mAdded) {
                    this.mAdded.add(fragment);
                }
                fragment.mAdded = true;
                if (isMenuAvailable(fragment)) {
                    this.mNeedMenuInvalidate = true;
                    return;
                }
                return;
            }
            StringBuilder sb3 = new StringBuilder();
            sb3.append("Fragment already added: ");
            sb3.append(fragment);
            throw new IllegalStateException(sb3.toString());
        }
    }

    public Fragment findFragmentById(int i) {
        for (int size = this.mAdded.size() - 1; size >= 0; size--) {
            Fragment fragment = (Fragment) this.mAdded.get(size);
            if (fragment != null && fragment.mFragmentId == i) {
                return fragment;
            }
        }
        for (Fragment fragment2 : this.mActive.values()) {
            if (fragment2 != null && fragment2.mFragmentId == i) {
                return fragment2;
            }
        }
        return null;
    }

    public Fragment findFragmentByTag(String str) {
        if (str != null) {
            for (int size = this.mAdded.size() - 1; size >= 0; size--) {
                Fragment fragment = (Fragment) this.mAdded.get(size);
                if (fragment != null && str.equals(fragment.mTag)) {
                    return fragment;
                }
            }
        }
        if (str != null) {
            for (Fragment fragment2 : this.mActive.values()) {
                if (fragment2 != null && str.equals(fragment2.mTag)) {
                    return fragment2;
                }
            }
        }
        return null;
    }

    public Fragment findFragmentByWho(String str) {
        for (Fragment fragment : this.mActive.values()) {
            if (fragment != null) {
                Fragment findFragmentByWho = fragment.findFragmentByWho(str);
                if (findFragmentByWho != null) {
                    return findFragmentByWho;
                }
            }
        }
        return null;
    }

    private void checkStateLoss() {
        if (isStateSaved()) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
    }

    public boolean isStateSaved() {
        return this.mStateSaved || this.mStopped;
    }

    public void enqueueAction(OpGenerator opGenerator, boolean z) {
        if (!z) {
            checkStateLoss();
        }
        synchronized (this) {
            if (!this.mDestroyed) {
                if (this.mHost != null) {
                    if (this.mPendingActions == null) {
                        this.mPendingActions = new ArrayList<>();
                    }
                    this.mPendingActions.add(opGenerator);
                    scheduleCommit();
                    return;
                }
            }
            if (!z) {
                throw new IllegalStateException("Activity has been destroyed");
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void scheduleCommit() {
        synchronized (this) {
            boolean z = false;
            boolean z2 = this.mPostponedTransactions != null && !this.mPostponedTransactions.isEmpty();
            if (this.mPendingActions != null && this.mPendingActions.size() == 1) {
                z = true;
            }
            if (z2 || z) {
                this.mHost.getHandler().removeCallbacks(this.mExecCommit);
                this.mHost.getHandler().post(this.mExecCommit);
                updateOnBackPressedCallbackEnabled();
            }
        }
    }

    public int allocBackStackIndex(BackStackRecord backStackRecord) {
        synchronized (this) {
            if (this.mAvailBackStackIndices != null) {
                if (this.mAvailBackStackIndices.size() > 0) {
                    int intValue = ((Integer) this.mAvailBackStackIndices.remove(this.mAvailBackStackIndices.size() - 1)).intValue();
                    if (DEBUG) {
                        String str = TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("Adding back stack index ");
                        sb.append(intValue);
                        sb.append(" with ");
                        sb.append(backStackRecord);
                        Log.v(str, sb.toString());
                    }
                    this.mBackStackIndices.set(intValue, backStackRecord);
                    return intValue;
                }
            }
            if (this.mBackStackIndices == null) {
                this.mBackStackIndices = new ArrayList<>();
            }
            int size = this.mBackStackIndices.size();
            if (DEBUG) {
                String str2 = TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Setting back stack index ");
                sb2.append(size);
                sb2.append(" to ");
                sb2.append(backStackRecord);
                Log.v(str2, sb2.toString());
            }
            this.mBackStackIndices.add(backStackRecord);
            return size;
        }
    }

    public void setBackStackIndex(int i, BackStackRecord backStackRecord) {
        synchronized (this) {
            if (this.mBackStackIndices == null) {
                this.mBackStackIndices = new ArrayList<>();
            }
            int size = this.mBackStackIndices.size();
            if (i < size) {
                if (DEBUG) {
                    String str = TAG;
                    StringBuilder sb = new StringBuilder();
                    sb.append("Setting back stack index ");
                    sb.append(i);
                    sb.append(" to ");
                    sb.append(backStackRecord);
                    Log.v(str, sb.toString());
                }
                this.mBackStackIndices.set(i, backStackRecord);
            } else {
                while (size < i) {
                    this.mBackStackIndices.add(null);
                    if (this.mAvailBackStackIndices == null) {
                        this.mAvailBackStackIndices = new ArrayList<>();
                    }
                    if (DEBUG) {
                        String str2 = TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("Adding available back stack index ");
                        sb2.append(size);
                        Log.v(str2, sb2.toString());
                    }
                    this.mAvailBackStackIndices.add(Integer.valueOf(size));
                    size++;
                }
                if (DEBUG) {
                    String str3 = TAG;
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Adding back stack index ");
                    sb3.append(i);
                    sb3.append(" with ");
                    sb3.append(backStackRecord);
                    Log.v(str3, sb3.toString());
                }
                this.mBackStackIndices.add(backStackRecord);
            }
        }
    }

    public void freeBackStackIndex(int i) {
        synchronized (this) {
            this.mBackStackIndices.set(i, null);
            if (this.mAvailBackStackIndices == null) {
                this.mAvailBackStackIndices = new ArrayList<>();
            }
            if (DEBUG) {
                String str = TAG;
                StringBuilder sb = new StringBuilder();
                sb.append("Freeing back stack index ");
                sb.append(i);
                Log.v(str, sb.toString());
            }
            this.mAvailBackStackIndices.add(Integer.valueOf(i));
        }
    }

    private void ensureExecReady(boolean z) {
        if (this.mExecutingActions) {
            throw new IllegalStateException("FragmentManager is already executing transactions");
        } else if (this.mHost == null) {
            throw new IllegalStateException("Fragment host has been destroyed");
        } else if (Looper.myLooper() == this.mHost.getHandler().getLooper()) {
            if (!z) {
                checkStateLoss();
            }
            if (this.mTmpRecords == null) {
                this.mTmpRecords = new ArrayList<>();
                this.mTmpIsPop = new ArrayList<>();
            }
            this.mExecutingActions = true;
            try {
                executePostponedTransaction(null, null);
            } finally {
                this.mExecutingActions = false;
            }
        } else {
            throw new IllegalStateException("Must be called from main thread of fragment host");
        }
    }

    public void execSingleAction(OpGenerator opGenerator, boolean z) {
        if (!z || (this.mHost != null && !this.mDestroyed)) {
            ensureExecReady(z);
            if (opGenerator.generateOps(this.mTmpRecords, this.mTmpIsPop)) {
                this.mExecutingActions = true;
                try {
                    removeRedundantOperationsAndExecute(this.mTmpRecords, this.mTmpIsPop);
                } finally {
                    cleanupExec();
                }
            }
            updateOnBackPressedCallbackEnabled();
            doPendingDeferredStart();
            burpActive();
        }
    }

    private void cleanupExec() {
        this.mExecutingActions = false;
        this.mTmpIsPop.clear();
        this.mTmpRecords.clear();
    }

    /* JADX INFO: finally extract failed */
    public boolean execPendingActions() {
        ensureExecReady(true);
        boolean z = false;
        while (generateOpsForPendingActions(this.mTmpRecords, this.mTmpIsPop)) {
            this.mExecutingActions = true;
            try {
                removeRedundantOperationsAndExecute(this.mTmpRecords, this.mTmpIsPop);
                cleanupExec();
                z = true;
            } catch (Throwable th) {
                cleanupExec();
                throw th;
            }
        }
        updateOnBackPressedCallbackEnabled();
        doPendingDeferredStart();
        burpActive();
        return z;
    }

    private void executePostponedTransaction(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2) {
        ArrayList<StartEnterTransitionListener> arrayList3 = this.mPostponedTransactions;
        int size = arrayList3 == null ? 0 : arrayList3.size();
        int i = 0;
        while (i < size) {
            StartEnterTransitionListener startEnterTransitionListener = (StartEnterTransitionListener) this.mPostponedTransactions.get(i);
            if (arrayList != null && !startEnterTransitionListener.mIsBack) {
                int indexOf = arrayList.indexOf(startEnterTransitionListener.mRecord);
                if (indexOf != -1 && ((Boolean) arrayList2.get(indexOf)).booleanValue()) {
                    this.mPostponedTransactions.remove(i);
                    i--;
                    size--;
                    startEnterTransitionListener.cancelTransaction();
                    i++;
                }
            }
            if (startEnterTransitionListener.isReady() || (arrayList != null && startEnterTransitionListener.mRecord.interactsWith(arrayList, 0, arrayList.size()))) {
                this.mPostponedTransactions.remove(i);
                i--;
                size--;
                if (arrayList != null && !startEnterTransitionListener.mIsBack) {
                    int indexOf2 = arrayList.indexOf(startEnterTransitionListener.mRecord);
                    if (indexOf2 != -1 && ((Boolean) arrayList2.get(indexOf2)).booleanValue()) {
                        startEnterTransitionListener.cancelTransaction();
                    }
                }
                startEnterTransitionListener.completeTransaction();
            }
            i++;
        }
    }

    private void removeRedundantOperationsAndExecute(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2) {
        if (arrayList != null && !arrayList.isEmpty()) {
            if (arrayList2 == null || arrayList.size() != arrayList2.size()) {
                throw new IllegalStateException("Internal error with the back stack records");
            }
            executePostponedTransaction(arrayList, arrayList2);
            int size = arrayList.size();
            int i = 0;
            int i2 = 0;
            while (i < size) {
                if (!((BackStackRecord) arrayList.get(i)).mReorderingAllowed) {
                    if (i2 != i) {
                        executeOpsTogether(arrayList, arrayList2, i2, i);
                    }
                    i2 = i + 1;
                    if (((Boolean) arrayList2.get(i)).booleanValue()) {
                        while (i2 < size && ((Boolean) arrayList2.get(i2)).booleanValue() && !((BackStackRecord) arrayList.get(i2)).mReorderingAllowed) {
                            i2++;
                        }
                    }
                    executeOpsTogether(arrayList, arrayList2, i, i2);
                    i = i2 - 1;
                }
                i++;
            }
            if (i2 != size) {
                executeOpsTogether(arrayList, arrayList2, i2, size);
            }
        }
    }

    private void executeOpsTogether(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2, int i, int i2) {
        int i3;
        ArrayList<BackStackRecord> arrayList3 = arrayList;
        ArrayList<Boolean> arrayList4 = arrayList2;
        int i4 = i;
        int i5 = i2;
        boolean z = ((BackStackRecord) arrayList3.get(i4)).mReorderingAllowed;
        ArrayList<Fragment> arrayList5 = this.mTmpAddedFragments;
        if (arrayList5 == null) {
            this.mTmpAddedFragments = new ArrayList<>();
        } else {
            arrayList5.clear();
        }
        this.mTmpAddedFragments.addAll(this.mAdded);
        Fragment primaryNavigationFragment = getPrimaryNavigationFragment();
        boolean z2 = false;
        for (int i6 = i4; i6 < i5; i6++) {
            BackStackRecord backStackRecord = (BackStackRecord) arrayList3.get(i6);
            if (!((Boolean) arrayList4.get(i6)).booleanValue()) {
                primaryNavigationFragment = backStackRecord.expandOps(this.mTmpAddedFragments, primaryNavigationFragment);
            } else {
                primaryNavigationFragment = backStackRecord.trackAddedFragmentsInPop(this.mTmpAddedFragments, primaryNavigationFragment);
            }
            z2 = z2 || backStackRecord.mAddToBackStack;
        }
        this.mTmpAddedFragments.clear();
        if (!z) {
            FragmentTransition.startTransitions(this, arrayList, arrayList2, i, i2, false);
        }
        executeOps(arrayList, arrayList2, i, i2);
        if (z) {
            ArraySet arraySet = new ArraySet();
            addAddedFragments(arraySet);
            int postponePostponableTransactions = postponePostponableTransactions(arrayList, arrayList2, i, i2, arraySet);
            makeRemovedFragmentsInvisible(arraySet);
            i3 = postponePostponableTransactions;
        } else {
            i3 = i5;
        }
        if (i3 != i4 && z) {
            FragmentTransition.startTransitions(this, arrayList, arrayList2, i, i3, true);
            moveToState(this.mCurState, true);
        }
        while (i4 < i5) {
            BackStackRecord backStackRecord2 = (BackStackRecord) arrayList3.get(i4);
            if (((Boolean) arrayList4.get(i4)).booleanValue() && backStackRecord2.mIndex >= 0) {
                freeBackStackIndex(backStackRecord2.mIndex);
                backStackRecord2.mIndex = -1;
            }
            backStackRecord2.runOnCommitRunnables();
            i4++;
        }
        if (z2) {
            reportBackStackChanged();
        }
    }

    private void makeRemovedFragmentsInvisible(ArraySet<Fragment> arraySet) {
        int size = arraySet.size();
        for (int i = 0; i < size; i++) {
            Fragment fragment = (Fragment) arraySet.valueAt(i);
            if (!fragment.mAdded) {
                View requireView = fragment.requireView();
                fragment.mPostponedAlpha = requireView.getAlpha();
                requireView.setAlpha(0.0f);
            }
        }
    }

    private int postponePostponableTransactions(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2, int i, int i2, ArraySet<Fragment> arraySet) {
        int i3 = i2;
        for (int i4 = i2 - 1; i4 >= i; i4--) {
            BackStackRecord backStackRecord = (BackStackRecord) arrayList.get(i4);
            boolean booleanValue = ((Boolean) arrayList2.get(i4)).booleanValue();
            if (backStackRecord.isPostponed() && !backStackRecord.interactsWith(arrayList, i4 + 1, i2)) {
                if (this.mPostponedTransactions == null) {
                    this.mPostponedTransactions = new ArrayList<>();
                }
                StartEnterTransitionListener startEnterTransitionListener = new StartEnterTransitionListener(backStackRecord, booleanValue);
                this.mPostponedTransactions.add(startEnterTransitionListener);
                backStackRecord.setOnStartPostponedListener(startEnterTransitionListener);
                if (booleanValue) {
                    backStackRecord.executeOps();
                } else {
                    backStackRecord.executePopOps(false);
                }
                i3--;
                if (i4 != i3) {
                    arrayList.remove(i4);
                    arrayList.add(i3, backStackRecord);
                }
                addAddedFragments(arraySet);
            }
        }
        return i3;
    }

    /* access modifiers changed from: 0000 */
    public void completeExecute(BackStackRecord backStackRecord, boolean z, boolean z2, boolean z3) {
        if (z) {
            backStackRecord.executePopOps(z3);
        } else {
            backStackRecord.executeOps();
        }
        ArrayList arrayList = new ArrayList(1);
        ArrayList arrayList2 = new ArrayList(1);
        arrayList.add(backStackRecord);
        arrayList2.add(Boolean.valueOf(z));
        if (z2) {
            FragmentTransition.startTransitions(this, arrayList, arrayList2, 0, 1, true);
        }
        if (z3) {
            moveToState(this.mCurState, true);
        }
        for (Fragment fragment : this.mActive.values()) {
            if (fragment != null && fragment.mView != null && fragment.mIsNewlyAdded && backStackRecord.interactsWith(fragment.mContainerId)) {
                if (fragment.mPostponedAlpha > 0.0f) {
                    fragment.mView.setAlpha(fragment.mPostponedAlpha);
                }
                if (z3) {
                    fragment.mPostponedAlpha = 0.0f;
                } else {
                    fragment.mPostponedAlpha = -1.0f;
                    fragment.mIsNewlyAdded = false;
                }
            }
        }
    }

    private Fragment findFragmentUnder(Fragment fragment) {
        ViewGroup viewGroup = fragment.mContainer;
        View view = fragment.mView;
        if (!(viewGroup == null || view == null)) {
            for (int indexOf = this.mAdded.indexOf(fragment) - 1; indexOf >= 0; indexOf--) {
                Fragment fragment2 = (Fragment) this.mAdded.get(indexOf);
                if (fragment2.mContainer == viewGroup && fragment2.mView != null) {
                    return fragment2;
                }
            }
        }
        return null;
    }

    private static void executeOps(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2, int i, int i2) {
        while (i < i2) {
            BackStackRecord backStackRecord = (BackStackRecord) arrayList.get(i);
            boolean z = true;
            if (((Boolean) arrayList2.get(i)).booleanValue()) {
                backStackRecord.bumpBackStackNesting(-1);
                if (i != i2 - 1) {
                    z = false;
                }
                backStackRecord.executePopOps(z);
            } else {
                backStackRecord.bumpBackStackNesting(1);
                backStackRecord.executeOps();
            }
            i++;
        }
    }

    private void addAddedFragments(ArraySet<Fragment> arraySet) {
        int i = this.mCurState;
        if (i >= 1) {
            int min = Math.min(i, 3);
            int size = this.mAdded.size();
            for (int i2 = 0; i2 < size; i2++) {
                Fragment fragment = (Fragment) this.mAdded.get(i2);
                if (fragment.mState < min) {
                    moveToState(fragment, min, fragment.getNextAnim(), fragment.getNextTransition(), false);
                    if (fragment.mView != null && !fragment.mHidden && fragment.mIsNewlyAdded) {
                        arraySet.add(fragment);
                    }
                }
            }
        }
    }

    private void forcePostponedTransactions() {
        if (this.mPostponedTransactions != null) {
            while (!this.mPostponedTransactions.isEmpty()) {
                ((StartEnterTransitionListener) this.mPostponedTransactions.remove(0)).completeTransaction();
            }
        }
    }

    private void endAnimatingAwayFragments() {
        for (Fragment fragment : this.mActive.values()) {
            if (fragment != null) {
                if (fragment.getAnimatingAway() != null) {
                    int stateAfterAnimating = fragment.getStateAfterAnimating();
                    View animatingAway = fragment.getAnimatingAway();
                    Animation animation = animatingAway.getAnimation();
                    if (animation != null) {
                        animation.cancel();
                        animatingAway.clearAnimation();
                    }
                    fragment.setAnimatingAway(null);
                    moveToState(fragment, stateAfterAnimating, 0, 0, false);
                } else if (fragment.getAnimator() != null) {
                    fragment.getAnimator().end();
                }
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:14:0x003b, code lost:
        return false;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private boolean generateOpsForPendingActions(java.util.ArrayList<androidx.fragment.app.BackStackRecord> r5, java.util.ArrayList<java.lang.Boolean> r6) {
        /*
            r4 = this;
            monitor-enter(r4)
            java.util.ArrayList<androidx.fragment.app.FragmentManagerImpl$OpGenerator> r0 = r4.mPendingActions     // Catch:{ all -> 0x003c }
            r1 = 0
            if (r0 == 0) goto L_0x003a
            java.util.ArrayList<androidx.fragment.app.FragmentManagerImpl$OpGenerator> r0 = r4.mPendingActions     // Catch:{ all -> 0x003c }
            int r0 = r0.size()     // Catch:{ all -> 0x003c }
            if (r0 != 0) goto L_0x000f
            goto L_0x003a
        L_0x000f:
            java.util.ArrayList<androidx.fragment.app.FragmentManagerImpl$OpGenerator> r0 = r4.mPendingActions     // Catch:{ all -> 0x003c }
            int r0 = r0.size()     // Catch:{ all -> 0x003c }
            r2 = r1
        L_0x0016:
            if (r1 >= r0) goto L_0x0028
            java.util.ArrayList<androidx.fragment.app.FragmentManagerImpl$OpGenerator> r3 = r4.mPendingActions     // Catch:{ all -> 0x003c }
            java.lang.Object r3 = r3.get(r1)     // Catch:{ all -> 0x003c }
            androidx.fragment.app.FragmentManagerImpl$OpGenerator r3 = (androidx.fragment.app.FragmentManagerImpl.OpGenerator) r3     // Catch:{ all -> 0x003c }
            boolean r3 = r3.generateOps(r5, r6)     // Catch:{ all -> 0x003c }
            r2 = r2 | r3
            int r1 = r1 + 1
            goto L_0x0016
        L_0x0028:
            java.util.ArrayList<androidx.fragment.app.FragmentManagerImpl$OpGenerator> r5 = r4.mPendingActions     // Catch:{ all -> 0x003c }
            r5.clear()     // Catch:{ all -> 0x003c }
            androidx.fragment.app.FragmentHostCallback r5 = r4.mHost     // Catch:{ all -> 0x003c }
            android.os.Handler r5 = r5.getHandler()     // Catch:{ all -> 0x003c }
            java.lang.Runnable r6 = r4.mExecCommit     // Catch:{ all -> 0x003c }
            r5.removeCallbacks(r6)     // Catch:{ all -> 0x003c }
            monitor-exit(r4)     // Catch:{ all -> 0x003c }
            return r2
        L_0x003a:
            monitor-exit(r4)     // Catch:{ all -> 0x003c }
            return r1
        L_0x003c:
            r5 = move-exception
            monitor-exit(r4)     // Catch:{ all -> 0x003c }
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.FragmentManagerImpl.generateOpsForPendingActions(java.util.ArrayList, java.util.ArrayList):boolean");
    }

    /* access modifiers changed from: 0000 */
    public void doPendingDeferredStart() {
        if (this.mHavePendingDeferredStart) {
            this.mHavePendingDeferredStart = false;
            startPendingDeferredFragments();
        }
    }

    /* access modifiers changed from: 0000 */
    public void reportBackStackChanged() {
        if (this.mBackStackChangeListeners != null) {
            for (int i = 0; i < this.mBackStackChangeListeners.size(); i++) {
                ((OnBackStackChangedListener) this.mBackStackChangeListeners.get(i)).onBackStackChanged();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void addBackStackState(BackStackRecord backStackRecord) {
        if (this.mBackStack == null) {
            this.mBackStack = new ArrayList<>();
        }
        this.mBackStack.add(backStackRecord);
    }

    /* access modifiers changed from: 0000 */
    public boolean popBackStackState(ArrayList<BackStackRecord> arrayList, ArrayList<Boolean> arrayList2, String str, int i, int i2) {
        int i3;
        ArrayList<BackStackRecord> arrayList3 = this.mBackStack;
        if (arrayList3 == null) {
            return false;
        }
        if (str == null && i < 0 && (i2 & 1) == 0) {
            int size = arrayList3.size() - 1;
            if (size < 0) {
                return false;
            }
            arrayList.add(this.mBackStack.remove(size));
            arrayList2.add(Boolean.valueOf(true));
        } else {
            if (str != null || i >= 0) {
                int size2 = this.mBackStack.size() - 1;
                while (size2 >= 0) {
                    BackStackRecord backStackRecord = (BackStackRecord) this.mBackStack.get(size2);
                    if ((str != null && str.equals(backStackRecord.getName())) || (i >= 0 && i == backStackRecord.mIndex)) {
                        break;
                    }
                    size2--;
                }
                if (size2 < 0) {
                    return false;
                }
                if ((i2 & 1) != 0) {
                    while (true) {
                        size2--;
                        if (size2 < 0) {
                            break;
                        }
                        BackStackRecord backStackRecord2 = (BackStackRecord) this.mBackStack.get(size2);
                        if ((str == null || !str.equals(backStackRecord2.getName())) && (i < 0 || i != backStackRecord2.mIndex)) {
                            break;
                        }
                    }
                }
                i3 = size2;
            } else {
                i3 = -1;
            }
            if (i3 == this.mBackStack.size() - 1) {
                return false;
            }
            for (int size3 = this.mBackStack.size() - 1; size3 > i3; size3--) {
                arrayList.add(this.mBackStack.remove(size3));
                arrayList2.add(Boolean.valueOf(true));
            }
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    @Deprecated
    public FragmentManagerNonConfig retainNonConfig() {
        if (this.mHost instanceof ViewModelStoreOwner) {
            throwException(new IllegalStateException("You cannot use retainNonConfig when your FragmentHostCallback implements ViewModelStoreOwner."));
        }
        return this.mNonConfig.getSnapshot();
    }

    /* access modifiers changed from: 0000 */
    public void saveFragmentViewState(Fragment fragment) {
        if (fragment.mInnerView != null) {
            SparseArray<Parcelable> sparseArray = this.mStateArray;
            if (sparseArray == null) {
                this.mStateArray = new SparseArray<>();
            } else {
                sparseArray.clear();
            }
            fragment.mInnerView.saveHierarchyState(this.mStateArray);
            if (this.mStateArray.size() > 0) {
                fragment.mSavedViewState = this.mStateArray;
                this.mStateArray = null;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public Bundle saveFragmentBasicState(Fragment fragment) {
        if (this.mStateBundle == null) {
            this.mStateBundle = new Bundle();
        }
        fragment.performSaveInstanceState(this.mStateBundle);
        dispatchOnFragmentSaveInstanceState(fragment, this.mStateBundle, false);
        Bundle bundle = null;
        if (!this.mStateBundle.isEmpty()) {
            Bundle bundle2 = this.mStateBundle;
            this.mStateBundle = null;
            bundle = bundle2;
        }
        if (fragment.mView != null) {
            saveFragmentViewState(fragment);
        }
        if (fragment.mSavedViewState != null) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putSparseParcelableArray(VIEW_STATE_TAG, fragment.mSavedViewState);
        }
        if (!fragment.mUserVisibleHint) {
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putBoolean(USER_VISIBLE_HINT_TAG, fragment.mUserVisibleHint);
        }
        return bundle;
    }

    /* access modifiers changed from: 0000 */
    public Parcelable saveAllState() {
        String str;
        String str2;
        String str3;
        String str4;
        ArrayList<String> arrayList;
        forcePostponedTransactions();
        endAnimatingAwayFragments();
        execPendingActions();
        this.mStateSaved = true;
        BackStackState[] backStackStateArr = null;
        if (this.mActive.isEmpty()) {
            return null;
        }
        ArrayList<FragmentState> arrayList2 = new ArrayList<>(this.mActive.size());
        Iterator it = this.mActive.values().iterator();
        boolean z = false;
        while (true) {
            boolean hasNext = it.hasNext();
            str = ": ";
            str2 = " was removed from the FragmentManager";
            str3 = "Failure saving state: active ";
            str4 = TAG;
            if (!hasNext) {
                break;
            }
            Fragment fragment = (Fragment) it.next();
            if (fragment != null) {
                if (fragment.mFragmentManager != this) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(str3);
                    sb.append(fragment);
                    sb.append(str2);
                    throwException(new IllegalStateException(sb.toString()));
                }
                FragmentState fragmentState = new FragmentState(fragment);
                arrayList2.add(fragmentState);
                if (fragment.mState <= 0 || fragmentState.mSavedFragmentState != null) {
                    fragmentState.mSavedFragmentState = fragment.mSavedFragmentState;
                } else {
                    fragmentState.mSavedFragmentState = saveFragmentBasicState(fragment);
                    if (fragment.mTargetWho != null) {
                        Fragment fragment2 = (Fragment) this.mActive.get(fragment.mTargetWho);
                        if (fragment2 == null) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("Failure saving state: ");
                            sb2.append(fragment);
                            sb2.append(" has target not in fragment manager: ");
                            sb2.append(fragment.mTargetWho);
                            throwException(new IllegalStateException(sb2.toString()));
                        }
                        if (fragmentState.mSavedFragmentState == null) {
                            fragmentState.mSavedFragmentState = new Bundle();
                        }
                        putFragment(fragmentState.mSavedFragmentState, TARGET_STATE_TAG, fragment2);
                        if (fragment.mTargetRequestCode != 0) {
                            fragmentState.mSavedFragmentState.putInt(TARGET_REQUEST_CODE_STATE_TAG, fragment.mTargetRequestCode);
                        }
                    }
                }
                if (DEBUG) {
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("Saved state of ");
                    sb3.append(fragment);
                    sb3.append(str);
                    sb3.append(fragmentState.mSavedFragmentState);
                    Log.v(str4, sb3.toString());
                }
                z = true;
            }
        }
        if (!z) {
            if (DEBUG) {
                Log.v(str4, "saveAllState: no fragments!");
            }
            return null;
        }
        int size = this.mAdded.size();
        if (size > 0) {
            arrayList = new ArrayList<>(size);
            Iterator it2 = this.mAdded.iterator();
            while (it2.hasNext()) {
                Fragment fragment3 = (Fragment) it2.next();
                arrayList.add(fragment3.mWho);
                if (fragment3.mFragmentManager != this) {
                    StringBuilder sb4 = new StringBuilder();
                    sb4.append(str3);
                    sb4.append(fragment3);
                    sb4.append(str2);
                    throwException(new IllegalStateException(sb4.toString()));
                }
                if (DEBUG) {
                    StringBuilder sb5 = new StringBuilder();
                    sb5.append("saveAllState: adding fragment (");
                    sb5.append(fragment3.mWho);
                    sb5.append("): ");
                    sb5.append(fragment3);
                    Log.v(str4, sb5.toString());
                }
            }
        } else {
            arrayList = null;
        }
        ArrayList<BackStackRecord> arrayList3 = this.mBackStack;
        if (arrayList3 != null) {
            int size2 = arrayList3.size();
            if (size2 > 0) {
                backStackStateArr = new BackStackState[size2];
                for (int i = 0; i < size2; i++) {
                    backStackStateArr[i] = new BackStackState((BackStackRecord) this.mBackStack.get(i));
                    if (DEBUG) {
                        StringBuilder sb6 = new StringBuilder();
                        sb6.append("saveAllState: adding back stack #");
                        sb6.append(i);
                        sb6.append(str);
                        sb6.append(this.mBackStack.get(i));
                        Log.v(str4, sb6.toString());
                    }
                }
            }
        }
        FragmentManagerState fragmentManagerState = new FragmentManagerState();
        fragmentManagerState.mActive = arrayList2;
        fragmentManagerState.mAdded = arrayList;
        fragmentManagerState.mBackStack = backStackStateArr;
        Fragment fragment4 = this.mPrimaryNav;
        if (fragment4 != null) {
            fragmentManagerState.mPrimaryNavActiveWho = fragment4.mWho;
        }
        fragmentManagerState.mNextFragmentIndex = this.mNextFragmentIndex;
        return fragmentManagerState;
    }

    /* access modifiers changed from: 0000 */
    public void restoreAllState(Parcelable parcelable, FragmentManagerNonConfig fragmentManagerNonConfig) {
        if (this.mHost instanceof ViewModelStoreOwner) {
            throwException(new IllegalStateException("You must use restoreSaveState when your FragmentHostCallback implements ViewModelStoreOwner"));
        }
        this.mNonConfig.restoreFromSnapshot(fragmentManagerNonConfig);
        restoreSaveState(parcelable);
    }

    /* access modifiers changed from: 0000 */
    public void restoreSaveState(Parcelable parcelable) {
        FragmentState fragmentState;
        if (parcelable != null) {
            FragmentManagerState fragmentManagerState = (FragmentManagerState) parcelable;
            if (fragmentManagerState.mActive != null) {
                for (Fragment fragment : this.mNonConfig.getRetainedFragments()) {
                    if (DEBUG) {
                        String str = TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("restoreSaveState: re-attaching retained ");
                        sb.append(fragment);
                        Log.v(str, sb.toString());
                    }
                    Iterator it = fragmentManagerState.mActive.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            fragmentState = null;
                            break;
                        }
                        fragmentState = (FragmentState) it.next();
                        if (fragmentState.mWho.equals(fragment.mWho)) {
                            break;
                        }
                    }
                    if (fragmentState == null) {
                        if (DEBUG) {
                            String str2 = TAG;
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("Discarding retained Fragment ");
                            sb2.append(fragment);
                            sb2.append(" that was not found in the set of active Fragments ");
                            sb2.append(fragmentManagerState.mActive);
                            Log.v(str2, sb2.toString());
                        }
                        Fragment fragment2 = fragment;
                        moveToState(fragment2, 1, 0, 0, false);
                        fragment.mRemoving = true;
                        moveToState(fragment2, 0, 0, 0, false);
                    } else {
                        fragmentState.mInstance = fragment;
                        fragment.mSavedViewState = null;
                        fragment.mBackStackNesting = 0;
                        fragment.mInLayout = false;
                        fragment.mAdded = false;
                        fragment.mTargetWho = fragment.mTarget != null ? fragment.mTarget.mWho : null;
                        fragment.mTarget = null;
                        if (fragmentState.mSavedFragmentState != null) {
                            fragmentState.mSavedFragmentState.setClassLoader(this.mHost.getContext().getClassLoader());
                            fragment.mSavedViewState = fragmentState.mSavedFragmentState.getSparseParcelableArray(VIEW_STATE_TAG);
                            fragment.mSavedFragmentState = fragmentState.mSavedFragmentState;
                        }
                    }
                }
                this.mActive.clear();
                Iterator it2 = fragmentManagerState.mActive.iterator();
                while (it2.hasNext()) {
                    FragmentState fragmentState2 = (FragmentState) it2.next();
                    if (fragmentState2 != null) {
                        Fragment instantiate = fragmentState2.instantiate(this.mHost.getContext().getClassLoader(), getFragmentFactory());
                        instantiate.mFragmentManager = this;
                        if (DEBUG) {
                            String str3 = TAG;
                            StringBuilder sb3 = new StringBuilder();
                            sb3.append("restoreSaveState: active (");
                            sb3.append(instantiate.mWho);
                            sb3.append("): ");
                            sb3.append(instantiate);
                            Log.v(str3, sb3.toString());
                        }
                        this.mActive.put(instantiate.mWho, instantiate);
                        fragmentState2.mInstance = null;
                    }
                }
                this.mAdded.clear();
                if (fragmentManagerState.mAdded != null) {
                    Iterator it3 = fragmentManagerState.mAdded.iterator();
                    while (it3.hasNext()) {
                        String str4 = (String) it3.next();
                        Fragment fragment3 = (Fragment) this.mActive.get(str4);
                        if (fragment3 == null) {
                            StringBuilder sb4 = new StringBuilder();
                            sb4.append("No instantiated fragment for (");
                            sb4.append(str4);
                            sb4.append(")");
                            throwException(new IllegalStateException(sb4.toString()));
                        }
                        fragment3.mAdded = true;
                        if (DEBUG) {
                            String str5 = TAG;
                            StringBuilder sb5 = new StringBuilder();
                            sb5.append("restoreSaveState: added (");
                            sb5.append(str4);
                            sb5.append("): ");
                            sb5.append(fragment3);
                            Log.v(str5, sb5.toString());
                        }
                        if (!this.mAdded.contains(fragment3)) {
                            synchronized (this.mAdded) {
                                this.mAdded.add(fragment3);
                            }
                        } else {
                            StringBuilder sb6 = new StringBuilder();
                            sb6.append("Already added ");
                            sb6.append(fragment3);
                            throw new IllegalStateException(sb6.toString());
                        }
                    }
                }
                if (fragmentManagerState.mBackStack != null) {
                    this.mBackStack = new ArrayList<>(fragmentManagerState.mBackStack.length);
                    for (int i = 0; i < fragmentManagerState.mBackStack.length; i++) {
                        BackStackRecord instantiate2 = fragmentManagerState.mBackStack[i].instantiate(this);
                        if (DEBUG) {
                            String str6 = TAG;
                            StringBuilder sb7 = new StringBuilder();
                            sb7.append("restoreAllState: back stack #");
                            sb7.append(i);
                            sb7.append(" (index ");
                            sb7.append(instantiate2.mIndex);
                            sb7.append("): ");
                            sb7.append(instantiate2);
                            Log.v(str6, sb7.toString());
                            PrintWriter printWriter = new PrintWriter(new LogWriter(TAG));
                            instantiate2.dump("  ", printWriter, false);
                            printWriter.close();
                        }
                        this.mBackStack.add(instantiate2);
                        if (instantiate2.mIndex >= 0) {
                            setBackStackIndex(instantiate2.mIndex, instantiate2);
                        }
                    }
                } else {
                    this.mBackStack = null;
                }
                if (fragmentManagerState.mPrimaryNavActiveWho != null) {
                    Fragment fragment4 = (Fragment) this.mActive.get(fragmentManagerState.mPrimaryNavActiveWho);
                    this.mPrimaryNav = fragment4;
                    dispatchParentPrimaryNavigationFragmentChanged(fragment4);
                }
                this.mNextFragmentIndex = fragmentManagerState.mNextFragmentIndex;
            }
        }
    }

    private void burpActive() {
        this.mActive.values().removeAll(Collections.singleton(null));
    }

    /* JADX WARNING: type inference failed for: r4v7, types: [androidx.lifecycle.LifecycleOwner] */
    /* JADX WARNING: Multi-variable type inference failed */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void attachController(androidx.fragment.app.FragmentHostCallback r3, androidx.fragment.app.FragmentContainer r4, androidx.fragment.app.Fragment r5) {
        /*
            r2 = this;
            androidx.fragment.app.FragmentHostCallback r0 = r2.mHost
            if (r0 != 0) goto L_0x004b
            r2.mHost = r3
            r2.mContainer = r4
            r2.mParent = r5
            if (r5 == 0) goto L_0x000f
            r2.updateOnBackPressedCallbackEnabled()
        L_0x000f:
            boolean r4 = r3 instanceof androidx.activity.OnBackPressedDispatcherOwner
            if (r4 == 0) goto L_0x0026
            r4 = r3
            androidx.activity.OnBackPressedDispatcherOwner r4 = (androidx.activity.OnBackPressedDispatcherOwner) r4
            androidx.activity.OnBackPressedDispatcher r0 = r4.getOnBackPressedDispatcher()
            r2.mOnBackPressedDispatcher = r0
            if (r5 == 0) goto L_0x001f
            r4 = r5
        L_0x001f:
            androidx.activity.OnBackPressedDispatcher r0 = r2.mOnBackPressedDispatcher
            androidx.activity.OnBackPressedCallback r1 = r2.mOnBackPressedCallback
            r0.addCallback(r4, r1)
        L_0x0026:
            if (r5 == 0) goto L_0x0031
            androidx.fragment.app.FragmentManagerImpl r3 = r5.mFragmentManager
            androidx.fragment.app.FragmentManagerViewModel r3 = r3.getChildNonConfig(r5)
            r2.mNonConfig = r3
            goto L_0x004a
        L_0x0031:
            boolean r4 = r3 instanceof androidx.lifecycle.ViewModelStoreOwner
            if (r4 == 0) goto L_0x0042
            androidx.lifecycle.ViewModelStoreOwner r3 = (androidx.lifecycle.ViewModelStoreOwner) r3
            androidx.lifecycle.ViewModelStore r3 = r3.getViewModelStore()
            androidx.fragment.app.FragmentManagerViewModel r3 = androidx.fragment.app.FragmentManagerViewModel.getInstance(r3)
            r2.mNonConfig = r3
            goto L_0x004a
        L_0x0042:
            androidx.fragment.app.FragmentManagerViewModel r3 = new androidx.fragment.app.FragmentManagerViewModel
            r4 = 0
            r3.<init>(r4)
            r2.mNonConfig = r3
        L_0x004a:
            return
        L_0x004b:
            java.lang.IllegalStateException r3 = new java.lang.IllegalStateException
            java.lang.String r4 = "Already attached"
            r3.<init>(r4)
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.FragmentManagerImpl.attachController(androidx.fragment.app.FragmentHostCallback, androidx.fragment.app.FragmentContainer, androidx.fragment.app.Fragment):void");
    }

    public void noteStateNotSaved() {
        this.mStateSaved = false;
        this.mStopped = false;
        int size = this.mAdded.size();
        for (int i = 0; i < size; i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null) {
                fragment.noteStateNotSaved();
            }
        }
    }

    public void dispatchCreate() {
        this.mStateSaved = false;
        this.mStopped = false;
        dispatchStateChange(1);
    }

    public void dispatchActivityCreated() {
        this.mStateSaved = false;
        this.mStopped = false;
        dispatchStateChange(2);
    }

    public void dispatchStart() {
        this.mStateSaved = false;
        this.mStopped = false;
        dispatchStateChange(3);
    }

    public void dispatchResume() {
        this.mStateSaved = false;
        this.mStopped = false;
        dispatchStateChange(4);
    }

    public void dispatchPause() {
        dispatchStateChange(3);
    }

    public void dispatchStop() {
        this.mStopped = true;
        dispatchStateChange(2);
    }

    public void dispatchDestroyView() {
        dispatchStateChange(1);
    }

    public void dispatchDestroy() {
        this.mDestroyed = true;
        execPendingActions();
        dispatchStateChange(0);
        this.mHost = null;
        this.mContainer = null;
        this.mParent = null;
        if (this.mOnBackPressedDispatcher != null) {
            this.mOnBackPressedCallback.remove();
            this.mOnBackPressedDispatcher = null;
        }
    }

    /* JADX INFO: finally extract failed */
    private void dispatchStateChange(int i) {
        try {
            this.mExecutingActions = true;
            moveToState(i, false);
            this.mExecutingActions = false;
            execPendingActions();
        } catch (Throwable th) {
            this.mExecutingActions = false;
            throw th;
        }
    }

    public void dispatchMultiWindowModeChanged(boolean z) {
        for (int size = this.mAdded.size() - 1; size >= 0; size--) {
            Fragment fragment = (Fragment) this.mAdded.get(size);
            if (fragment != null) {
                fragment.performMultiWindowModeChanged(z);
            }
        }
    }

    public void dispatchPictureInPictureModeChanged(boolean z) {
        for (int size = this.mAdded.size() - 1; size >= 0; size--) {
            Fragment fragment = (Fragment) this.mAdded.get(size);
            if (fragment != null) {
                fragment.performPictureInPictureModeChanged(z);
            }
        }
    }

    public void dispatchConfigurationChanged(Configuration configuration) {
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null) {
                fragment.performConfigurationChanged(configuration);
            }
        }
    }

    public void dispatchLowMemory() {
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null) {
                fragment.performLowMemory();
            }
        }
    }

    public boolean dispatchCreateOptionsMenu(Menu menu, MenuInflater menuInflater) {
        if (this.mCurState < 1) {
            return false;
        }
        ArrayList<Fragment> arrayList = null;
        boolean z = false;
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null && fragment.performCreateOptionsMenu(menu, menuInflater)) {
                if (arrayList == null) {
                    arrayList = new ArrayList<>();
                }
                arrayList.add(fragment);
                z = true;
            }
        }
        if (this.mCreatedMenus != null) {
            for (int i2 = 0; i2 < this.mCreatedMenus.size(); i2++) {
                Fragment fragment2 = (Fragment) this.mCreatedMenus.get(i2);
                if (arrayList == null || !arrayList.contains(fragment2)) {
                    fragment2.onDestroyOptionsMenu();
                }
            }
        }
        this.mCreatedMenus = arrayList;
        return z;
    }

    public boolean dispatchPrepareOptionsMenu(Menu menu) {
        if (this.mCurState < 1) {
            return false;
        }
        boolean z = false;
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null && fragment.performPrepareOptionsMenu(menu)) {
                z = true;
            }
        }
        return z;
    }

    public boolean dispatchOptionsItemSelected(MenuItem menuItem) {
        if (this.mCurState < 1) {
            return false;
        }
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null && fragment.performOptionsItemSelected(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public boolean dispatchContextItemSelected(MenuItem menuItem) {
        if (this.mCurState < 1) {
            return false;
        }
        for (int i = 0; i < this.mAdded.size(); i++) {
            Fragment fragment = (Fragment) this.mAdded.get(i);
            if (fragment != null && fragment.performContextItemSelected(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void dispatchOptionsMenuClosed(Menu menu) {
        if (this.mCurState >= 1) {
            for (int i = 0; i < this.mAdded.size(); i++) {
                Fragment fragment = (Fragment) this.mAdded.get(i);
                if (fragment != null) {
                    fragment.performOptionsMenuClosed(menu);
                }
            }
        }
    }

    public void setPrimaryNavigationFragment(Fragment fragment) {
        if (fragment == null || (this.mActive.get(fragment.mWho) == fragment && (fragment.mHost == null || fragment.getFragmentManager() == this))) {
            Fragment fragment2 = this.mPrimaryNav;
            this.mPrimaryNav = fragment;
            dispatchParentPrimaryNavigationFragmentChanged(fragment2);
            dispatchParentPrimaryNavigationFragmentChanged(this.mPrimaryNav);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(fragment);
        sb.append(" is not an active fragment of FragmentManager ");
        sb.append(this);
        throw new IllegalArgumentException(sb.toString());
    }

    private void dispatchParentPrimaryNavigationFragmentChanged(Fragment fragment) {
        if (fragment != null && this.mActive.get(fragment.mWho) == fragment) {
            fragment.performPrimaryNavigationFragmentChanged();
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchPrimaryNavigationFragmentChanged() {
        updateOnBackPressedCallbackEnabled();
        dispatchParentPrimaryNavigationFragmentChanged(this.mPrimaryNav);
    }

    public Fragment getPrimaryNavigationFragment() {
        return this.mPrimaryNav;
    }

    public void setMaxLifecycle(Fragment fragment, State state) {
        if (this.mActive.get(fragment.mWho) == fragment && (fragment.mHost == null || fragment.getFragmentManager() == this)) {
            fragment.mMaxState = state;
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(fragment);
        sb.append(" is not an active fragment of FragmentManager ");
        sb.append(this);
        throw new IllegalArgumentException(sb.toString());
    }

    public FragmentFactory getFragmentFactory() {
        if (super.getFragmentFactory() == DEFAULT_FACTORY) {
            Fragment fragment = this.mParent;
            if (fragment != null) {
                return fragment.mFragmentManager.getFragmentFactory();
            }
            setFragmentFactory(new FragmentFactory() {
                public Fragment instantiate(ClassLoader classLoader, String str) {
                    return FragmentManagerImpl.this.mHost.instantiate(FragmentManagerImpl.this.mHost.getContext(), str, null);
                }
            });
        }
        return super.getFragmentFactory();
    }

    public void registerFragmentLifecycleCallbacks(FragmentLifecycleCallbacks fragmentLifecycleCallbacks, boolean z) {
        this.mLifecycleCallbacks.add(new FragmentLifecycleCallbacksHolder(fragmentLifecycleCallbacks, z));
    }

    public void unregisterFragmentLifecycleCallbacks(FragmentLifecycleCallbacks fragmentLifecycleCallbacks) {
        synchronized (this.mLifecycleCallbacks) {
            int i = 0;
            int size = this.mLifecycleCallbacks.size();
            while (true) {
                if (i >= size) {
                    break;
                } else if (((FragmentLifecycleCallbacksHolder) this.mLifecycleCallbacks.get(i)).mCallback == fragmentLifecycleCallbacks) {
                    this.mLifecycleCallbacks.remove(i);
                    break;
                } else {
                    i++;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentPreAttached(Fragment fragment, Context context, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentPreAttached(fragment, context, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentPreAttached(this, fragment, context);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentAttached(Fragment fragment, Context context, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentAttached(fragment, context, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentAttached(this, fragment, context);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentPreCreated(Fragment fragment, Bundle bundle, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentPreCreated(fragment, bundle, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentPreCreated(this, fragment, bundle);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentCreated(Fragment fragment, Bundle bundle, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentCreated(fragment, bundle, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentCreated(this, fragment, bundle);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentActivityCreated(Fragment fragment, Bundle bundle, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentActivityCreated(fragment, bundle, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentActivityCreated(this, fragment, bundle);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentViewCreated(Fragment fragment, View view, Bundle bundle, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentViewCreated(fragment, view, bundle, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentViewCreated(this, fragment, view, bundle);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentStarted(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentStarted(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentStarted(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentResumed(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentResumed(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentResumed(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentPaused(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentPaused(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentPaused(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentStopped(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentStopped(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentStopped(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentSaveInstanceState(Fragment fragment, Bundle bundle, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentSaveInstanceState(fragment, bundle, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentSaveInstanceState(this, fragment, bundle);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentViewDestroyed(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentViewDestroyed(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentViewDestroyed(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentDestroyed(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentDestroyed(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentDestroyed(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnFragmentDetached(Fragment fragment, boolean z) {
        Fragment fragment2 = this.mParent;
        if (fragment2 != null) {
            FragmentManager fragmentManager = fragment2.getFragmentManager();
            if (fragmentManager instanceof FragmentManagerImpl) {
                ((FragmentManagerImpl) fragmentManager).dispatchOnFragmentDetached(fragment, true);
            }
        }
        Iterator it = this.mLifecycleCallbacks.iterator();
        while (it.hasNext()) {
            FragmentLifecycleCallbacksHolder fragmentLifecycleCallbacksHolder = (FragmentLifecycleCallbacksHolder) it.next();
            if (!z || fragmentLifecycleCallbacksHolder.mRecursive) {
                fragmentLifecycleCallbacksHolder.mCallback.onFragmentDetached(this, fragment);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean checkForMenus() {
        boolean z = false;
        for (Fragment fragment : this.mActive.values()) {
            if (fragment != null) {
                z = isMenuAvailable(fragment);
                continue;
            }
            if (z) {
                return true;
            }
        }
        return false;
    }

    private boolean isMenuAvailable(Fragment fragment) {
        return (fragment.mHasMenu && fragment.mMenuVisible) || fragment.mChildFragmentManager.checkForMenus();
    }

    public View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        Fragment fragment = null;
        if (!"fragment".equals(str)) {
            return null;
        }
        String attributeValue = attributeSet.getAttributeValue(null, "class");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, FragmentTag.Fragment);
        int i = 0;
        if (attributeValue == null) {
            attributeValue = obtainStyledAttributes.getString(0);
        }
        String str2 = attributeValue;
        int resourceId = obtainStyledAttributes.getResourceId(1, -1);
        String string = obtainStyledAttributes.getString(2);
        obtainStyledAttributes.recycle();
        if (str2 == null || !FragmentFactory.isFragmentClass(context.getClassLoader(), str2)) {
            return null;
        }
        if (view != null) {
            i = view.getId();
        }
        if (i == -1 && resourceId == -1 && string == null) {
            StringBuilder sb = new StringBuilder();
            sb.append(attributeSet.getPositionDescription());
            sb.append(": Must specify unique android:id, android:tag, or have a parent with an id for ");
            sb.append(str2);
            throw new IllegalArgumentException(sb.toString());
        }
        if (resourceId != -1) {
            fragment = findFragmentById(resourceId);
        }
        if (fragment == null && string != null) {
            fragment = findFragmentByTag(string);
        }
        if (fragment == null && i != -1) {
            fragment = findFragmentById(i);
        }
        if (DEBUG) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("onCreateView: id=0x");
            sb2.append(Integer.toHexString(resourceId));
            sb2.append(" fname=");
            sb2.append(str2);
            sb2.append(" existing=");
            sb2.append(fragment);
            Log.v(TAG, sb2.toString());
        }
        if (fragment == null) {
            fragment = getFragmentFactory().instantiate(context.getClassLoader(), str2);
            fragment.mFromLayout = true;
            fragment.mFragmentId = resourceId != 0 ? resourceId : i;
            fragment.mContainerId = i;
            fragment.mTag = string;
            fragment.mInLayout = true;
            fragment.mFragmentManager = this;
            fragment.mHost = this.mHost;
            fragment.onInflate(this.mHost.getContext(), attributeSet, fragment.mSavedFragmentState);
            addFragment(fragment, true);
        } else if (!fragment.mInLayout) {
            fragment.mInLayout = true;
            fragment.mHost = this.mHost;
            fragment.onInflate(this.mHost.getContext(), attributeSet, fragment.mSavedFragmentState);
        } else {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(attributeSet.getPositionDescription());
            sb3.append(": Duplicate id 0x");
            sb3.append(Integer.toHexString(resourceId));
            sb3.append(", tag ");
            sb3.append(string);
            sb3.append(", or parent id 0x");
            sb3.append(Integer.toHexString(i));
            sb3.append(" with another fragment for ");
            sb3.append(str2);
            throw new IllegalArgumentException(sb3.toString());
        }
        Fragment fragment2 = fragment;
        if (this.mCurState >= 1 || !fragment2.mFromLayout) {
            moveToState(fragment2);
        } else {
            moveToState(fragment2, 1, 0, 0, false);
        }
        if (fragment2.mView != null) {
            if (resourceId != 0) {
                fragment2.mView.setId(resourceId);
            }
            if (fragment2.mView.getTag() == null) {
                fragment2.mView.setTag(string);
            }
            return fragment2.mView;
        }
        StringBuilder sb4 = new StringBuilder();
        sb4.append("Fragment ");
        sb4.append(str2);
        sb4.append(" did not create a view.");
        throw new IllegalStateException(sb4.toString());
    }

    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return onCreateView(null, str, context, attributeSet);
    }
}
