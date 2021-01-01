package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.res.TypedArrayUtils;
import androidx.transition.Transition.TransitionListener;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Map;

public abstract class Visibility extends Transition {
    public static final int MODE_IN = 1;
    public static final int MODE_OUT = 2;
    private static final String PROPNAME_PARENT = "android:visibility:parent";
    private static final String PROPNAME_SCREEN_LOCATION = "android:visibility:screenLocation";
    static final String PROPNAME_VISIBILITY = "android:visibility:visibility";
    private static final String[] sTransitionProperties = {PROPNAME_VISIBILITY, PROPNAME_PARENT};
    private int mMode = 3;

    private static class DisappearListener extends AnimatorListenerAdapter implements TransitionListener, AnimatorPauseListenerCompat {
        boolean mCanceled = false;
        private final int mFinalVisibility;
        private boolean mLayoutSuppressed;
        private final ViewGroup mParent;
        private final boolean mSuppressLayout;
        private final View mView;

        DisappearListener(View view, int finalVisibility, boolean suppressLayout) {
            this.mView = view;
            this.mFinalVisibility = finalVisibility;
            this.mParent = (ViewGroup) view.getParent();
            this.mSuppressLayout = suppressLayout;
            suppressLayout(true);
        }

        public void onAnimationPause(Animator animation) {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, this.mFinalVisibility);
            }
        }

        public void onAnimationResume(Animator animation) {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, 0);
            }
        }

        public void onAnimationCancel(Animator animation) {
            this.mCanceled = true;
        }

        public void onAnimationRepeat(Animator animation) {
        }

        public void onAnimationStart(Animator animation) {
        }

        public void onAnimationEnd(Animator animation) {
            hideViewWhenNotCanceled();
        }

        public void onTransitionStart(Transition transition) {
        }

        public void onTransitionEnd(Transition transition) {
            hideViewWhenNotCanceled();
            transition.removeListener(this);
        }

        public void onTransitionCancel(Transition transition) {
        }

        public void onTransitionPause(Transition transition) {
            suppressLayout(false);
        }

        public void onTransitionResume(Transition transition) {
            suppressLayout(true);
        }

        private void hideViewWhenNotCanceled() {
            if (!this.mCanceled) {
                ViewUtils.setTransitionVisibility(this.mView, this.mFinalVisibility);
                ViewGroup viewGroup = this.mParent;
                if (viewGroup != null) {
                    viewGroup.invalidate();
                }
            }
            suppressLayout(false);
        }

        private void suppressLayout(boolean suppress) {
            if (this.mSuppressLayout && this.mLayoutSuppressed != suppress) {
                ViewGroup viewGroup = this.mParent;
                if (viewGroup != null) {
                    this.mLayoutSuppressed = suppress;
                    ViewGroupUtils.suppressLayout(viewGroup, suppress);
                }
            }
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface Mode {
    }

    private static class VisibilityInfo {
        ViewGroup mEndParent;
        int mEndVisibility;
        boolean mFadeIn;
        ViewGroup mStartParent;
        int mStartVisibility;
        boolean mVisibilityChange;

        VisibilityInfo() {
        }
    }

    public Visibility() {
    }

    public Visibility(Context context, AttributeSet attrs) {
        super(context, attrs);
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.VISIBILITY_TRANSITION);
        int mode = TypedArrayUtils.getNamedInt(a, (XmlResourceParser) attrs, "transitionVisibilityMode", 0, 0);
        a.recycle();
        if (mode != 0) {
            setMode(mode);
        }
    }

    public void setMode(int mode) {
        if ((mode & -4) == 0) {
            this.mMode = mode;
            return;
        }
        throw new IllegalArgumentException("Only MODE_IN and MODE_OUT flags are allowed");
    }

    public int getMode() {
        return this.mMode;
    }

    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    private void captureValues(TransitionValues transitionValues) {
        int visibility = transitionValues.view.getVisibility();
        transitionValues.values.put(PROPNAME_VISIBILITY, Integer.valueOf(visibility));
        transitionValues.values.put(PROPNAME_PARENT, transitionValues.view.getParent());
        int[] loc = new int[2];
        transitionValues.view.getLocationOnScreen(loc);
        transitionValues.values.put(PROPNAME_SCREEN_LOCATION, loc);
    }

    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public boolean isVisible(TransitionValues values) {
        boolean z = false;
        if (values == null) {
            return false;
        }
        View parent = (View) values.values.get(PROPNAME_PARENT);
        if (((Integer) values.values.get(PROPNAME_VISIBILITY)).intValue() == 0 && parent != null) {
            z = true;
        }
        return z;
    }

    private VisibilityInfo getVisibilityChangeInfo(TransitionValues startValues, TransitionValues endValues) {
        VisibilityInfo visInfo = new VisibilityInfo();
        visInfo.mVisibilityChange = false;
        visInfo.mFadeIn = false;
        String str = PROPNAME_PARENT;
        String str2 = PROPNAME_VISIBILITY;
        if (startValues == null || !startValues.values.containsKey(str2)) {
            visInfo.mStartVisibility = -1;
            visInfo.mStartParent = null;
        } else {
            visInfo.mStartVisibility = ((Integer) startValues.values.get(str2)).intValue();
            visInfo.mStartParent = (ViewGroup) startValues.values.get(str);
        }
        if (endValues == null || !endValues.values.containsKey(str2)) {
            visInfo.mEndVisibility = -1;
            visInfo.mEndParent = null;
        } else {
            visInfo.mEndVisibility = ((Integer) endValues.values.get(str2)).intValue();
            visInfo.mEndParent = (ViewGroup) endValues.values.get(str);
        }
        if (startValues == null || endValues == null) {
            if (startValues == null && visInfo.mEndVisibility == 0) {
                visInfo.mFadeIn = true;
                visInfo.mVisibilityChange = true;
            } else if (endValues == null && visInfo.mStartVisibility == 0) {
                visInfo.mFadeIn = false;
                visInfo.mVisibilityChange = true;
            }
        } else if (visInfo.mStartVisibility == visInfo.mEndVisibility && visInfo.mStartParent == visInfo.mEndParent) {
            return visInfo;
        } else {
            if (visInfo.mStartVisibility != visInfo.mEndVisibility) {
                if (visInfo.mStartVisibility == 0) {
                    visInfo.mFadeIn = false;
                    visInfo.mVisibilityChange = true;
                } else if (visInfo.mEndVisibility == 0) {
                    visInfo.mFadeIn = true;
                    visInfo.mVisibilityChange = true;
                }
            } else if (visInfo.mEndParent == null) {
                visInfo.mFadeIn = false;
                visInfo.mVisibilityChange = true;
            } else if (visInfo.mStartParent == null) {
                visInfo.mFadeIn = true;
                visInfo.mVisibilityChange = true;
            }
        }
        return visInfo;
    }

    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        VisibilityInfo visInfo = getVisibilityChangeInfo(startValues, endValues);
        if (!visInfo.mVisibilityChange || (visInfo.mStartParent == null && visInfo.mEndParent == null)) {
            return null;
        }
        if (visInfo.mFadeIn) {
            return onAppear(sceneRoot, startValues, visInfo.mStartVisibility, endValues, visInfo.mEndVisibility);
        }
        return onDisappear(sceneRoot, startValues, visInfo.mStartVisibility, endValues, visInfo.mEndVisibility);
    }

    public Animator onAppear(ViewGroup sceneRoot, TransitionValues startValues, int startVisibility, TransitionValues endValues, int endVisibility) {
        if ((this.mMode & 1) != 1 || endValues == null) {
            return null;
        }
        if (startValues == null) {
            View endParent = (View) endValues.view.getParent();
            if (getVisibilityChangeInfo(getMatchedTransitionValues(endParent, false), getTransitionValues(endParent, false)).mVisibilityChange) {
                return null;
            }
        }
        return onAppear(sceneRoot, endValues.view, startValues, endValues);
    }

    public Animator onAppear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        return null;
    }

    /* JADX WARNING: Removed duplicated region for block: B:54:0x00f9  */
    /* JADX WARNING: Removed duplicated region for block: B:59:0x0119  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public android.animation.Animator onDisappear(android.view.ViewGroup r20, androidx.transition.TransitionValues r21, int r22, androidx.transition.TransitionValues r23, int r24) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            r2 = r21
            r3 = r23
            int r4 = r0.mMode
            r5 = 2
            r4 = r4 & r5
            r6 = 0
            if (r4 == r5) goto L_0x0010
            return r6
        L_0x0010:
            if (r2 == 0) goto L_0x0015
            android.view.View r4 = r2.view
            goto L_0x0016
        L_0x0015:
            r4 = r6
        L_0x0016:
            if (r3 == 0) goto L_0x001b
            android.view.View r7 = r3.view
            goto L_0x001c
        L_0x001b:
            r7 = r6
        L_0x001c:
            r8 = 0
            r9 = 0
            r10 = 1
            if (r7 == 0) goto L_0x0049
            android.view.ViewParent r11 = r7.getParent()
            if (r11 != 0) goto L_0x002a
            r12 = r24
            goto L_0x004b
        L_0x002a:
            r11 = 4
            r12 = r24
            if (r12 != r11) goto L_0x0032
            r9 = r7
            goto L_0x0097
        L_0x0032:
            if (r4 != r7) goto L_0x0037
            r9 = r7
            goto L_0x0097
        L_0x0037:
            boolean r11 = r0.mCanRemoveViews
            if (r11 == 0) goto L_0x003d
            r8 = r4
            goto L_0x0097
        L_0x003d:
            android.view.ViewParent r11 = r4.getParent()
            android.view.View r11 = (android.view.View) r11
            android.view.View r8 = androidx.transition.TransitionUtils.copyViewImage(r1, r4, r11)
            goto L_0x0097
        L_0x0049:
            r12 = r24
        L_0x004b:
            if (r7 == 0) goto L_0x004f
            r8 = r7
            goto L_0x0097
        L_0x004f:
            if (r4 == 0) goto L_0x0097
            android.view.ViewParent r11 = r4.getParent()
            if (r11 != 0) goto L_0x0059
            r8 = r4
            goto L_0x0097
        L_0x0059:
            android.view.ViewParent r11 = r4.getParent()
            boolean r11 = r11 instanceof android.view.View
            if (r11 == 0) goto L_0x0097
            android.view.ViewParent r11 = r4.getParent()
            android.view.View r11 = (android.view.View) r11
            androidx.transition.TransitionValues r13 = r0.getTransitionValues(r11, r10)
            androidx.transition.TransitionValues r14 = r0.getMatchedTransitionValues(r11, r10)
            androidx.transition.Visibility$VisibilityInfo r15 = r0.getVisibilityChangeInfo(r13, r14)
            boolean r6 = r15.mVisibilityChange
            if (r6 != 0) goto L_0x007e
            android.view.View r6 = androidx.transition.TransitionUtils.copyViewImage(r1, r4, r11)
            r8 = r6
            goto L_0x0097
        L_0x007e:
            android.view.ViewParent r6 = r11.getParent()
            if (r6 != 0) goto L_0x0097
            int r6 = r11.getId()
            r5 = -1
            if (r6 == r5) goto L_0x0097
            android.view.View r5 = r1.findViewById(r6)
            if (r5 == 0) goto L_0x0097
            boolean r5 = r0.mCanRemoveViews
            if (r5 == 0) goto L_0x0097
            r5 = r4
            r8 = r5
        L_0x0097:
            r5 = r24
            r6 = 0
            if (r8 == 0) goto L_0x00f3
            if (r2 == 0) goto L_0x00f3
            java.util.Map<java.lang.String, java.lang.Object> r11 = r2.values
            java.lang.String r13 = "android:visibility:screenLocation"
            java.lang.Object r11 = r11.get(r13)
            int[] r11 = (int[]) r11
            int[] r11 = (int[]) r11
            r13 = r11[r6]
            r14 = r11[r10]
            r15 = 2
            int[] r15 = new int[r15]
            r1.getLocationOnScreen(r15)
            r6 = r15[r6]
            int r6 = r13 - r6
            int r16 = r8.getLeft()
            int r6 = r6 - r16
            r8.offsetLeftAndRight(r6)
            r6 = r15[r10]
            int r6 = r14 - r6
            int r10 = r8.getTop()
            int r6 = r6 - r10
            r8.offsetTopAndBottom(r6)
            androidx.transition.ViewGroupOverlayImpl r6 = androidx.transition.ViewGroupUtils.getOverlay(r20)
            r6.add(r8)
            android.animation.Animator r10 = r0.onDisappear(r1, r8, r2, r3)
            if (r10 != 0) goto L_0x00e2
            r6.remove(r8)
            r17 = r4
            r18 = r7
            goto L_0x00f2
        L_0x00e2:
            r16 = r8
            r17 = r4
            androidx.transition.Visibility$1 r4 = new androidx.transition.Visibility$1
            r18 = r7
            r7 = r16
            r4.<init>(r6, r7)
            r10.addListener(r4)
        L_0x00f2:
            return r10
        L_0x00f3:
            r17 = r4
            r18 = r7
            if (r9 == 0) goto L_0x0119
            int r4 = r9.getVisibility()
            androidx.transition.ViewUtils.setTransitionVisibility(r9, r6)
            android.animation.Animator r6 = r0.onDisappear(r1, r9, r2, r3)
            if (r6 == 0) goto L_0x0115
            androidx.transition.Visibility$DisappearListener r7 = new androidx.transition.Visibility$DisappearListener
            r7.<init>(r9, r5, r10)
            r6.addListener(r7)
            androidx.transition.AnimatorUtils.addPauseListener(r6, r7)
            r0.addListener(r7)
            goto L_0x0118
        L_0x0115:
            androidx.transition.ViewUtils.setTransitionVisibility(r9, r4)
        L_0x0118:
            return r6
        L_0x0119:
            r4 = 0
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.Visibility.onDisappear(android.view.ViewGroup, androidx.transition.TransitionValues, int, androidx.transition.TransitionValues, int):android.animation.Animator");
    }

    public Animator onDisappear(ViewGroup sceneRoot, View view, TransitionValues startValues, TransitionValues endValues) {
        return null;
    }

    public boolean isTransitionRequired(TransitionValues startValues, TransitionValues newValues) {
        boolean z = false;
        if (startValues == null && newValues == null) {
            return false;
        }
        if (!(startValues == null || newValues == null)) {
            Map<String, Object> map = newValues.values;
            String str = PROPNAME_VISIBILITY;
            if (map.containsKey(str) != startValues.values.containsKey(str)) {
                return false;
            }
        }
        VisibilityInfo changeInfo = getVisibilityChangeInfo(startValues, newValues);
        if (changeInfo.mVisibilityChange && (changeInfo.mStartVisibility == 0 || changeInfo.mEndVisibility == 0)) {
            z = true;
        }
        return z;
    }
}
