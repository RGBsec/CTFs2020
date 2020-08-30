package com.google.android.material.transformation;

import android.animation.Animator;
import android.animation.Animator.AnimatorListener;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewAnimationUtils;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.animation.AnimatorSetCompat;
import com.google.android.material.animation.ArgbEvaluatorCompat;
import com.google.android.material.animation.ChildrenAlphaProperty;
import com.google.android.material.animation.DrawableAlphaProperty;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.animation.MotionTiming;
import com.google.android.material.animation.Positioning;
import com.google.android.material.circularreveal.CircularRevealCompat;
import com.google.android.material.circularreveal.CircularRevealHelper;
import com.google.android.material.circularreveal.CircularRevealWidget;
import com.google.android.material.circularreveal.CircularRevealWidget.CircularRevealScrimColorProperty;
import com.google.android.material.circularreveal.CircularRevealWidget.RevealInfo;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.math.MathUtils;
import java.util.ArrayList;
import java.util.List;

public abstract class FabTransformationBehavior extends ExpandableTransformationBehavior {
    private final int[] tmpArray = new int[2];
    private final Rect tmpRect = new Rect();
    private final RectF tmpRectF1 = new RectF();
    private final RectF tmpRectF2 = new RectF();

    protected static class FabTransformationSpec {
        public Positioning positioning;
        public MotionSpec timings;

        protected FabTransformationSpec() {
        }
    }

    /* access modifiers changed from: protected */
    public abstract FabTransformationSpec onCreateMotionSpec(Context context, boolean z);

    public FabTransformationBehavior() {
    }

    public FabTransformationBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean layoutDependsOn(CoordinatorLayout parent, View child, View dependency) {
        if (child.getVisibility() != 8) {
            boolean z = false;
            if (!(dependency instanceof FloatingActionButton)) {
                return false;
            }
            int expandedComponentIdHint = ((FloatingActionButton) dependency).getExpandedComponentIdHint();
            if (expandedComponentIdHint == 0 || expandedComponentIdHint == child.getId()) {
                z = true;
            }
            return z;
        }
        throw new IllegalStateException("This behavior cannot be attached to a GONE view. Set the view to INVISIBLE instead.");
    }

    public void onAttachedToLayoutParams(LayoutParams lp) {
        if (lp.dodgeInsetEdges == 0) {
            lp.dodgeInsetEdges = 80;
        }
    }

    /* access modifiers changed from: protected */
    public AnimatorSet onCreateExpandedStateChangeAnimation(View dependency, View child, boolean expanded, boolean isAnimating) {
        final boolean z = expanded;
        FabTransformationSpec spec = onCreateMotionSpec(child.getContext(), z);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        if (VERSION.SDK_INT >= 21) {
            createElevationAnimation(dependency, child, expanded, isAnimating, spec, arrayList, arrayList2);
        }
        RectF childBounds = this.tmpRectF1;
        View view = dependency;
        View view2 = child;
        boolean z2 = expanded;
        boolean z3 = isAnimating;
        FabTransformationSpec fabTransformationSpec = spec;
        ArrayList arrayList3 = arrayList;
        ArrayList arrayList4 = arrayList2;
        createTranslationAnimation(view, view2, z2, z3, fabTransformationSpec, arrayList3, arrayList4, childBounds);
        float childWidth = childBounds.width();
        float childHeight = childBounds.height();
        createIconFadeAnimation(view, view2, z2, z3, fabTransformationSpec, arrayList3, arrayList4);
        createExpansionAnimation(view, view2, z2, z3, fabTransformationSpec, childWidth, childHeight, arrayList, arrayList2);
        ArrayList arrayList5 = arrayList;
        ArrayList arrayList6 = arrayList2;
        createColorAnimation(view, view2, z2, z3, fabTransformationSpec, arrayList5, arrayList6);
        createChildrenFadeAnimation(view, view2, z2, z3, fabTransformationSpec, arrayList5, arrayList6);
        AnimatorSet set = new AnimatorSet();
        AnimatorSetCompat.playTogether(set, arrayList);
        final View view3 = dependency;
        final View view4 = child;
        set.addListener(new AnimatorListenerAdapter() {
            public void onAnimationStart(Animator animation) {
                if (z) {
                    view4.setVisibility(0);
                    view3.setAlpha(0.0f);
                    view3.setVisibility(4);
                }
            }

            public void onAnimationEnd(Animator animation) {
                if (!z) {
                    view4.setVisibility(4);
                    view3.setAlpha(1.0f);
                    view3.setVisibility(0);
                }
            }
        });
        int count = arrayList2.size();
        for (int i = 0; i < count; i++) {
            set.addListener((AnimatorListener) arrayList2.get(i));
        }
        return set;
    }

    private void createElevationAnimation(View dependency, View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, List<Animator> animations, List<AnimatorListener> list) {
        Animator animator;
        float translationZ = ViewCompat.getElevation(child) - ViewCompat.getElevation(dependency);
        if (expanded) {
            if (!currentlyAnimating) {
                child.setTranslationZ(-translationZ);
            }
            animator = ObjectAnimator.ofFloat(child, View.TRANSLATION_Z, new float[]{0.0f});
        } else {
            animator = ObjectAnimator.ofFloat(child, View.TRANSLATION_Z, new float[]{-translationZ});
        }
        spec.timings.getTiming("elevation").apply(animator);
        animations.add(animator);
    }

    private void createTranslationAnimation(View dependency, View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, List<Animator> animations, List<AnimatorListener> list, RectF childBounds) {
        MotionTiming translationXTiming;
        MotionTiming translationYTiming;
        MotionTiming translationXTiming2;
        MotionTiming translationYTiming2;
        ValueAnimator translationYAnimator;
        ValueAnimator translationXAnimator;
        View view = dependency;
        View view2 = child;
        FabTransformationSpec fabTransformationSpec = spec;
        List<Animator> list2 = animations;
        float translationX = calculateTranslationX(view, view2, fabTransformationSpec.positioning);
        float translationY = calculateTranslationY(view, view2, fabTransformationSpec.positioning);
        if (translationX == 0.0f || translationY == 0.0f) {
            translationXTiming = fabTransformationSpec.timings.getTiming("translationXLinear");
            translationYTiming = fabTransformationSpec.timings.getTiming("translationYLinear");
        } else if ((!expanded || translationY >= 0.0f) && (expanded || translationY <= 0.0f)) {
            translationXTiming = fabTransformationSpec.timings.getTiming("translationXCurveDownwards");
            translationYTiming = fabTransformationSpec.timings.getTiming("translationYCurveDownwards");
        } else {
            translationXTiming = fabTransformationSpec.timings.getTiming("translationXCurveUpwards");
            translationYTiming = fabTransformationSpec.timings.getTiming("translationYCurveUpwards");
        }
        if (expanded) {
            if (!currentlyAnimating) {
                view2.setTranslationX(-translationX);
                view2.setTranslationY(-translationY);
            }
            ValueAnimator translationXAnimator2 = ObjectAnimator.ofFloat(view2, View.TRANSLATION_X, new float[]{0.0f});
            ValueAnimator translationYAnimator2 = ObjectAnimator.ofFloat(view2, View.TRANSLATION_Y, new float[]{0.0f});
            translationYTiming2 = translationYTiming;
            translationXTiming2 = translationXTiming;
            float f = translationY;
            calculateChildVisibleBoundsAtEndOfExpansion(child, spec, translationXTiming, translationYTiming, -translationX, -translationY, 0.0f, 0.0f, childBounds);
            translationXAnimator = translationXAnimator2;
            translationYAnimator = translationYAnimator2;
        } else {
            translationYTiming2 = translationYTiming;
            translationXTiming2 = translationXTiming;
            float translationY2 = translationY;
            ValueAnimator translationXAnimator3 = ObjectAnimator.ofFloat(view2, View.TRANSLATION_X, new float[]{-translationX});
            ValueAnimator ofFloat = ObjectAnimator.ofFloat(view2, View.TRANSLATION_Y, new float[]{-translationY2});
            translationXAnimator = translationXAnimator3;
            translationYAnimator = ofFloat;
        }
        translationXTiming2.apply(translationXAnimator);
        translationYTiming2.apply(translationYAnimator);
        list2.add(translationXAnimator);
        list2.add(translationYAnimator);
    }

    private void createIconFadeAnimation(View dependency, final View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, List<Animator> animations, List<AnimatorListener> listeners) {
        ObjectAnimator animator;
        if ((child instanceof CircularRevealWidget) && (dependency instanceof ImageView)) {
            final CircularRevealWidget circularRevealChild = (CircularRevealWidget) child;
            final Drawable icon = ((ImageView) dependency).getDrawable();
            if (icon != null) {
                icon.mutate();
                if (expanded) {
                    if (!currentlyAnimating) {
                        icon.setAlpha(255);
                    }
                    animator = ObjectAnimator.ofInt(icon, DrawableAlphaProperty.DRAWABLE_ALPHA_COMPAT, new int[]{0});
                } else {
                    animator = ObjectAnimator.ofInt(icon, DrawableAlphaProperty.DRAWABLE_ALPHA_COMPAT, new int[]{255});
                }
                animator.addUpdateListener(new AnimatorUpdateListener() {
                    public void onAnimationUpdate(ValueAnimator animation) {
                        child.invalidate();
                    }
                });
                spec.timings.getTiming("iconFade").apply(animator);
                animations.add(animator);
                listeners.add(new AnimatorListenerAdapter() {
                    public void onAnimationStart(Animator animation) {
                        circularRevealChild.setCircularRevealOverlayDrawable(icon);
                    }

                    public void onAnimationEnd(Animator animation) {
                        circularRevealChild.setCircularRevealOverlayDrawable(null);
                    }
                });
            }
        }
    }

    private void createExpansionAnimation(View dependency, View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, float childWidth, float childHeight, List<Animator> animations, List<AnimatorListener> listeners) {
        CircularRevealWidget circularRevealChild;
        MotionTiming timing;
        Animator animator;
        View view = dependency;
        View view2 = child;
        FabTransformationSpec fabTransformationSpec = spec;
        if (view2 instanceof CircularRevealWidget) {
            final CircularRevealWidget circularRevealChild2 = (CircularRevealWidget) view2;
            float revealCenterX = calculateRevealCenterX(view, view2, fabTransformationSpec.positioning);
            float revealCenterY = calculateRevealCenterY(view, view2, fabTransformationSpec.positioning);
            ((FloatingActionButton) view).getContentRect(this.tmpRect);
            float dependencyRadius = ((float) this.tmpRect.width()) / 2.0f;
            MotionTiming timing2 = fabTransformationSpec.timings.getTiming("expansion");
            if (expanded) {
                if (!currentlyAnimating) {
                    circularRevealChild2.setRevealInfo(new RevealInfo(revealCenterX, revealCenterY, dependencyRadius));
                }
                float fromRadius = currentlyAnimating ? circularRevealChild2.getRevealInfo().radius : dependencyRadius;
                float toRadius = MathUtils.distanceToFurthestCorner(revealCenterX, revealCenterY, 0.0f, 0.0f, childWidth, childHeight);
                Animator animator2 = CircularRevealCompat.createCircularReveal(circularRevealChild2, revealCenterX, revealCenterY, toRadius);
                animator2.addListener(new AnimatorListenerAdapter() {
                    public void onAnimationEnd(Animator animation) {
                        RevealInfo revealInfo = circularRevealChild2.getRevealInfo();
                        revealInfo.radius = Float.MAX_VALUE;
                        circularRevealChild2.setRevealInfo(revealInfo);
                    }
                });
                Animator animator3 = animator2;
                float f = toRadius;
                timing = timing2;
                createPreFillRadialExpansion(child, timing2.getDelay(), (int) revealCenterX, (int) revealCenterY, fromRadius, animations);
                float f2 = dependencyRadius;
                float f3 = revealCenterY;
                float f4 = revealCenterX;
                circularRevealChild = circularRevealChild2;
                animator = animator3;
            } else {
                timing = timing2;
                float fromRadius2 = circularRevealChild2.getRevealInfo().radius;
                float toRadius2 = dependencyRadius;
                Animator animator4 = CircularRevealCompat.createCircularReveal(circularRevealChild2, revealCenterX, revealCenterY, toRadius2);
                float toRadius3 = toRadius2;
                float f5 = fromRadius2;
                createPreFillRadialExpansion(child, timing.getDelay(), (int) revealCenterX, (int) revealCenterY, fromRadius2, animations);
                float f6 = dependencyRadius;
                float f7 = revealCenterY;
                float f8 = revealCenterX;
                circularRevealChild = circularRevealChild2;
                createPostFillRadialExpansion(child, timing.getDelay(), timing.getDuration(), fabTransformationSpec.timings.getTotalDuration(), (int) revealCenterX, (int) revealCenterY, toRadius3, animations);
                animator = animator4;
            }
            timing.apply(animator);
            animations.add(animator);
            listeners.add(CircularRevealCompat.createCircularRevealListener(circularRevealChild));
        }
    }

    private void createColorAnimation(View dependency, View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, List<Animator> animations, List<AnimatorListener> list) {
        ObjectAnimator animator;
        if (child instanceof CircularRevealWidget) {
            CircularRevealWidget circularRevealChild = (CircularRevealWidget) child;
            int tint = getBackgroundTint(dependency);
            int transparent = 16777215 & tint;
            if (expanded) {
                if (!currentlyAnimating) {
                    circularRevealChild.setCircularRevealScrimColor(tint);
                }
                animator = ObjectAnimator.ofInt(circularRevealChild, CircularRevealScrimColorProperty.CIRCULAR_REVEAL_SCRIM_COLOR, new int[]{transparent});
            } else {
                animator = ObjectAnimator.ofInt(circularRevealChild, CircularRevealScrimColorProperty.CIRCULAR_REVEAL_SCRIM_COLOR, new int[]{tint});
            }
            animator.setEvaluator(ArgbEvaluatorCompat.getInstance());
            spec.timings.getTiming("color").apply(animator);
            animations.add(animator);
        }
    }

    private void createChildrenFadeAnimation(View unusedDependency, View child, boolean expanded, boolean currentlyAnimating, FabTransformationSpec spec, List<Animator> animations, List<AnimatorListener> list) {
        Animator animator;
        if (child instanceof ViewGroup) {
            if (!(child instanceof CircularRevealWidget) || CircularRevealHelper.STRATEGY != 0) {
                ViewGroup childContentContainer = calculateChildContentContainer(child);
                if (childContentContainer != null) {
                    if (expanded) {
                        if (!currentlyAnimating) {
                            ChildrenAlphaProperty.CHILDREN_ALPHA.set(childContentContainer, Float.valueOf(0.0f));
                        }
                        animator = ObjectAnimator.ofFloat(childContentContainer, ChildrenAlphaProperty.CHILDREN_ALPHA, new float[]{1.0f});
                    } else {
                        animator = ObjectAnimator.ofFloat(childContentContainer, ChildrenAlphaProperty.CHILDREN_ALPHA, new float[]{0.0f});
                    }
                    spec.timings.getTiming("contentFade").apply(animator);
                    animations.add(animator);
                }
            }
        }
    }

    private float calculateTranslationX(View dependency, View child, Positioning positioning) {
        RectF dependencyBounds = this.tmpRectF1;
        RectF childBounds = this.tmpRectF2;
        calculateWindowBounds(dependency, dependencyBounds);
        calculateWindowBounds(child, childBounds);
        float translationX = 0.0f;
        int i = positioning.gravity & 7;
        if (i == 1) {
            translationX = childBounds.centerX() - dependencyBounds.centerX();
        } else if (i == 3) {
            translationX = childBounds.left - dependencyBounds.left;
        } else if (i == 5) {
            translationX = childBounds.right - dependencyBounds.right;
        }
        return translationX + positioning.xAdjustment;
    }

    private float calculateTranslationY(View dependency, View child, Positioning positioning) {
        RectF dependencyBounds = this.tmpRectF1;
        RectF childBounds = this.tmpRectF2;
        calculateWindowBounds(dependency, dependencyBounds);
        calculateWindowBounds(child, childBounds);
        float translationY = 0.0f;
        int i = positioning.gravity & 112;
        if (i == 16) {
            translationY = childBounds.centerY() - dependencyBounds.centerY();
        } else if (i == 48) {
            translationY = childBounds.top - dependencyBounds.top;
        } else if (i == 80) {
            translationY = childBounds.bottom - dependencyBounds.bottom;
        }
        return translationY + positioning.yAdjustment;
    }

    private void calculateWindowBounds(View view, RectF rect) {
        RectF windowBounds = rect;
        windowBounds.set(0.0f, 0.0f, (float) view.getWidth(), (float) view.getHeight());
        int[] windowLocation = this.tmpArray;
        view.getLocationInWindow(windowLocation);
        windowBounds.offsetTo((float) windowLocation[0], (float) windowLocation[1]);
        windowBounds.offset((float) ((int) (-view.getTranslationX())), (float) ((int) (-view.getTranslationY())));
    }

    private float calculateRevealCenterX(View dependency, View child, Positioning positioning) {
        RectF dependencyBounds = this.tmpRectF1;
        RectF childBounds = this.tmpRectF2;
        calculateWindowBounds(dependency, dependencyBounds);
        calculateWindowBounds(child, childBounds);
        childBounds.offset(-calculateTranslationX(dependency, child, positioning), 0.0f);
        return dependencyBounds.centerX() - childBounds.left;
    }

    private float calculateRevealCenterY(View dependency, View child, Positioning positioning) {
        RectF dependencyBounds = this.tmpRectF1;
        RectF childBounds = this.tmpRectF2;
        calculateWindowBounds(dependency, dependencyBounds);
        calculateWindowBounds(child, childBounds);
        childBounds.offset(0.0f, -calculateTranslationY(dependency, child, positioning));
        return dependencyBounds.centerY() - childBounds.top;
    }

    private void calculateChildVisibleBoundsAtEndOfExpansion(View child, FabTransformationSpec spec, MotionTiming translationXTiming, MotionTiming translationYTiming, float fromX, float fromY, float toX, float toY, RectF childBounds) {
        float translationX = calculateValueOfAnimationAtEndOfExpansion(spec, translationXTiming, fromX, toX);
        float translationY = calculateValueOfAnimationAtEndOfExpansion(spec, translationYTiming, fromY, toY);
        Rect window = this.tmpRect;
        child.getWindowVisibleDisplayFrame(window);
        RectF windowF = this.tmpRectF1;
        windowF.set(window);
        RectF childVisibleBounds = this.tmpRectF2;
        calculateWindowBounds(child, childVisibleBounds);
        childVisibleBounds.offset(translationX, translationY);
        childVisibleBounds.intersect(windowF);
        childBounds.set(childVisibleBounds);
    }

    private float calculateValueOfAnimationAtEndOfExpansion(FabTransformationSpec spec, MotionTiming timing, float from, float to) {
        long delay = timing.getDelay();
        long duration = timing.getDuration();
        MotionTiming expansionTiming = spec.timings.getTiming("expansion");
        return AnimationUtils.lerp(from, to, timing.getInterpolator().getInterpolation(((float) (((expansionTiming.getDelay() + expansionTiming.getDuration()) + 17) - delay)) / ((float) duration)));
    }

    private ViewGroup calculateChildContentContainer(View view) {
        View childContentContainer = view.findViewById(C0078R.C0080id.mtrl_child_content_container);
        if (childContentContainer != null) {
            return toViewGroupOrNull(childContentContainer);
        }
        if ((view instanceof TransformationChildLayout) || (view instanceof TransformationChildCard)) {
            return toViewGroupOrNull(((ViewGroup) view).getChildAt(0));
        }
        return toViewGroupOrNull(view);
    }

    private ViewGroup toViewGroupOrNull(View view) {
        if (view instanceof ViewGroup) {
            return (ViewGroup) view;
        }
        return null;
    }

    private int getBackgroundTint(View view) {
        ColorStateList tintList = ViewCompat.getBackgroundTintList(view);
        if (tintList != null) {
            return tintList.getColorForState(view.getDrawableState(), tintList.getDefaultColor());
        }
        return 0;
    }

    private void createPreFillRadialExpansion(View child, long delay, int revealCenterX, int revealCenterY, float fromRadius, List<Animator> animations) {
        if (VERSION.SDK_INT >= 21 && delay > 0) {
            Animator animator = ViewAnimationUtils.createCircularReveal(child, revealCenterX, revealCenterY, fromRadius, fromRadius);
            animator.setStartDelay(0);
            animator.setDuration(delay);
            animations.add(animator);
        }
    }

    private void createPostFillRadialExpansion(View child, long delay, long duration, long totalDuration, int revealCenterX, int revealCenterY, float toRadius, List<Animator> animations) {
        if (VERSION.SDK_INT >= 21 && delay + duration < totalDuration) {
            Animator animator = ViewAnimationUtils.createCircularReveal(child, revealCenterX, revealCenterY, toRadius, toRadius);
            animator.setStartDelay(delay + duration);
            animator.setDuration(totalDuration - (delay + duration));
            animations.add(animator);
        }
    }
}
