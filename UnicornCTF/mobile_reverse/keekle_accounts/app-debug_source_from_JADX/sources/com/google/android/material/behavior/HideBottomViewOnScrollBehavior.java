package com.google.android.material.behavior;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.TimeInterpolator;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewPropertyAnimator;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior;
import com.google.android.material.animation.AnimationUtils;

public class HideBottomViewOnScrollBehavior<V extends View> extends Behavior<V> {
    protected static final int ENTER_ANIMATION_DURATION = 225;
    protected static final int EXIT_ANIMATION_DURATION = 175;
    private static final int STATE_SCROLLED_DOWN = 1;
    private static final int STATE_SCROLLED_UP = 2;
    /* access modifiers changed from: private */
    public ViewPropertyAnimator currentAnimator;
    private int currentState = 2;
    private int height = 0;

    public HideBottomViewOnScrollBehavior() {
    }

    public HideBottomViewOnScrollBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        this.height = child.getMeasuredHeight();
        return super.onLayoutChild(parent, child, layoutDirection);
    }

    public boolean onStartNestedScroll(CoordinatorLayout coordinatorLayout, V v, View directTargetChild, View target, int nestedScrollAxes) {
        return nestedScrollAxes == 2;
    }

    public void onNestedScroll(CoordinatorLayout coordinatorLayout, V child, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed) {
        if (this.currentState != 1 && dyConsumed > 0) {
            slideDown(child);
        } else if (this.currentState != 2 && dyConsumed < 0) {
            slideUp(child);
        }
    }

    /* access modifiers changed from: protected */
    public void slideUp(V child) {
        ViewPropertyAnimator viewPropertyAnimator = this.currentAnimator;
        if (viewPropertyAnimator != null) {
            viewPropertyAnimator.cancel();
            child.clearAnimation();
        }
        this.currentState = 2;
        animateChildTo(child, 0, 225, AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR);
    }

    /* access modifiers changed from: protected */
    public void slideDown(V child) {
        ViewPropertyAnimator viewPropertyAnimator = this.currentAnimator;
        if (viewPropertyAnimator != null) {
            viewPropertyAnimator.cancel();
            child.clearAnimation();
        }
        this.currentState = 1;
        animateChildTo(child, this.height, 175, AnimationUtils.FAST_OUT_LINEAR_IN_INTERPOLATOR);
    }

    private void animateChildTo(V child, int targetY, long duration, TimeInterpolator interpolator) {
        this.currentAnimator = child.animate().translationY((float) targetY).setInterpolator(interpolator).setDuration(duration).setListener(new AnimatorListenerAdapter() {
            public void onAnimationEnd(Animator animation) {
                HideBottomViewOnScrollBehavior.this.currentAnimator = null;
            }
        });
    }
}
