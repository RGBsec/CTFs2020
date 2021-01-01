package com.google.android.material.circularreveal;

import android.animation.Animator;
import android.animation.Animator.AnimatorListener;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.os.Build.VERSION;
import android.view.View;
import android.view.ViewAnimationUtils;
import com.google.android.material.circularreveal.CircularRevealWidget.CircularRevealEvaluator;
import com.google.android.material.circularreveal.CircularRevealWidget.CircularRevealProperty;
import com.google.android.material.circularreveal.CircularRevealWidget.RevealInfo;

public final class CircularRevealCompat {
    private CircularRevealCompat() {
    }

    public static Animator createCircularReveal(CircularRevealWidget view, float centerX, float centerY, float endRadius) {
        Animator revealInfoAnimator = ObjectAnimator.ofObject(view, CircularRevealProperty.CIRCULAR_REVEAL, CircularRevealEvaluator.CIRCULAR_REVEAL, new RevealInfo[]{new RevealInfo(centerX, centerY, endRadius)});
        if (VERSION.SDK_INT < 21) {
            return revealInfoAnimator;
        }
        RevealInfo revealInfo = view.getRevealInfo();
        if (revealInfo != null) {
            Animator circularRevealAnimator = ViewAnimationUtils.createCircularReveal((View) view, (int) centerX, (int) centerY, revealInfo.radius, endRadius);
            AnimatorSet set = new AnimatorSet();
            set.playTogether(new Animator[]{revealInfoAnimator, circularRevealAnimator});
            return set;
        }
        throw new IllegalStateException("Caller must set a non-null RevealInfo before calling this.");
    }

    public static Animator createCircularReveal(CircularRevealWidget view, float centerX, float centerY, float startRadius, float endRadius) {
        Animator revealInfoAnimator = ObjectAnimator.ofObject(view, CircularRevealProperty.CIRCULAR_REVEAL, CircularRevealEvaluator.CIRCULAR_REVEAL, new RevealInfo[]{new RevealInfo(centerX, centerY, startRadius), new RevealInfo(centerX, centerY, endRadius)});
        if (VERSION.SDK_INT < 21) {
            return revealInfoAnimator;
        }
        Animator circularRevealAnimator = ViewAnimationUtils.createCircularReveal((View) view, (int) centerX, (int) centerY, startRadius, endRadius);
        AnimatorSet set = new AnimatorSet();
        set.playTogether(new Animator[]{revealInfoAnimator, circularRevealAnimator});
        return set;
    }

    public static AnimatorListener createCircularRevealListener(final CircularRevealWidget view) {
        return new AnimatorListenerAdapter() {
            public void onAnimationStart(Animator animation) {
                view.buildCircularRevealCache();
            }

            public void onAnimationEnd(Animator animation) {
                view.destroyCircularRevealCache();
            }
        };
    }
}
