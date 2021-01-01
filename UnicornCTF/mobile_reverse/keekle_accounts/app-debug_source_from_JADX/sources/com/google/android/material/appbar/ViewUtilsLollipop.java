package com.google.android.material.appbar;

import android.animation.AnimatorInflater;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewOutlineProvider;
import com.google.android.material.C0078R;
import com.google.android.material.internal.ThemeEnforcement;

class ViewUtilsLollipop {
    private static final int[] STATE_LIST_ANIM_ATTRS = {16843848};

    ViewUtilsLollipop() {
    }

    static void setBoundsViewOutlineProvider(View view) {
        view.setOutlineProvider(ViewOutlineProvider.BOUNDS);
    }

    static void setStateListAnimatorFromAttrs(View view, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        Context context = view.getContext();
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(context, attrs, STATE_LIST_ANIM_ATTRS, defStyleAttr, defStyleRes, new int[0]);
        try {
            if (a.hasValue(0)) {
                view.setStateListAnimator(AnimatorInflater.loadStateListAnimator(context, a.getResourceId(0, 0)));
            }
        } finally {
            a.recycle();
        }
    }

    static void setDefaultAppBarLayoutStateListAnimator(View view, float elevation) {
        int dur = view.getResources().getInteger(C0078R.integer.app_bar_elevation_anim_duration);
        StateListAnimator sla = new StateListAnimator();
        String str = "elevation";
        sla.addState(new int[]{16842766, C0078R.attr.state_liftable, -C0078R.attr.state_lifted}, ObjectAnimator.ofFloat(view, str, new float[]{0.0f}).setDuration((long) dur));
        sla.addState(new int[]{16842766}, ObjectAnimator.ofFloat(view, str, new float[]{elevation}).setDuration((long) dur));
        sla.addState(new int[0], ObjectAnimator.ofFloat(view, str, new float[]{0.0f}).setDuration(0));
        view.setStateListAnimator(sla);
    }
}
