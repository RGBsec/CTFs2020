package com.google.android.material.drawable;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;

public class DrawableUtils {
    private DrawableUtils() {
    }

    public static PorterDuffColorFilter updateTintFilter(Drawable drawable, ColorStateList tint, Mode tintMode) {
        if (tint == null || tintMode == null) {
            return null;
        }
        return new PorterDuffColorFilter(tint.getColorForState(drawable.getState(), 0), tintMode);
    }
}
