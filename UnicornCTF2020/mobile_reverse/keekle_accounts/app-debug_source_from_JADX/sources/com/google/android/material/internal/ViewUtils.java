package com.google.android.material.internal;

import android.graphics.PorterDuff.Mode;
import android.view.View;
import androidx.core.view.ViewCompat;

public class ViewUtils {
    public static Mode parseTintMode(int value, Mode defaultMode) {
        if (value == 3) {
            return Mode.SRC_OVER;
        }
        if (value == 5) {
            return Mode.SRC_IN;
        }
        if (value == 9) {
            return Mode.SRC_ATOP;
        }
        switch (value) {
            case 14:
                return Mode.MULTIPLY;
            case 15:
                return Mode.SCREEN;
            case 16:
                return Mode.ADD;
            default:
                return defaultMode;
        }
    }

    public static boolean isLayoutRtl(View view) {
        return ViewCompat.getLayoutDirection(view) == 1;
    }
}
