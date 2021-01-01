package androidx.transition;

import android.os.Build.VERSION;
import android.view.ViewGroup;

class ViewGroupUtils {
    static ViewGroupOverlayImpl getOverlay(ViewGroup group) {
        if (VERSION.SDK_INT >= 18) {
            return new ViewGroupOverlayApi18(group);
        }
        return ViewGroupOverlayApi14.createFrom(group);
    }

    static void suppressLayout(ViewGroup group, boolean suppress) {
        if (VERSION.SDK_INT >= 18) {
            ViewGroupUtilsApi18.suppressLayout(group, suppress);
        } else {
            ViewGroupUtilsApi14.suppressLayout(group, suppress);
        }
    }

    private ViewGroupUtils() {
    }
}
