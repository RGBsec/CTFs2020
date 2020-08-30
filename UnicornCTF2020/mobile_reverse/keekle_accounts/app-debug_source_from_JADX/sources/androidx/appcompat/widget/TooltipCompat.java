package androidx.appcompat.widget;

import android.os.Build.VERSION;
import android.view.View;

public class TooltipCompat {
    public static void setTooltipText(View view, CharSequence tooltipText) {
        if (VERSION.SDK_INT >= 26) {
            view.setTooltipText(tooltipText);
        } else {
            TooltipCompatHandler.setTooltipText(view, tooltipText);
        }
    }

    private TooltipCompat() {
    }
}
