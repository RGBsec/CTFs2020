package androidx.core.view;

import android.os.Build.VERSION;
import android.view.Menu;
import android.view.MenuItem;
import androidx.core.internal.view.SupportMenu;

public final class MenuCompat {
    @Deprecated
    public static void setShowAsAction(MenuItem item, int actionEnum) {
        item.setShowAsAction(actionEnum);
    }

    public static void setGroupDividerEnabled(Menu menu, boolean enabled) {
        if (menu instanceof SupportMenu) {
            ((SupportMenu) menu).setGroupDividerEnabled(enabled);
        } else if (VERSION.SDK_INT >= 28) {
            menu.setGroupDividerEnabled(enabled);
        }
    }

    private MenuCompat() {
    }
}
