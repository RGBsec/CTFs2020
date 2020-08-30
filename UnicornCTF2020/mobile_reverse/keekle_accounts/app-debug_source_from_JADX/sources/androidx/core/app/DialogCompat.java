package androidx.core.app;

import android.app.Dialog;
import android.os.Build.VERSION;
import android.view.View;

public class DialogCompat {
    private DialogCompat() {
    }

    public static View requireViewById(Dialog dialog, int id) {
        if (VERSION.SDK_INT >= 28) {
            return dialog.requireViewById(id);
        }
        View view = dialog.findViewById(id);
        if (view != null) {
            return view;
        }
        throw new IllegalArgumentException("ID does not reference a View inside this Dialog");
    }
}
