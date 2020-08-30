package androidx.core.database.sqlite;

import android.database.sqlite.SQLiteCursor;
import android.os.Build.VERSION;

public final class SQLiteCursorCompat {
    private SQLiteCursorCompat() {
    }

    public static void setFillWindowForwardOnly(SQLiteCursor cursor, boolean fillWindowForwardOnly) {
        if (VERSION.SDK_INT >= 28) {
            cursor.setFillWindowForwardOnly(fillWindowForwardOnly);
        }
    }
}
