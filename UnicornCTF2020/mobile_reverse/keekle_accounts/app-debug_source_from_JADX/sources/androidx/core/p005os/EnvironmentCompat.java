package androidx.core.p005os;

import android.os.Build.VERSION;
import android.os.Environment;
import android.util.Log;
import java.io.File;
import java.io.IOException;

/* renamed from: androidx.core.os.EnvironmentCompat */
public final class EnvironmentCompat {
    public static final String MEDIA_UNKNOWN = "unknown";
    private static final String TAG = "EnvironmentCompat";

    public static String getStorageState(File path) {
        if (VERSION.SDK_INT >= 19) {
            return Environment.getStorageState(path);
        }
        try {
            if (path.getCanonicalPath().startsWith(Environment.getExternalStorageDirectory().getCanonicalPath())) {
                return Environment.getExternalStorageState();
            }
        } catch (IOException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to resolve canonical path: ");
            sb.append(e);
            Log.w(TAG, sb.toString());
        }
        return MEDIA_UNKNOWN;
    }

    private EnvironmentCompat() {
    }
}
