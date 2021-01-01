package androidx.core.p005os;

import android.os.Build.VERSION;
import android.os.Trace;

/* renamed from: androidx.core.os.TraceCompat */
public final class TraceCompat {
    public static void beginSection(String sectionName) {
        if (VERSION.SDK_INT >= 18) {
            Trace.beginSection(sectionName);
        }
    }

    public static void endSection() {
        if (VERSION.SDK_INT >= 18) {
            Trace.endSection();
        }
    }

    private TraceCompat() {
    }
}
