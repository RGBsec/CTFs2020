package androidx.core.content.p004pm;

import android.content.pm.PackageInfo;
import android.os.Build.VERSION;

/* renamed from: androidx.core.content.pm.PackageInfoCompat */
public final class PackageInfoCompat {
    public static long getLongVersionCode(PackageInfo info) {
        if (VERSION.SDK_INT >= 28) {
            return info.getLongVersionCode();
        }
        return (long) info.versionCode;
    }

    private PackageInfoCompat() {
    }
}
