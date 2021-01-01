package com.google.android.gms.internal.common;

import android.content.Context;
import android.os.Build.VERSION;

public final class zzg {
    private static volatile boolean zziy = (!zzam());

    public static boolean zzam() {
        return VERSION.SDK_INT >= 24;
    }

    public static Context getDeviceProtectedStorageContext(Context context) {
        if (context.isDeviceProtectedStorage()) {
            return context;
        }
        return context.createDeviceProtectedStorageContext();
    }
}
