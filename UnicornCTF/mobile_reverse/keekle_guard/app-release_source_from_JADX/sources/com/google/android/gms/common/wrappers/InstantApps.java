package com.google.android.gms.common.wrappers;

import android.content.Context;
import com.google.android.gms.common.util.PlatformVersion;

public class InstantApps {
    private static Context zzhv;
    private static Boolean zzhw;

    public static synchronized boolean isInstantApp(Context context) {
        synchronized (InstantApps.class) {
            Context applicationContext = context.getApplicationContext();
            if (zzhv == null || zzhw == null || zzhv != applicationContext) {
                zzhw = null;
                if (PlatformVersion.isAtLeastO()) {
                    zzhw = Boolean.valueOf(applicationContext.getPackageManager().isInstantApp());
                } else {
                    try {
                        context.getClassLoader().loadClass("com.google.android.instantapps.supervisor.InstantAppsRuntime");
                        zzhw = Boolean.valueOf(true);
                    } catch (ClassNotFoundException unused) {
                        zzhw = Boolean.valueOf(false);
                    }
                }
                zzhv = applicationContext;
                boolean booleanValue = zzhw.booleanValue();
                return booleanValue;
            }
            boolean booleanValue2 = zzhw.booleanValue();
            return booleanValue2;
        }
    }
}
