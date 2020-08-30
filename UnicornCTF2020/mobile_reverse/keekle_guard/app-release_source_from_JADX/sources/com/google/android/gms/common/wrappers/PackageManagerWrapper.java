package com.google.android.gms.common.wrappers;

import android.app.AppOpsManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Binder;
import android.os.Process;
import com.google.android.gms.common.util.PlatformVersion;

public class PackageManagerWrapper {
    private final Context zzhx;

    public PackageManagerWrapper(Context context) {
        this.zzhx = context;
    }

    public ApplicationInfo getApplicationInfo(String str, int i) throws NameNotFoundException {
        return this.zzhx.getPackageManager().getApplicationInfo(str, i);
    }

    public PackageInfo getPackageInfo(String str, int i) throws NameNotFoundException {
        return this.zzhx.getPackageManager().getPackageInfo(str, i);
    }

    public final PackageInfo zza(String str, int i, int i2) throws NameNotFoundException {
        return this.zzhx.getPackageManager().getPackageInfo(str, 64);
    }

    public final String[] getPackagesForUid(int i) {
        return this.zzhx.getPackageManager().getPackagesForUid(i);
    }

    public final boolean zzb(int i, String str) {
        if (PlatformVersion.isAtLeastKitKat()) {
            try {
                ((AppOpsManager) this.zzhx.getSystemService("appops")).checkPackage(i, str);
                return true;
            } catch (SecurityException unused) {
                return false;
            }
        } else {
            String[] packagesForUid = this.zzhx.getPackageManager().getPackagesForUid(i);
            if (!(str == null || packagesForUid == null)) {
                for (String equals : packagesForUid) {
                    if (str.equals(equals)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    public int checkCallingOrSelfPermission(String str) {
        return this.zzhx.checkCallingOrSelfPermission(str);
    }

    public int checkPermission(String str, String str2) {
        return this.zzhx.getPackageManager().checkPermission(str, str2);
    }

    public CharSequence getApplicationLabel(String str) throws NameNotFoundException {
        return this.zzhx.getPackageManager().getApplicationLabel(this.zzhx.getPackageManager().getApplicationInfo(str, 0));
    }

    public boolean isCallerInstantApp() {
        if (Binder.getCallingUid() == Process.myUid()) {
            return InstantApps.isInstantApp(this.zzhx);
        }
        if (PlatformVersion.isAtLeastO()) {
            String nameForUid = this.zzhx.getPackageManager().getNameForUid(Binder.getCallingUid());
            if (nameForUid != null) {
                return this.zzhx.getPackageManager().isInstantApp(nameForUid);
            }
        }
        return false;
    }
}
