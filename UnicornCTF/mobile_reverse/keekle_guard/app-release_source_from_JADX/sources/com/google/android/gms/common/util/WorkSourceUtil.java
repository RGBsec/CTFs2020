package com.google.android.gms.common.util;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Process;
import android.os.WorkSource;
import android.util.Log;
import com.google.android.gms.common.wrappers.Wrappers;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class WorkSourceUtil {
    private static final int zzhj = Process.myUid();
    private static final Method zzhk = zzx();
    private static final Method zzhl = zzy();
    private static final Method zzhm = zzz();
    private static final Method zzhn = zzaa();
    private static final Method zzho = zzab();
    private static final Method zzhp = zzac();
    private static final Method zzhq = zzad();

    private WorkSourceUtil() {
    }

    private static WorkSource zza(int i, String str) {
        WorkSource workSource = new WorkSource();
        zza(workSource, i, str);
        return workSource;
    }

    public static WorkSource fromPackage(Context context, String str) {
        String str2 = "WorkSourceUtil";
        if (!(context == null || context.getPackageManager() == null || str == null)) {
            try {
                ApplicationInfo applicationInfo = Wrappers.packageManager(context).getApplicationInfo(str, 0);
                if (applicationInfo != null) {
                    return zza(applicationInfo.uid, str);
                }
                String str3 = "Could not get applicationInfo from package: ";
                String valueOf = String.valueOf(str);
                Log.e(str2, valueOf.length() != 0 ? str3.concat(valueOf) : new String(str3));
                return null;
            } catch (NameNotFoundException unused) {
                String str4 = "Could not find package: ";
                String valueOf2 = String.valueOf(str);
                Log.e(str2, valueOf2.length() != 0 ? str4.concat(valueOf2) : new String(str4));
            }
        }
        return null;
    }

    private static void zza(WorkSource workSource, int i, String str) {
        String str2 = "Unable to assign blame through WorkSource";
        String str3 = "WorkSourceUtil";
        if (zzhl != null) {
            if (str == null) {
                str = "";
            }
            try {
                zzhl.invoke(workSource, new Object[]{Integer.valueOf(i), str});
            } catch (Exception e) {
                Log.wtf(str3, str2, e);
            }
        } else {
            Method method = zzhk;
            if (method != null) {
                try {
                    method.invoke(workSource, new Object[]{Integer.valueOf(i)});
                } catch (Exception e2) {
                    Log.wtf(str3, str2, e2);
                }
            }
        }
    }

    public static WorkSource fromPackageAndModuleExperimentalPi(Context context, String str, String str2) {
        String str3 = "WorkSourceUtil";
        if (context == null || context.getPackageManager() == null || str2 == null || str == null) {
            Log.w(str3, "Unexpected null arguments");
            return null;
        }
        int zzd = zzd(context, str);
        if (zzd < 0) {
            return null;
        }
        WorkSource workSource = new WorkSource();
        Method method = zzhp;
        if (method == null || zzhq == null) {
            zza(workSource, zzd, str);
        } else {
            try {
                Object invoke = method.invoke(workSource, new Object[0]);
                if (zzd != zzhj) {
                    zzhq.invoke(invoke, new Object[]{Integer.valueOf(zzd), str});
                }
                zzhq.invoke(invoke, new Object[]{Integer.valueOf(zzhj), str2});
            } catch (Exception e) {
                Log.w(str3, "Unable to assign chained blame through WorkSource", e);
            }
        }
        return workSource;
    }

    private static int zza(WorkSource workSource) {
        Method method = zzhm;
        if (method != null) {
            try {
                return ((Integer) method.invoke(workSource, new Object[0])).intValue();
            } catch (Exception e) {
                Log.wtf("WorkSourceUtil", "Unable to assign blame through WorkSource", e);
            }
        }
        return 0;
    }

    private static String zza(WorkSource workSource, int i) {
        Method method = zzho;
        if (method != null) {
            try {
                return (String) method.invoke(workSource, new Object[]{Integer.valueOf(i)});
            } catch (Exception e) {
                Log.wtf("WorkSourceUtil", "Unable to assign blame through WorkSource", e);
            }
        }
        return null;
    }

    public static List<String> getNames(WorkSource workSource) {
        int zza = workSource == null ? 0 : zza(workSource);
        if (zza == 0) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < zza; i++) {
            String zza2 = zza(workSource, i);
            if (!Strings.isEmptyOrWhitespace(zza2)) {
                arrayList.add(zza2);
            }
        }
        return arrayList;
    }

    public static boolean hasWorkSourcePermission(Context context) {
        if (context == null || context.getPackageManager() == null) {
            return false;
        }
        if (Wrappers.packageManager(context).checkPermission("android.permission.UPDATE_DEVICE_STATS", context.getPackageName()) == 0) {
            return true;
        }
        return false;
    }

    private static int zzd(Context context, String str) {
        String str2 = "WorkSourceUtil";
        try {
            ApplicationInfo applicationInfo = Wrappers.packageManager(context).getApplicationInfo(str, 0);
            if (applicationInfo != null) {
                return applicationInfo.uid;
            }
            String str3 = "Could not get applicationInfo from package: ";
            String valueOf = String.valueOf(str);
            Log.e(str2, valueOf.length() != 0 ? str3.concat(valueOf) : new String(str3));
            return -1;
        } catch (NameNotFoundException unused) {
            String str4 = "Could not find package: ";
            String valueOf2 = String.valueOf(str);
            Log.e(str2, valueOf2.length() != 0 ? str4.concat(valueOf2) : new String(str4));
            return -1;
        }
    }

    private static Method zzx() {
        try {
            return WorkSource.class.getMethod("add", new Class[]{Integer.TYPE});
        } catch (Exception unused) {
            return null;
        }
    }

    private static Method zzy() {
        if (PlatformVersion.isAtLeastJellyBeanMR2()) {
            try {
                return WorkSource.class.getMethod("add", new Class[]{Integer.TYPE, String.class});
            } catch (Exception unused) {
            }
        }
        return null;
    }

    private static Method zzz() {
        try {
            return WorkSource.class.getMethod("size", new Class[0]);
        } catch (Exception unused) {
            return null;
        }
    }

    private static Method zzaa() {
        try {
            return WorkSource.class.getMethod("get", new Class[]{Integer.TYPE});
        } catch (Exception unused) {
            return null;
        }
    }

    private static Method zzab() {
        if (PlatformVersion.isAtLeastJellyBeanMR2()) {
            try {
                return WorkSource.class.getMethod("getName", new Class[]{Integer.TYPE});
            } catch (Exception unused) {
            }
        }
        return null;
    }

    private static final Method zzac() {
        if (PlatformVersion.isAtLeastP()) {
            try {
                return WorkSource.class.getMethod("createWorkChain", new Class[0]);
            } catch (Exception e) {
                Log.w("WorkSourceUtil", "Missing WorkChain API createWorkChain", e);
            }
        }
        return null;
    }

    private static final Method zzad() {
        if (PlatformVersion.isAtLeastP()) {
            try {
                return Class.forName("android.os.WorkSource$WorkChain").getMethod("addNode", new Class[]{Integer.TYPE, String.class});
            } catch (Exception e) {
                Log.w("WorkSourceUtil", "Missing WorkChain class", e);
            }
        }
        return null;
    }
}
