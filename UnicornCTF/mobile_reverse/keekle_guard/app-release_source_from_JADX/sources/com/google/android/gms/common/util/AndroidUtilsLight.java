package com.google.android.gms.common.util;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import com.google.android.gms.common.wrappers.Wrappers;
import com.google.android.gms.internal.common.zzg;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AndroidUtilsLight {
    private static volatile int zzgf = -1;

    public static byte[] getPackageCertificateHashBytes(Context context, String str) throws NameNotFoundException {
        PackageInfo packageInfo = Wrappers.packageManager(context).getPackageInfo(str, 64);
        if (packageInfo.signatures != null && packageInfo.signatures.length == 1) {
            MessageDigest zzj = zzj("SHA1");
            if (zzj != null) {
                return zzj.digest(packageInfo.signatures[0].toByteArray());
            }
        }
        return null;
    }

    public static MessageDigest zzj(String str) {
        int i = 0;
        while (i < 2) {
            try {
                MessageDigest instance = MessageDigest.getInstance(str);
                if (instance != null) {
                    return instance;
                }
                i++;
            } catch (NoSuchAlgorithmException unused) {
            }
        }
        return null;
    }

    @Deprecated
    public static Context getDeviceProtectedStorageContext(Context context) {
        return zzg.zzam() ? zzg.getDeviceProtectedStorageContext(context) : context;
    }
}
