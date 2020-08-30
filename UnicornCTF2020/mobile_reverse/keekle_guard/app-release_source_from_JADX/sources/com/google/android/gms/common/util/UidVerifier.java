package com.google.android.gms.common.util;

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;
import com.google.android.gms.common.GoogleSignatureVerifier;
import com.google.android.gms.common.wrappers.Wrappers;

public final class UidVerifier {
    private UidVerifier() {
    }

    public static boolean isGooglePlayServicesUid(Context context, int i) {
        String str = "com.google.android.gms";
        if (!uidHasPackageName(context, i, str)) {
            return false;
        }
        try {
            return GoogleSignatureVerifier.getInstance(context).isGooglePublicSignedPackage(context.getPackageManager().getPackageInfo(str, 64));
        } catch (NameNotFoundException unused) {
            String str2 = "UidVerifier";
            if (Log.isLoggable(str2, 3)) {
                Log.d(str2, "Package manager can't find google play services package, defaulting to false");
            }
            return false;
        }
    }

    public static boolean uidHasPackageName(Context context, int i, String str) {
        return Wrappers.packageManager(context).zzb(i, str);
    }
}
