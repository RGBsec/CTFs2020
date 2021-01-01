package com.google.android.gms.security;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources.NotFoundException;
import android.util.Log;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.common.GooglePlayServicesUtilLight;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.util.CrashUtils;
import com.google.android.gms.dynamite.DynamiteModule;
import com.google.android.gms.dynamite.DynamiteModule.LoadingException;
import java.lang.reflect.Method;

public class ProviderInstaller {
    public static final String PROVIDER_NAME = "GmsCore_OpenSSL";
    private static final Object lock = new Object();
    /* access modifiers changed from: private */
    public static final GoogleApiAvailabilityLight zziv = GoogleApiAvailabilityLight.getInstance();
    private static Method zziw = null;

    public interface ProviderInstallListener {
        void onProviderInstallFailed(int i, Intent intent);

        void onProviderInstalled();
    }

    public static void installIfNeeded(Context context) throws GooglePlayServicesRepairableException, GooglePlayServicesNotAvailableException {
        Preconditions.checkNotNull(context, "Context must not be null");
        zziv.verifyGooglePlayServicesIsAvailable(context, 11925000);
        Context zzk = zzk(context);
        if (zzk == null) {
            zzk = zzl(context);
        }
        if (zzk != null) {
            synchronized (lock) {
                try {
                    if (zziw == null) {
                        zziw = zzk.getClassLoader().loadClass("com.google.android.gms.common.security.ProviderInstallerImpl").getMethod("insertProvider", new Class[]{Context.class});
                    }
                    zziw.invoke(null, new Object[]{zzk});
                } catch (Exception e) {
                    Throwable cause = e.getCause();
                    if (Log.isLoggable("ProviderInstaller", 6)) {
                        String str = "ProviderInstaller";
                        String str2 = "Failed to install provider: ";
                        String valueOf = String.valueOf(cause == 0 ? e.getMessage() : cause.getMessage());
                        Log.e(str, valueOf.length() != 0 ? str2.concat(valueOf) : new String(str2));
                    }
                    CrashUtils.addDynamiteErrorToDropBox(context, cause == 0 ? e : cause);
                    throw new GooglePlayServicesNotAvailableException(8);
                } catch (Throwable th) {
                    throw th;
                }
            }
            return;
        }
        Log.e("ProviderInstaller", "Failed to get remote context");
        throw new GooglePlayServicesNotAvailableException(8);
    }

    public static void installIfNeededAsync(Context context, ProviderInstallListener providerInstallListener) {
        Preconditions.checkNotNull(context, "Context must not be null");
        Preconditions.checkNotNull(providerInstallListener, "Listener must not be null");
        Preconditions.checkMainThread("Must be called on the UI thread");
        new zza(context, providerInstallListener).execute(new Void[0]);
    }

    private static Context zzk(Context context) {
        try {
            return DynamiteModule.load(context, DynamiteModule.PREFER_HIGHEST_OR_LOCAL_VERSION_NO_FORCE_STAGING, "providerinstaller").getModuleContext();
        } catch (LoadingException e) {
            String str = "Failed to load providerinstaller module: ";
            String valueOf = String.valueOf(e.getMessage());
            Log.w("ProviderInstaller", valueOf.length() != 0 ? str.concat(valueOf) : new String(str));
            return null;
        }
    }

    private static Context zzl(Context context) {
        try {
            return GooglePlayServicesUtilLight.getRemoteContext(context);
        } catch (NotFoundException e) {
            String str = "Failed to load GMS Core context for providerinstaller: ";
            String valueOf = String.valueOf(e.getMessage());
            Log.w("ProviderInstaller", valueOf.length() != 0 ? str.concat(valueOf) : new String(str));
            CrashUtils.addDynamiteErrorToDropBox(context, e);
            return null;
        }
    }
}
