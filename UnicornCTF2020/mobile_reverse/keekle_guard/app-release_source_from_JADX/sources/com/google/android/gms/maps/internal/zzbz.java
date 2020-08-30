package com.google.android.gms.maps.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.dynamic.ObjectWrapper;
import com.google.android.gms.dynamite.DynamiteModule;
import com.google.android.gms.maps.model.RuntimeRemoteException;

public class zzbz {
    private static final String TAG = zzbz.class.getSimpleName();
    private static Context zzck = null;
    private static zze zzcl;

    public static zze zza(Context context) throws GooglePlayServicesNotAvailableException {
        zze zze;
        Preconditions.checkNotNull(context);
        zze zze2 = zzcl;
        if (zze2 != null) {
            return zze2;
        }
        int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(context, 13400000);
        if (isGooglePlayServicesAvailable == 0) {
            Log.i(TAG, "Making Creator dynamically");
            IBinder iBinder = (IBinder) zza(zzb(context).getClassLoader(), "com.google.android.gms.maps.internal.CreatorImpl");
            if (iBinder == null) {
                zze = null;
            } else {
                IInterface queryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.maps.internal.ICreator");
                if (queryLocalInterface instanceof zze) {
                    zze = (zze) queryLocalInterface;
                } else {
                    zze = new zzf(iBinder);
                }
            }
            zzcl = zze;
            try {
                zze.zza(ObjectWrapper.wrap(zzb(context).getResources()), GooglePlayServicesUtil.GOOGLE_PLAY_SERVICES_VERSION_CODE);
                return zzcl;
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        } else {
            throw new GooglePlayServicesNotAvailableException(isGooglePlayServicesAvailable);
        }
    }

    private static Context zzb(Context context) {
        Context context2 = zzck;
        if (context2 != null) {
            return context2;
        }
        Context zzc = zzc(context);
        zzck = zzc;
        return zzc;
    }

    private static Context zzc(Context context) {
        try {
            return DynamiteModule.load(context, DynamiteModule.PREFER_REMOTE, "com.google.android.gms.maps_dynamite").getModuleContext();
        } catch (Exception e) {
            Log.e(TAG, "Failed to load maps module, use legacy", e);
            return GooglePlayServicesUtil.getRemoteContext(context);
        }
    }

    private static <T> T zza(ClassLoader classLoader, String str) {
        try {
            return zza(((ClassLoader) Preconditions.checkNotNull(classLoader)).loadClass(str));
        } catch (ClassNotFoundException unused) {
            String str2 = "Unable to find dynamic class ";
            String valueOf = String.valueOf(str);
            throw new IllegalStateException(valueOf.length() != 0 ? str2.concat(valueOf) : new String(str2));
        }
    }

    private static <T> T zza(Class<?> cls) {
        try {
            return cls.newInstance();
        } catch (InstantiationException unused) {
            String str = "Unable to instantiate the dynamic class ";
            String valueOf = String.valueOf(cls.getName());
            throw new IllegalStateException(valueOf.length() != 0 ? str.concat(valueOf) : new String(str));
        } catch (IllegalAccessException unused2) {
            String str2 = "Unable to call the default constructor of ";
            String valueOf2 = String.valueOf(cls.getName());
            throw new IllegalStateException(valueOf2.length() != 0 ? str2.concat(valueOf2) : new String(str2));
        }
    }
}
