package com.google.android.gms.maps.internal;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzc;
import com.google.android.gms.maps.StreetViewPanoramaOptions;

public final class zzbv extends zza implements IStreetViewPanoramaFragmentDelegate {
    zzbv(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IStreetViewPanoramaFragmentDelegate");
    }

    public final IStreetViewPanoramaDelegate getStreetViewPanorama() throws RemoteException {
        IStreetViewPanoramaDelegate iStreetViewPanoramaDelegate;
        Parcel zza = zza(1, zza());
        IBinder readStrongBinder = zza.readStrongBinder();
        if (readStrongBinder == null) {
            iStreetViewPanoramaDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IStreetViewPanoramaDelegate");
            if (queryLocalInterface instanceof IStreetViewPanoramaDelegate) {
                iStreetViewPanoramaDelegate = (IStreetViewPanoramaDelegate) queryLocalInterface;
            } else {
                iStreetViewPanoramaDelegate = new zzbu(readStrongBinder);
            }
        }
        zza.recycle();
        return iStreetViewPanoramaDelegate;
    }

    public final void onInflate(IObjectWrapper iObjectWrapper, StreetViewPanoramaOptions streetViewPanoramaOptions, Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzc.zza(zza, (Parcelable) streetViewPanoramaOptions);
        zzc.zza(zza, (Parcelable) bundle);
        zzb(2, zza);
    }

    public final void onCreate(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        zzb(3, zza);
    }

    public final IObjectWrapper onCreateView(IObjectWrapper iObjectWrapper, IObjectWrapper iObjectWrapper2, Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzc.zza(zza, (IInterface) iObjectWrapper2);
        zzc.zza(zza, (Parcelable) bundle);
        Parcel zza2 = zza(4, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final void onResume() throws RemoteException {
        zzb(5, zza());
    }

    public final void onPause() throws RemoteException {
        zzb(6, zza());
    }

    public final void onDestroyView() throws RemoteException {
        zzb(7, zza());
    }

    public final void onDestroy() throws RemoteException {
        zzb(8, zza());
    }

    public final void onLowMemory() throws RemoteException {
        zzb(9, zza());
    }

    public final void onSaveInstanceState(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        Parcel zza2 = zza(10, zza);
        if (zza2.readInt() != 0) {
            bundle.readFromParcel(zza2);
        }
        zza2.recycle();
    }

    public final boolean isReady() throws RemoteException {
        Parcel zza = zza(11, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void getStreetViewPanoramaAsync(zzbp zzbp) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbp);
        zzb(12, zza);
    }

    public final void onStart() throws RemoteException {
        zzb(13, zza());
    }

    public final void onStop() throws RemoteException {
        zzb(14, zza());
    }
}
