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

public final class zzk extends zza implements IMapViewDelegate {
    zzk(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IMapViewDelegate");
    }

    public final IGoogleMapDelegate getMap() throws RemoteException {
        IGoogleMapDelegate iGoogleMapDelegate;
        Parcel zza = zza(1, zza());
        IBinder readStrongBinder = zza.readStrongBinder();
        if (readStrongBinder == null) {
            iGoogleMapDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IGoogleMapDelegate");
            if (queryLocalInterface instanceof IGoogleMapDelegate) {
                iGoogleMapDelegate = (IGoogleMapDelegate) queryLocalInterface;
            } else {
                iGoogleMapDelegate = new zzg(readStrongBinder);
            }
        }
        zza.recycle();
        return iGoogleMapDelegate;
    }

    public final void onCreate(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        zzb(2, zza);
    }

    public final void onResume() throws RemoteException {
        zzb(3, zza());
    }

    public final void onPause() throws RemoteException {
        zzb(4, zza());
    }

    public final void onDestroy() throws RemoteException {
        zzb(5, zza());
    }

    public final void onLowMemory() throws RemoteException {
        zzb(6, zza());
    }

    public final void onSaveInstanceState(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        Parcel zza2 = zza(7, zza);
        if (zza2.readInt() != 0) {
            bundle.readFromParcel(zza2);
        }
        zza2.recycle();
    }

    public final IObjectWrapper getView() throws RemoteException {
        Parcel zza = zza(8, zza());
        IObjectWrapper asInterface = Stub.asInterface(zza.readStrongBinder());
        zza.recycle();
        return asInterface;
    }

    public final void getMapAsync(zzap zzap) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzap);
        zzb(9, zza);
    }

    public final void onEnterAmbient(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        zzb(10, zza);
    }

    public final void onExitAmbient() throws RemoteException {
        zzb(11, zza());
    }

    public final void onStart() throws RemoteException {
        zzb(12, zza());
    }

    public final void onStop() throws RemoteException {
        zzb(13, zza());
    }
}
