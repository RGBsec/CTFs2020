package com.google.android.gms.maps.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzc;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.VisibleRegion;

public final class zzbr extends zza implements IProjectionDelegate {
    zzbr(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IProjectionDelegate");
    }

    public final LatLng fromScreenLocation(IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        Parcel zza2 = zza(1, zza);
        LatLng latLng = (LatLng) zzc.zza(zza2, LatLng.CREATOR);
        zza2.recycle();
        return latLng;
    }

    public final IObjectWrapper toScreenLocation(LatLng latLng) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        Parcel zza2 = zza(2, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final VisibleRegion getVisibleRegion() throws RemoteException {
        Parcel zza = zza(3, zza());
        VisibleRegion visibleRegion = (VisibleRegion) zzc.zza(zza, VisibleRegion.CREATOR);
        zza.recycle();
        return visibleRegion;
    }
}
