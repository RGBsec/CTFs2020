package com.google.android.gms.maps.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzc;
import com.google.android.gms.maps.model.CameraPosition;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.LatLngBounds;

public final class zzb extends zza implements ICameraUpdateFactoryDelegate {
    zzb(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.ICameraUpdateFactoryDelegate");
    }

    public final IObjectWrapper zoomIn() throws RemoteException {
        Parcel zza = zza(1, zza());
        IObjectWrapper asInterface = Stub.asInterface(zza.readStrongBinder());
        zza.recycle();
        return asInterface;
    }

    public final IObjectWrapper zoomOut() throws RemoteException {
        Parcel zza = zza(2, zza());
        IObjectWrapper asInterface = Stub.asInterface(zza.readStrongBinder());
        zza.recycle();
        return asInterface;
    }

    public final IObjectWrapper scrollBy(float f, float f2) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zza.writeFloat(f2);
        Parcel zza2 = zza(3, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper zoomTo(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        Parcel zza2 = zza(4, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper zoomBy(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        Parcel zza2 = zza(5, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper zoomByWithFocus(float f, int i, int i2) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zza.writeInt(i);
        zza.writeInt(i2);
        Parcel zza2 = zza(6, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper newCameraPosition(CameraPosition cameraPosition) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) cameraPosition);
        Parcel zza2 = zza(7, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper newLatLng(LatLng latLng) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        Parcel zza2 = zza(8, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper newLatLngZoom(LatLng latLng, float f) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        zza.writeFloat(f);
        Parcel zza2 = zza(9, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper newLatLngBounds(LatLngBounds latLngBounds, int i) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLngBounds);
        zza.writeInt(i);
        Parcel zza2 = zza(10, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final IObjectWrapper newLatLngBoundsWithSize(LatLngBounds latLngBounds, int i, int i2, int i3) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLngBounds);
        zza.writeInt(i);
        zza.writeInt(i2);
        zza.writeInt(i3);
        Parcel zza2 = zza(11, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }
}
