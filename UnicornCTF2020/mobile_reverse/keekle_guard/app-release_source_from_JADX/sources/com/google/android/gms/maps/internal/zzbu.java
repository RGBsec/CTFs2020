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
import com.google.android.gms.maps.model.StreetViewPanoramaCamera;
import com.google.android.gms.maps.model.StreetViewPanoramaLocation;
import com.google.android.gms.maps.model.StreetViewPanoramaOrientation;
import com.google.android.gms.maps.model.StreetViewSource;

public final class zzbu extends zza implements IStreetViewPanoramaDelegate {
    zzbu(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IStreetViewPanoramaDelegate");
    }

    public final void enableZoom(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(1, zza);
    }

    public final void enablePanning(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(2, zza);
    }

    public final void enableUserNavigation(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(3, zza);
    }

    public final void enableStreetNames(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(4, zza);
    }

    public final boolean isZoomGesturesEnabled() throws RemoteException {
        Parcel zza = zza(5, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isPanningGesturesEnabled() throws RemoteException {
        Parcel zza = zza(6, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isUserNavigationEnabled() throws RemoteException {
        Parcel zza = zza(7, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isStreetNamesEnabled() throws RemoteException {
        Parcel zza = zza(8, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void animateTo(StreetViewPanoramaCamera streetViewPanoramaCamera, long j) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) streetViewPanoramaCamera);
        zza.writeLong(j);
        zzb(9, zza);
    }

    public final StreetViewPanoramaCamera getPanoramaCamera() throws RemoteException {
        Parcel zza = zza(10, zza());
        StreetViewPanoramaCamera streetViewPanoramaCamera = (StreetViewPanoramaCamera) zzc.zza(zza, StreetViewPanoramaCamera.CREATOR);
        zza.recycle();
        return streetViewPanoramaCamera;
    }

    public final void setPositionWithID(String str) throws RemoteException {
        Parcel zza = zza();
        zza.writeString(str);
        zzb(11, zza);
    }

    public final void setPosition(LatLng latLng) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        zzb(12, zza);
    }

    public final void setPositionWithRadius(LatLng latLng, int i) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        zza.writeInt(i);
        zzb(13, zza);
    }

    public final StreetViewPanoramaLocation getStreetViewPanoramaLocation() throws RemoteException {
        Parcel zza = zza(14, zza());
        StreetViewPanoramaLocation streetViewPanoramaLocation = (StreetViewPanoramaLocation) zzc.zza(zza, StreetViewPanoramaLocation.CREATOR);
        zza.recycle();
        return streetViewPanoramaLocation;
    }

    public final void setOnStreetViewPanoramaChangeListener(zzbj zzbj) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbj);
        zzb(15, zza);
    }

    public final void setOnStreetViewPanoramaCameraChangeListener(zzbh zzbh) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbh);
        zzb(16, zza);
    }

    public final void setOnStreetViewPanoramaClickListener(zzbl zzbl) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbl);
        zzb(17, zza);
    }

    public final StreetViewPanoramaOrientation pointToOrientation(IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        Parcel zza2 = zza(18, zza);
        StreetViewPanoramaOrientation streetViewPanoramaOrientation = (StreetViewPanoramaOrientation) zzc.zza(zza2, StreetViewPanoramaOrientation.CREATOR);
        zza2.recycle();
        return streetViewPanoramaOrientation;
    }

    public final IObjectWrapper orientationToPoint(StreetViewPanoramaOrientation streetViewPanoramaOrientation) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) streetViewPanoramaOrientation);
        Parcel zza2 = zza(19, zza);
        IObjectWrapper asInterface = Stub.asInterface(zza2.readStrongBinder());
        zza2.recycle();
        return asInterface;
    }

    public final void setOnStreetViewPanoramaLongClickListener(zzbn zzbn) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbn);
        zzb(20, zza);
    }

    public final void setPositionWithSource(LatLng latLng, StreetViewSource streetViewSource) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        zzc.zza(zza, (Parcelable) streetViewSource);
        zzb(21, zza);
    }

    public final void setPositionWithRadiusAndSource(LatLng latLng, int i, StreetViewSource streetViewSource) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLng);
        zza.writeInt(i);
        zzc.zza(zza, (Parcelable) streetViewSource);
        zzb(22, zza);
    }
}
