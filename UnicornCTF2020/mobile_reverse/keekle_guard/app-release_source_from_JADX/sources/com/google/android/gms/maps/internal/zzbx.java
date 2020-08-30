package com.google.android.gms.maps.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzc;

public final class zzbx extends zza implements IUiSettingsDelegate {
    zzbx(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IUiSettingsDelegate");
    }

    public final void setZoomControlsEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(1, zza);
    }

    public final void setCompassEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(2, zza);
    }

    public final void setMyLocationButtonEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(3, zza);
    }

    public final void setScrollGesturesEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(4, zza);
    }

    public final void setZoomGesturesEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(5, zza);
    }

    public final void setTiltGesturesEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(6, zza);
    }

    public final void setRotateGesturesEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(7, zza);
    }

    public final void setAllGesturesEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(8, zza);
    }

    public final boolean isZoomControlsEnabled() throws RemoteException {
        Parcel zza = zza(9, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isCompassEnabled() throws RemoteException {
        Parcel zza = zza(10, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isMyLocationButtonEnabled() throws RemoteException {
        Parcel zza = zza(11, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isScrollGesturesEnabled() throws RemoteException {
        Parcel zza = zza(12, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isZoomGesturesEnabled() throws RemoteException {
        Parcel zza = zza(13, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isTiltGesturesEnabled() throws RemoteException {
        Parcel zza = zza(14, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean isRotateGesturesEnabled() throws RemoteException {
        Parcel zza = zza(15, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setIndoorLevelPickerEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(16, zza);
    }

    public final boolean isIndoorLevelPickerEnabled() throws RemoteException {
        Parcel zza = zza(17, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setMapToolbarEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(18, zza);
    }

    public final boolean isMapToolbarEnabled() throws RemoteException {
        Parcel zza = zza(19, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setScrollGesturesEnabledDuringRotateOrZoom(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(20, zza);
    }

    public final boolean isScrollGesturesEnabledDuringRotateOrZoom() throws RemoteException {
        Parcel zza = zza(21, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }
}
