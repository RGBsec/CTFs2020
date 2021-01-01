package com.google.android.gms.internal.maps;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

public final class zzae extends zza implements zzac {
    zzae(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.model.internal.ITileOverlayDelegate");
    }

    public final void remove() throws RemoteException {
        zzb(1, zza());
    }

    public final void clearTileCache() throws RemoteException {
        zzb(2, zza());
    }

    public final String getId() throws RemoteException {
        Parcel zza = zza(3, zza());
        String readString = zza.readString();
        zza.recycle();
        return readString;
    }

    public final void setZIndex(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(4, zza);
    }

    public final float getZIndex() throws RemoteException {
        Parcel zza = zza(5, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }

    public final void setVisible(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(6, zza);
    }

    public final boolean isVisible() throws RemoteException {
        Parcel zza = zza(7, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean zza(zzac zzac) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzac);
        Parcel zza2 = zza(8, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final int zzj() throws RemoteException {
        Parcel zza = zza(9, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final void setFadeIn(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(10, zza);
    }

    public final boolean getFadeIn() throws RemoteException {
        Parcel zza = zza(11, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setTransparency(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(12, zza);
    }

    public final float getTransparency() throws RemoteException {
        Parcel zza = zza(13, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }
}
