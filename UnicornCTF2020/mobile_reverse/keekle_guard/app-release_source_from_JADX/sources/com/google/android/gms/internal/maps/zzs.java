package com.google.android.gms.internal.maps;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

public final class zzs extends zza implements zzq {
    zzs(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.model.internal.IIndoorLevelDelegate");
    }

    public final String getName() throws RemoteException {
        Parcel zza = zza(1, zza());
        String readString = zza.readString();
        zza.recycle();
        return readString;
    }

    public final String getShortName() throws RemoteException {
        Parcel zza = zza(2, zza());
        String readString = zza.readString();
        zza.recycle();
        return readString;
    }

    public final void activate() throws RemoteException {
        zzb(3, zza());
    }

    public final boolean zzb(zzq zzq) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzq);
        Parcel zza2 = zza(4, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final int zzj() throws RemoteException {
        Parcel zza = zza(5, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }
}
