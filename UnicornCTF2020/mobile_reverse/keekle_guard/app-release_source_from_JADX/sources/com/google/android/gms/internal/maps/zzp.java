package com.google.android.gms.internal.maps;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import java.util.ArrayList;
import java.util.List;

public final class zzp extends zza implements zzn {
    zzp(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.model.internal.IIndoorBuildingDelegate");
    }

    public final int getActiveLevelIndex() throws RemoteException {
        Parcel zza = zza(1, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final int getDefaultLevelIndex() throws RemoteException {
        Parcel zza = zza(2, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final List<IBinder> getLevels() throws RemoteException {
        Parcel zza = zza(3, zza());
        ArrayList createBinderArrayList = zza.createBinderArrayList();
        zza.recycle();
        return createBinderArrayList;
    }

    public final boolean isUnderground() throws RemoteException {
        Parcel zza = zza(4, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean zzb(zzn zzn) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzn);
        Parcel zza2 = zza(5, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final int zzj() throws RemoteException {
        Parcel zza = zza(6, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }
}
