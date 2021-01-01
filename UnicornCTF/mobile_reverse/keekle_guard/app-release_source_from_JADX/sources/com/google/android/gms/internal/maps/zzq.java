package com.google.android.gms.internal.maps;

import android.os.IInterface;
import android.os.RemoteException;

public interface zzq extends IInterface {
    void activate() throws RemoteException;

    String getName() throws RemoteException;

    String getShortName() throws RemoteException;

    boolean zzb(zzq zzq) throws RemoteException;

    int zzj() throws RemoteException;
}
