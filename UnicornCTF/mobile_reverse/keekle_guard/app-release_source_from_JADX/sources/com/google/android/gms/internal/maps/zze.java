package com.google.android.gms.internal.maps;

import android.graphics.Bitmap;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;

public interface zze extends IInterface {
    IObjectWrapper zza(float f) throws RemoteException;

    IObjectWrapper zza(int i) throws RemoteException;

    IObjectWrapper zza(Bitmap bitmap) throws RemoteException;

    IObjectWrapper zza(String str) throws RemoteException;

    IObjectWrapper zzb(String str) throws RemoteException;

    IObjectWrapper zzc(String str) throws RemoteException;

    IObjectWrapper zzi() throws RemoteException;
}
