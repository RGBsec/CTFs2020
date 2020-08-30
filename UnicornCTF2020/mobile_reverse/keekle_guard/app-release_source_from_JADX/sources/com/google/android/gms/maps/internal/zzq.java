package com.google.android.gms.maps.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.maps.zzb;

public abstract class zzq extends zzb implements zzp {
    public zzq() {
        super("com.google.android.gms.maps.internal.IOnCameraMoveCanceledListener");
    }

    /* access modifiers changed from: protected */
    public final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i != 1) {
            return false;
        }
        onCameraMoveCanceled();
        parcel2.writeNoException();
        return true;
    }
}
