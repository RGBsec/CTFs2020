package com.google.android.gms.maps.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.maps.zzb;

public abstract class zzd extends zzb implements zzc {
    public zzd() {
        super("com.google.android.gms.maps.internal.ICancelableCallback");
    }

    /* access modifiers changed from: protected */
    public final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i == 1) {
            onFinish();
        } else if (i != 2) {
            return false;
        } else {
            onCancel();
        }
        parcel2.writeNoException();
        return true;
    }
}
