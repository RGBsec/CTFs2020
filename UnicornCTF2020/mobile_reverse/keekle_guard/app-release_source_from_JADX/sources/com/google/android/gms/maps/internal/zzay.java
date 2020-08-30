package com.google.android.gms.maps.internal;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.internal.maps.zzb;

public abstract class zzay extends zzb implements zzax {
    public zzay() {
        super("com.google.android.gms.maps.internal.IOnMyLocationChangeListener");
    }

    /* access modifiers changed from: protected */
    public final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i != 1) {
            return false;
        }
        zza(Stub.asInterface(parcel.readStrongBinder()));
        parcel2.writeNoException();
        return true;
    }
}
