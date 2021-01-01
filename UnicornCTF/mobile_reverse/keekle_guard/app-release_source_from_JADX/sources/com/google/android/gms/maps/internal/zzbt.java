package com.google.android.gms.maps.internal;

import android.graphics.Bitmap;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.internal.maps.zzb;
import com.google.android.gms.internal.maps.zzc;

public abstract class zzbt extends zzb implements zzbs {
    public zzbt() {
        super("com.google.android.gms.maps.internal.ISnapshotReadyCallback");
    }

    /* access modifiers changed from: protected */
    public final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i == 1) {
            onSnapshotReady((Bitmap) zzc.zza(parcel, Bitmap.CREATOR));
        } else if (i != 2) {
            return false;
        } else {
            zzb(Stub.asInterface(parcel.readStrongBinder()));
        }
        parcel2.writeNoException();
        return true;
    }
}
