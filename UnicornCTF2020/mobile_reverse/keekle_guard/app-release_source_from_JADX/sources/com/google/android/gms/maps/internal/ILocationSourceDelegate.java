package com.google.android.gms.maps.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.maps.zzb;

public interface ILocationSourceDelegate extends IInterface {

    public static abstract class zza extends zzb implements ILocationSourceDelegate {
        public zza() {
            super("com.google.android.gms.maps.internal.ILocationSourceDelegate");
        }

        /* access modifiers changed from: protected */
        public final boolean dispatchTransaction(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
            zzah zzah;
            if (i == 1) {
                IBinder readStrongBinder = parcel.readStrongBinder();
                if (readStrongBinder == null) {
                    zzah = null;
                } else {
                    IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IOnLocationChangeListener");
                    if (queryLocalInterface instanceof zzah) {
                        zzah = (zzah) queryLocalInterface;
                    } else {
                        zzah = new zzai(readStrongBinder);
                    }
                }
                activate(zzah);
            } else if (i != 2) {
                return false;
            } else {
                deactivate();
            }
            parcel2.writeNoException();
            return true;
        }
    }

    void activate(zzah zzah) throws RemoteException;

    void deactivate() throws RemoteException;
}
