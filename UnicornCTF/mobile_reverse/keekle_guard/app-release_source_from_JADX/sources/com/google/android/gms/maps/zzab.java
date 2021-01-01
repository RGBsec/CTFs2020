package com.google.android.gms.maps;

import android.os.RemoteException;
import com.google.android.gms.maps.internal.IGoogleMapDelegate;
import com.google.android.gms.maps.internal.zzaq;

final class zzab extends zzaq {
    private final /* synthetic */ OnMapReadyCallback zzbc;

    zzab(zza zza, OnMapReadyCallback onMapReadyCallback) {
        this.zzbc = onMapReadyCallback;
    }

    public final void zza(IGoogleMapDelegate iGoogleMapDelegate) throws RemoteException {
        this.zzbc.onMapReady(new GoogleMap(iGoogleMapDelegate));
    }
}
