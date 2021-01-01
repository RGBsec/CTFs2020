package com.google.android.gms.maps;

import android.os.RemoteException;
import com.google.android.gms.maps.GoogleMap.OnPoiClickListener;
import com.google.android.gms.maps.internal.zzbc;
import com.google.android.gms.maps.model.PointOfInterest;

final class zzs extends zzbc {
    private final /* synthetic */ OnPoiClickListener zzaa;

    zzs(GoogleMap googleMap, OnPoiClickListener onPoiClickListener) {
        this.zzaa = onPoiClickListener;
    }

    public final void zza(PointOfInterest pointOfInterest) throws RemoteException {
        this.zzaa.onPoiClick(pointOfInterest);
    }
}
