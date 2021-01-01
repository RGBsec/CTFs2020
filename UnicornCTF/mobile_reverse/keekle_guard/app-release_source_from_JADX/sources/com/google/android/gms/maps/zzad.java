package com.google.android.gms.maps;

import com.google.android.gms.maps.StreetViewPanorama.OnStreetViewPanoramaChangeListener;
import com.google.android.gms.maps.internal.zzbk;
import com.google.android.gms.maps.model.StreetViewPanoramaLocation;

final class zzad extends zzbk {
    private final /* synthetic */ OnStreetViewPanoramaChangeListener zzbp;

    zzad(StreetViewPanorama streetViewPanorama, OnStreetViewPanoramaChangeListener onStreetViewPanoramaChangeListener) {
        this.zzbp = onStreetViewPanoramaChangeListener;
    }

    public final void onStreetViewPanoramaChange(StreetViewPanoramaLocation streetViewPanoramaLocation) {
        this.zzbp.onStreetViewPanoramaChange(streetViewPanoramaLocation);
    }
}
