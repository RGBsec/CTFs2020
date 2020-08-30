package com.google.android.gms.maps;

import com.google.android.gms.maps.StreetViewPanorama.OnStreetViewPanoramaLongClickListener;
import com.google.android.gms.maps.internal.zzbo;
import com.google.android.gms.maps.model.StreetViewPanoramaOrientation;

final class zzag extends zzbo {
    private final /* synthetic */ OnStreetViewPanoramaLongClickListener zzbs;

    zzag(StreetViewPanorama streetViewPanorama, OnStreetViewPanoramaLongClickListener onStreetViewPanoramaLongClickListener) {
        this.zzbs = onStreetViewPanoramaLongClickListener;
    }

    public final void onStreetViewPanoramaLongClick(StreetViewPanoramaOrientation streetViewPanoramaOrientation) {
        this.zzbs.onStreetViewPanoramaLongClick(streetViewPanoramaOrientation);
    }
}
