package com.google.android.gms.maps.model;

import com.google.android.gms.common.internal.Preconditions;

public final class CustomCap extends Cap {
    public final BitmapDescriptor bitmapDescriptor;
    public final float refWidth;

    public CustomCap(BitmapDescriptor bitmapDescriptor2, float f) {
        BitmapDescriptor bitmapDescriptor3 = (BitmapDescriptor) Preconditions.checkNotNull(bitmapDescriptor2, "bitmapDescriptor must not be null");
        if (f > 0.0f) {
            super(bitmapDescriptor3, f);
            this.bitmapDescriptor = bitmapDescriptor2;
            this.refWidth = f;
            return;
        }
        throw new IllegalArgumentException("refWidth must be positive");
    }

    public CustomCap(BitmapDescriptor bitmapDescriptor2) {
        this(bitmapDescriptor2, 10.0f);
    }

    public final String toString() {
        String valueOf = String.valueOf(this.bitmapDescriptor);
        float f = this.refWidth;
        StringBuilder sb = new StringBuilder(String.valueOf(valueOf).length() + 55);
        sb.append("[CustomCap: bitmapDescriptor=");
        sb.append(valueOf);
        sb.append(" refWidth=");
        sb.append(f);
        sb.append("]");
        return sb.toString();
    }
}
