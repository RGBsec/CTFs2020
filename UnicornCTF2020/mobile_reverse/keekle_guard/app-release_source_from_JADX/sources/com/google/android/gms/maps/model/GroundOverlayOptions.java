package com.google.android.gms.maps.model;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;

public final class GroundOverlayOptions extends AbstractSafeParcelable {
    public static final Creator<GroundOverlayOptions> CREATOR = new zzd();
    public static final float NO_DIMENSION = -1.0f;
    private float bearing;
    private float height;
    private float width;
    private float zzcs;
    private boolean zzct = true;
    private boolean zzcu = false;
    private BitmapDescriptor zzcx;
    private LatLng zzcy;
    private LatLngBounds zzcz;
    private float zzda = 0.0f;
    private float zzdb = 0.5f;
    private float zzdc = 0.5f;

    GroundOverlayOptions(IBinder iBinder, LatLng latLng, float f, float f2, LatLngBounds latLngBounds, float f3, float f4, boolean z, float f5, float f6, float f7, boolean z2) {
        this.zzcx = new BitmapDescriptor(Stub.asInterface(iBinder));
        this.zzcy = latLng;
        this.width = f;
        this.height = f2;
        this.zzcz = latLngBounds;
        this.bearing = f3;
        this.zzcs = f4;
        this.zzct = z;
        this.zzda = f5;
        this.zzdb = f6;
        this.zzdc = f7;
        this.zzcu = z2;
    }

    public GroundOverlayOptions() {
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeIBinder(parcel, 2, this.zzcx.zzb().asBinder(), false);
        SafeParcelWriter.writeParcelable(parcel, 3, getLocation(), i, false);
        SafeParcelWriter.writeFloat(parcel, 4, getWidth());
        SafeParcelWriter.writeFloat(parcel, 5, getHeight());
        SafeParcelWriter.writeParcelable(parcel, 6, getBounds(), i, false);
        SafeParcelWriter.writeFloat(parcel, 7, getBearing());
        SafeParcelWriter.writeFloat(parcel, 8, getZIndex());
        SafeParcelWriter.writeBoolean(parcel, 9, isVisible());
        SafeParcelWriter.writeFloat(parcel, 10, getTransparency());
        SafeParcelWriter.writeFloat(parcel, 11, getAnchorU());
        SafeParcelWriter.writeFloat(parcel, 12, getAnchorV());
        SafeParcelWriter.writeBoolean(parcel, 13, isClickable());
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    public final GroundOverlayOptions image(BitmapDescriptor bitmapDescriptor) {
        Preconditions.checkNotNull(bitmapDescriptor, "imageDescriptor must not be null");
        this.zzcx = bitmapDescriptor;
        return this;
    }

    public final GroundOverlayOptions anchor(float f, float f2) {
        this.zzdb = f;
        this.zzdc = f2;
        return this;
    }

    public final GroundOverlayOptions position(LatLng latLng, float f) {
        boolean z = true;
        Preconditions.checkState(this.zzcz == null, "Position has already been set using positionFromBounds");
        Preconditions.checkArgument(latLng != null, "Location must be specified");
        if (f < 0.0f) {
            z = false;
        }
        Preconditions.checkArgument(z, "Width must be non-negative");
        return zza(latLng, f, -1.0f);
    }

    public final GroundOverlayOptions position(LatLng latLng, float f, float f2) {
        boolean z = true;
        Preconditions.checkState(this.zzcz == null, "Position has already been set using positionFromBounds");
        Preconditions.checkArgument(latLng != null, "Location must be specified");
        Preconditions.checkArgument(f >= 0.0f, "Width must be non-negative");
        if (f2 < 0.0f) {
            z = false;
        }
        Preconditions.checkArgument(z, "Height must be non-negative");
        return zza(latLng, f, f2);
    }

    private final GroundOverlayOptions zza(LatLng latLng, float f, float f2) {
        this.zzcy = latLng;
        this.width = f;
        this.height = f2;
        return this;
    }

    public final GroundOverlayOptions positionFromBounds(LatLngBounds latLngBounds) {
        boolean z = this.zzcy == null;
        String valueOf = String.valueOf(this.zzcy);
        StringBuilder sb = new StringBuilder(String.valueOf(valueOf).length() + 46);
        sb.append("Position has already been set using position: ");
        sb.append(valueOf);
        Preconditions.checkState(z, sb.toString());
        this.zzcz = latLngBounds;
        return this;
    }

    public final GroundOverlayOptions bearing(float f) {
        this.bearing = ((f % 360.0f) + 360.0f) % 360.0f;
        return this;
    }

    public final GroundOverlayOptions zIndex(float f) {
        this.zzcs = f;
        return this;
    }

    public final GroundOverlayOptions visible(boolean z) {
        this.zzct = z;
        return this;
    }

    public final GroundOverlayOptions transparency(float f) {
        Preconditions.checkArgument(f >= 0.0f && f <= 1.0f, "Transparency must be in the range [0..1]");
        this.zzda = f;
        return this;
    }

    public final GroundOverlayOptions clickable(boolean z) {
        this.zzcu = z;
        return this;
    }

    public final BitmapDescriptor getImage() {
        return this.zzcx;
    }

    public final LatLng getLocation() {
        return this.zzcy;
    }

    public final float getWidth() {
        return this.width;
    }

    public final float getHeight() {
        return this.height;
    }

    public final LatLngBounds getBounds() {
        return this.zzcz;
    }

    public final float getBearing() {
        return this.bearing;
    }

    public final float getZIndex() {
        return this.zzcs;
    }

    public final float getTransparency() {
        return this.zzda;
    }

    public final float getAnchorU() {
        return this.zzdb;
    }

    public final float getAnchorV() {
        return this.zzdc;
    }

    public final boolean isVisible() {
        return this.zzct;
    }

    public final boolean isClickable() {
        return this.zzcu;
    }
}
