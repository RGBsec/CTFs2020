package com.google.android.gms.maps.model;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.Objects;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;

public final class VisibleRegion extends AbstractSafeParcelable {
    public static final Creator<VisibleRegion> CREATOR = new zzv();
    public final LatLng farLeft;
    public final LatLng farRight;
    public final LatLngBounds latLngBounds;
    public final LatLng nearLeft;
    public final LatLng nearRight;

    public VisibleRegion(LatLng latLng, LatLng latLng2, LatLng latLng3, LatLng latLng4, LatLngBounds latLngBounds2) {
        this.nearLeft = latLng;
        this.nearRight = latLng2;
        this.farLeft = latLng3;
        this.farRight = latLng4;
        this.latLngBounds = latLngBounds2;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeParcelable(parcel, 2, this.nearLeft, i, false);
        SafeParcelWriter.writeParcelable(parcel, 3, this.nearRight, i, false);
        SafeParcelWriter.writeParcelable(parcel, 4, this.farLeft, i, false);
        SafeParcelWriter.writeParcelable(parcel, 5, this.farRight, i, false);
        SafeParcelWriter.writeParcelable(parcel, 6, this.latLngBounds, i, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    public final int hashCode() {
        return Objects.hashCode(this.nearLeft, this.nearRight, this.farLeft, this.farRight, this.latLngBounds);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof VisibleRegion)) {
            return false;
        }
        VisibleRegion visibleRegion = (VisibleRegion) obj;
        return this.nearLeft.equals(visibleRegion.nearLeft) && this.nearRight.equals(visibleRegion.nearRight) && this.farLeft.equals(visibleRegion.farLeft) && this.farRight.equals(visibleRegion.farRight) && this.latLngBounds.equals(visibleRegion.latLngBounds);
    }

    public final String toString() {
        return Objects.toStringHelper(this).add("nearLeft", this.nearLeft).add("nearRight", this.nearRight).add("farLeft", this.farLeft).add("farRight", this.farRight).add("latLngBounds", this.latLngBounds).toString();
    }
}
