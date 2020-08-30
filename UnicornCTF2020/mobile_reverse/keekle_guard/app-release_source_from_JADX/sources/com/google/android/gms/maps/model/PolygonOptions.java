package com.google.android.gms.maps.model;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import androidx.core.view.ViewCompat;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class PolygonOptions extends AbstractSafeParcelable {
    public static final Creator<PolygonOptions> CREATOR = new zzk();
    private int fillColor;
    private int strokeColor;
    private float zzcr;
    private float zzcs;
    private boolean zzct;
    private boolean zzcu;
    private List<PatternItem> zzcv;
    private final List<LatLng> zzdx;
    private final List<List<LatLng>> zzdy;
    private boolean zzdz;
    private int zzea;

    public PolygonOptions() {
        this.zzcr = 10.0f;
        this.strokeColor = ViewCompat.MEASURED_STATE_MASK;
        this.fillColor = 0;
        this.zzcs = 0.0f;
        this.zzct = true;
        this.zzdz = false;
        this.zzcu = false;
        this.zzea = 0;
        this.zzcv = null;
        this.zzdx = new ArrayList();
        this.zzdy = new ArrayList();
    }

    PolygonOptions(List<LatLng> list, List list2, float f, int i, int i2, float f2, boolean z, boolean z2, boolean z3, int i3, List<PatternItem> list3) {
        this.zzcr = 10.0f;
        this.strokeColor = ViewCompat.MEASURED_STATE_MASK;
        this.fillColor = 0;
        this.zzcs = 0.0f;
        this.zzct = true;
        this.zzdz = false;
        this.zzcu = false;
        this.zzea = 0;
        this.zzcv = null;
        this.zzdx = list;
        this.zzdy = list2;
        this.zzcr = f;
        this.strokeColor = i;
        this.fillColor = i2;
        this.zzcs = f2;
        this.zzct = z;
        this.zzdz = z2;
        this.zzcu = z3;
        this.zzea = i3;
        this.zzcv = list3;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeTypedList(parcel, 2, getPoints(), false);
        SafeParcelWriter.writeList(parcel, 3, this.zzdy, false);
        SafeParcelWriter.writeFloat(parcel, 4, getStrokeWidth());
        SafeParcelWriter.writeInt(parcel, 5, getStrokeColor());
        SafeParcelWriter.writeInt(parcel, 6, getFillColor());
        SafeParcelWriter.writeFloat(parcel, 7, getZIndex());
        SafeParcelWriter.writeBoolean(parcel, 8, isVisible());
        SafeParcelWriter.writeBoolean(parcel, 9, isGeodesic());
        SafeParcelWriter.writeBoolean(parcel, 10, isClickable());
        SafeParcelWriter.writeInt(parcel, 11, getStrokeJointType());
        SafeParcelWriter.writeTypedList(parcel, 12, getStrokePattern(), false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    public final PolygonOptions add(LatLng latLng) {
        this.zzdx.add(latLng);
        return this;
    }

    public final PolygonOptions add(LatLng... latLngArr) {
        this.zzdx.addAll(Arrays.asList(latLngArr));
        return this;
    }

    public final PolygonOptions addAll(Iterable<LatLng> iterable) {
        for (LatLng add : iterable) {
            this.zzdx.add(add);
        }
        return this;
    }

    public final PolygonOptions addHole(Iterable<LatLng> iterable) {
        ArrayList arrayList = new ArrayList();
        for (LatLng add : iterable) {
            arrayList.add(add);
        }
        this.zzdy.add(arrayList);
        return this;
    }

    public final PolygonOptions strokeWidth(float f) {
        this.zzcr = f;
        return this;
    }

    public final PolygonOptions strokeColor(int i) {
        this.strokeColor = i;
        return this;
    }

    public final PolygonOptions strokeJointType(int i) {
        this.zzea = i;
        return this;
    }

    public final PolygonOptions strokePattern(List<PatternItem> list) {
        this.zzcv = list;
        return this;
    }

    public final PolygonOptions fillColor(int i) {
        this.fillColor = i;
        return this;
    }

    public final PolygonOptions zIndex(float f) {
        this.zzcs = f;
        return this;
    }

    public final PolygonOptions visible(boolean z) {
        this.zzct = z;
        return this;
    }

    public final PolygonOptions geodesic(boolean z) {
        this.zzdz = z;
        return this;
    }

    public final PolygonOptions clickable(boolean z) {
        this.zzcu = z;
        return this;
    }

    public final List<LatLng> getPoints() {
        return this.zzdx;
    }

    public final List<List<LatLng>> getHoles() {
        return this.zzdy;
    }

    public final float getStrokeWidth() {
        return this.zzcr;
    }

    public final int getStrokeColor() {
        return this.strokeColor;
    }

    public final int getStrokeJointType() {
        return this.zzea;
    }

    public final List<PatternItem> getStrokePattern() {
        return this.zzcv;
    }

    public final int getFillColor() {
        return this.fillColor;
    }

    public final float getZIndex() {
        return this.zzcs;
    }

    public final boolean isVisible() {
        return this.zzct;
    }

    public final boolean isGeodesic() {
        return this.zzdz;
    }

    public final boolean isClickable() {
        return this.zzcu;
    }
}
