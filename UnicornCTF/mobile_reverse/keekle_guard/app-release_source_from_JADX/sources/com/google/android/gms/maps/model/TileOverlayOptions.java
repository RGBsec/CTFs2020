package com.google.android.gms.maps.model;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.internal.maps.zzaf;
import com.google.android.gms.internal.maps.zzag;

public final class TileOverlayOptions extends AbstractSafeParcelable {
    public static final Creator<TileOverlayOptions> CREATOR = new zzu();
    private float zzcs;
    private boolean zzct = true;
    private float zzda = 0.0f;
    /* access modifiers changed from: private */
    public zzaf zzei;
    private TileProvider zzej;
    private boolean zzek = true;

    public TileOverlayOptions() {
    }

    TileOverlayOptions(IBinder iBinder, boolean z, float f, boolean z2, float f2) {
        zzs zzs;
        zzaf zzk = zzag.zzk(iBinder);
        this.zzei = zzk;
        if (zzk == null) {
            zzs = null;
        } else {
            zzs = new zzs(this);
        }
        this.zzej = zzs;
        this.zzct = z;
        this.zzcs = f;
        this.zzek = z2;
        this.zzda = f2;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeIBinder(parcel, 2, this.zzei.asBinder(), false);
        SafeParcelWriter.writeBoolean(parcel, 3, isVisible());
        SafeParcelWriter.writeFloat(parcel, 4, getZIndex());
        SafeParcelWriter.writeBoolean(parcel, 5, getFadeIn());
        SafeParcelWriter.writeFloat(parcel, 6, getTransparency());
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    public final TileOverlayOptions tileProvider(TileProvider tileProvider) {
        zzaf zzaf;
        this.zzej = tileProvider;
        if (tileProvider == null) {
            zzaf = null;
        } else {
            zzaf = new zzt(this, tileProvider);
        }
        this.zzei = zzaf;
        return this;
    }

    public final TileOverlayOptions zIndex(float f) {
        this.zzcs = f;
        return this;
    }

    public final TileOverlayOptions visible(boolean z) {
        this.zzct = z;
        return this;
    }

    public final TileOverlayOptions fadeIn(boolean z) {
        this.zzek = z;
        return this;
    }

    public final TileOverlayOptions transparency(float f) {
        Preconditions.checkArgument(f >= 0.0f && f <= 1.0f, "Transparency must be in the range [0..1]");
        this.zzda = f;
        return this;
    }

    public final TileProvider getTileProvider() {
        return this.zzej;
    }

    public final float getZIndex() {
        return this.zzcs;
    }

    public final boolean isVisible() {
        return this.zzct;
    }

    public final boolean getFadeIn() {
        return this.zzek;
    }

    public final float getTransparency() {
        return this.zzda;
    }
}
