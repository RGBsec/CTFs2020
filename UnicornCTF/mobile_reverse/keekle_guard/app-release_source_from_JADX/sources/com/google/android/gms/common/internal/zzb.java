package com.google.android.gms.common.internal;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;

public final class zzb extends AbstractSafeParcelable {
    public static final Creator<zzb> CREATOR = new zzc();
    Bundle zzda;
    Feature[] zzdb;

    zzb(Bundle bundle, Feature[] featureArr) {
        this.zzda = bundle;
        this.zzdb = featureArr;
    }

    public zzb() {
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeBundle(parcel, 1, this.zzda, false);
        SafeParcelWriter.writeTypedArray(parcel, 2, this.zzdb, i, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }
}
