package com.google.android.gms.common.server.response;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.server.response.FastJsonResponse.Field;

public final class zam extends AbstractSafeParcelable {
    public static final Creator<zam> CREATOR = new zaj();
    private final int versionCode;
    final String zaqz;
    final Field<?, ?> zara;

    zam(int i, String str, Field<?, ?> field) {
        this.versionCode = i;
        this.zaqz = str;
        this.zara = field;
    }

    zam(String str, Field<?, ?> field) {
        this.versionCode = 1;
        this.zaqz = str;
        this.zara = field;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.versionCode);
        SafeParcelWriter.writeString(parcel, 2, this.zaqz, false);
        SafeParcelWriter.writeParcelable(parcel, 3, this.zara, i, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }
}
