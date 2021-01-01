package com.google.android.gms.common.server.converter;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.server.response.FastJsonResponse.FieldConverter;

public final class zaa extends AbstractSafeParcelable {
    public static final Creator<zaa> CREATOR = new zab();
    private final int zalf;
    private final StringToIntConverter zapl;

    zaa(int i, StringToIntConverter stringToIntConverter) {
        this.zalf = i;
        this.zapl = stringToIntConverter;
    }

    private zaa(StringToIntConverter stringToIntConverter) {
        this.zalf = 1;
        this.zapl = stringToIntConverter;
    }

    public static zaa zaa(FieldConverter<?, ?> fieldConverter) {
        if (fieldConverter instanceof StringToIntConverter) {
            return new zaa((StringToIntConverter) fieldConverter);
        }
        throw new IllegalArgumentException("Unsupported safe parcelable field converter class.");
    }

    public final FieldConverter<?, ?> zaci() {
        StringToIntConverter stringToIntConverter = this.zapl;
        if (stringToIntConverter != null) {
            return stringToIntConverter;
        }
        throw new IllegalStateException("There was no converter wrapped in this ConverterWrapper.");
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.zalf);
        SafeParcelWriter.writeParcelable(parcel, 2, this.zapl, i, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }
}
