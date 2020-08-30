package com.google.android.gms.common.data;

import android.database.CursorWindow;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader;

public final class zac implements Creator<DataHolder> {
    public final /* synthetic */ Object[] newArray(int i) {
        return new DataHolder[i];
    }

    public final /* synthetic */ Object createFromParcel(Parcel parcel) {
        int validateObjectHeader = SafeParcelReader.validateObjectHeader(parcel);
        int i = 0;
        int i2 = 0;
        String[] strArr = null;
        CursorWindow[] cursorWindowArr = null;
        Bundle bundle = null;
        while (parcel.dataPosition() < validateObjectHeader) {
            int readHeader = SafeParcelReader.readHeader(parcel);
            int fieldId = SafeParcelReader.getFieldId(readHeader);
            if (fieldId == 1) {
                strArr = SafeParcelReader.createStringArray(parcel, readHeader);
            } else if (fieldId == 2) {
                cursorWindowArr = (CursorWindow[]) SafeParcelReader.createTypedArray(parcel, readHeader, CursorWindow.CREATOR);
            } else if (fieldId == 3) {
                i2 = SafeParcelReader.readInt(parcel, readHeader);
            } else if (fieldId == 4) {
                bundle = SafeParcelReader.createBundle(parcel, readHeader);
            } else if (fieldId != 1000) {
                SafeParcelReader.skipUnknownField(parcel, readHeader);
            } else {
                i = SafeParcelReader.readInt(parcel, readHeader);
            }
        }
        SafeParcelReader.ensureAtEnd(parcel, validateObjectHeader);
        DataHolder dataHolder = new DataHolder(i, strArr, cursorWindowArr, i2, bundle);
        dataHolder.zaca();
        return dataHolder;
    }
}
