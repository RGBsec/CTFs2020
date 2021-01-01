package com.google.android.gms.common.server.response;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.server.response.FastJsonResponse.Field;
import java.util.ArrayList;
import java.util.Map;

public final class zal extends AbstractSafeParcelable {
    public static final Creator<zal> CREATOR = new zao();
    final String className;
    private final int versionCode;
    final ArrayList<zam> zaqy;

    zal(int i, String str, ArrayList<zam> arrayList) {
        this.versionCode = i;
        this.className = str;
        this.zaqy = arrayList;
    }

    zal(String str, Map<String, Field<?, ?>> map) {
        ArrayList<zam> arrayList;
        this.versionCode = 1;
        this.className = str;
        if (map == null) {
            arrayList = null;
        } else {
            arrayList = new ArrayList<>();
            for (String str2 : map.keySet()) {
                arrayList.add(new zam(str2, (Field) map.get(str2)));
            }
        }
        this.zaqy = arrayList;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.versionCode);
        SafeParcelWriter.writeString(parcel, 2, this.className, false);
        SafeParcelWriter.writeTypedList(parcel, 3, this.zaqy, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }
}
