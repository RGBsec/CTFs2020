package com.google.android.gms.common.server.converter;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import android.util.SparseArray;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.common.server.response.FastJsonResponse.FieldConverter;
import java.util.ArrayList;
import java.util.HashMap;

public final class StringToIntConverter extends AbstractSafeParcelable implements FieldConverter<String, Integer> {
    public static final Creator<StringToIntConverter> CREATOR = new zac();
    private final int zalf;
    private final HashMap<String, Integer> zapm;
    private final SparseArray<String> zapn;
    private final ArrayList<zaa> zapo;

    public static final class zaa extends AbstractSafeParcelable {
        public static final Creator<zaa> CREATOR = new zad();
        private final int versionCode;
        final String zapp;
        final int zapq;

        zaa(int i, String str, int i2) {
            this.versionCode = i;
            this.zapp = str;
            this.zapq = i2;
        }

        zaa(String str, int i) {
            this.versionCode = 1;
            this.zapp = str;
            this.zapq = i;
        }

        public final void writeToParcel(Parcel parcel, int i) {
            int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
            SafeParcelWriter.writeInt(parcel, 1, this.versionCode);
            SafeParcelWriter.writeString(parcel, 2, this.zapp, false);
            SafeParcelWriter.writeInt(parcel, 3, this.zapq);
            SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
        }
    }

    StringToIntConverter(int i, ArrayList<zaa> arrayList) {
        this.zalf = i;
        this.zapm = new HashMap<>();
        this.zapn = new SparseArray<>();
        this.zapo = null;
        ArrayList arrayList2 = arrayList;
        int size = arrayList2.size();
        int i2 = 0;
        while (i2 < size) {
            Object obj = arrayList2.get(i2);
            i2++;
            zaa zaa2 = (zaa) obj;
            add(zaa2.zapp, zaa2.zapq);
        }
    }

    public final int zacj() {
        return 7;
    }

    public final int zack() {
        return 0;
    }

    public StringToIntConverter() {
        this.zalf = 1;
        this.zapm = new HashMap<>();
        this.zapn = new SparseArray<>();
        this.zapo = null;
    }

    public final StringToIntConverter add(String str, int i) {
        this.zapm.put(str, Integer.valueOf(i));
        this.zapn.put(i, str);
        return this;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.zalf);
        ArrayList arrayList = new ArrayList();
        for (String str : this.zapm.keySet()) {
            arrayList.add(new zaa(str, ((Integer) this.zapm.get(str)).intValue()));
        }
        SafeParcelWriter.writeTypedList(parcel, 2, arrayList, false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }

    public final /* synthetic */ Object convertBack(Object obj) {
        String str = (String) this.zapn.get(((Integer) obj).intValue());
        if (str == null) {
            String str2 = "gms_unknown";
            if (this.zapm.containsKey(str2)) {
                return str2;
            }
        }
        return str;
    }

    public final /* synthetic */ Object convert(Object obj) {
        Integer num = (Integer) this.zapm.get((String) obj);
        return num == null ? (Integer) this.zapm.get("gms_unknown") : num;
    }
}
