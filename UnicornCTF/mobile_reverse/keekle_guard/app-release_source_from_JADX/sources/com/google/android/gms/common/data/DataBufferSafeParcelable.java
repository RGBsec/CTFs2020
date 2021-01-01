package com.google.android.gms.common.data;

import android.content.ContentValues;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.data.DataHolder.Builder;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;

public class DataBufferSafeParcelable<T extends SafeParcelable> extends AbstractDataBuffer<T> {
    private static final String[] zalo = {"data"};
    private final Creator<T> zalp;

    public DataBufferSafeParcelable(DataHolder dataHolder, Creator<T> creator) {
        super(dataHolder);
        this.zalp = creator;
    }

    public static Builder buildDataHolder() {
        return DataHolder.builder(zalo);
    }

    public static <T extends SafeParcelable> void addValue(Builder builder, T t) {
        Parcel obtain = Parcel.obtain();
        t.writeToParcel(obtain, 0);
        ContentValues contentValues = new ContentValues();
        contentValues.put("data", obtain.marshall());
        builder.withRow(contentValues);
        obtain.recycle();
    }

    public T get(int i) {
        byte[] byteArray = this.mDataHolder.getByteArray("data", i, this.mDataHolder.getWindowIndex(i));
        Parcel obtain = Parcel.obtain();
        obtain.unmarshall(byteArray, 0, byteArray.length);
        obtain.setDataPosition(0);
        T t = (SafeParcelable) this.zalp.createFromParcel(obtain);
        obtain.recycle();
        return t;
    }
}
