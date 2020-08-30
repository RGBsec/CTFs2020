package androidx.core.p005os;

import android.os.Parcel;

/* renamed from: androidx.core.os.ParcelCompat */
public final class ParcelCompat {
    public static boolean readBoolean(Parcel in) {
        return in.readInt() != 0;
    }

    public static void writeBoolean(Parcel out, boolean value) {
        out.writeInt(value);
    }

    private ParcelCompat() {
    }
}
