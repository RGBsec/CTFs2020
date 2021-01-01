package androidx.versionedparcelable;

import android.os.Bundle;
import android.os.Parcelable;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ParcelUtils {
    private static final String INNER_BUNDLE_KEY = "a";

    private ParcelUtils() {
    }

    public static Parcelable toParcelable(VersionedParcelable obj) {
        return new ParcelImpl(obj);
    }

    public static <T extends VersionedParcelable> T fromParcelable(Parcelable p) {
        if (p instanceof ParcelImpl) {
            return ((ParcelImpl) p).getVersionedParcel();
        }
        throw new IllegalArgumentException("Invalid parcel");
    }

    public static void toOutputStream(VersionedParcelable obj, OutputStream output) {
        VersionedParcelStream stream = new VersionedParcelStream(null, output);
        stream.writeVersionedParcelable(obj);
        stream.closeField();
    }

    public static <T extends VersionedParcelable> T fromInputStream(InputStream input) {
        return new VersionedParcelStream(input, null).readVersionedParcelable();
    }

    public static void putVersionedParcelable(Bundle b, String key, VersionedParcelable obj) {
        if (obj != null) {
            Bundle innerBundle = new Bundle();
            innerBundle.putParcelable(INNER_BUNDLE_KEY, toParcelable(obj));
            b.putParcelable(key, innerBundle);
        }
    }

    public static <T extends VersionedParcelable> T getVersionedParcelable(Bundle bundle, String key) {
        try {
            Bundle innerBundle = (Bundle) bundle.getParcelable(key);
            if (innerBundle == null) {
                return null;
            }
            innerBundle.setClassLoader(ParcelUtils.class.getClassLoader());
            return fromParcelable(innerBundle.getParcelable(INNER_BUNDLE_KEY));
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static void putVersionedParcelableList(Bundle b, String key, List<? extends VersionedParcelable> list) {
        Bundle innerBundle = new Bundle();
        ArrayList<Parcelable> toWrite = new ArrayList<>();
        for (VersionedParcelable obj : list) {
            toWrite.add(toParcelable(obj));
        }
        innerBundle.putParcelableArrayList(INNER_BUNDLE_KEY, toWrite);
        b.putParcelable(key, innerBundle);
    }

    public static <T extends VersionedParcelable> List<T> getVersionedParcelableList(Bundle bundle, String key) {
        List<T> resultList = new ArrayList<>();
        try {
            Bundle innerBundle = (Bundle) bundle.getParcelable(key);
            innerBundle.setClassLoader(ParcelUtils.class.getClassLoader());
            Iterator it = innerBundle.getParcelableArrayList(INNER_BUNDLE_KEY).iterator();
            while (it.hasNext()) {
                resultList.add(fromParcelable((Parcelable) it.next()));
            }
            return resultList;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
