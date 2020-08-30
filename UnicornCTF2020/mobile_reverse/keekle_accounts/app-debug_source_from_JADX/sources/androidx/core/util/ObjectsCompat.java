package androidx.core.util;

import android.os.Build.VERSION;
import java.util.Arrays;
import java.util.Objects;

public class ObjectsCompat {
    private ObjectsCompat() {
    }

    public static boolean equals(Object a, Object b) {
        if (VERSION.SDK_INT >= 19) {
            return Objects.equals(a, b);
        }
        return a == b || (a != null && a.equals(b));
    }

    public static int hashCode(Object o) {
        if (o != null) {
            return o.hashCode();
        }
        return 0;
    }

    public static int hash(Object... values) {
        if (VERSION.SDK_INT >= 19) {
            return Objects.hash(values);
        }
        return Arrays.hashCode(values);
    }
}
