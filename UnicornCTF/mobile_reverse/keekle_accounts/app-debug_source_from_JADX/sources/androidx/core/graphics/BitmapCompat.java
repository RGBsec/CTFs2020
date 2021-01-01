package androidx.core.graphics;

import android.graphics.Bitmap;
import android.os.Build.VERSION;

public final class BitmapCompat {
    public static boolean hasMipMap(Bitmap bitmap) {
        if (VERSION.SDK_INT >= 18) {
            return bitmap.hasMipMap();
        }
        return false;
    }

    public static void setHasMipMap(Bitmap bitmap, boolean hasMipMap) {
        if (VERSION.SDK_INT >= 18) {
            bitmap.setHasMipMap(hasMipMap);
        }
    }

    public static int getAllocationByteCount(Bitmap bitmap) {
        if (VERSION.SDK_INT >= 19) {
            return bitmap.getAllocationByteCount();
        }
        return bitmap.getByteCount();
    }

    private BitmapCompat() {
    }
}
