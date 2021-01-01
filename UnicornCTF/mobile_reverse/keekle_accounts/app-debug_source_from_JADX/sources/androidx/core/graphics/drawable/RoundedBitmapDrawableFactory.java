package androidx.core.graphics.drawable;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import android.os.Build.VERSION;
import android.util.Log;
import androidx.core.graphics.BitmapCompat;
import androidx.core.view.GravityCompat;
import java.io.InputStream;

public final class RoundedBitmapDrawableFactory {
    private static final String TAG = "RoundedBitmapDrawableFa";

    private static class DefaultRoundedBitmapDrawable extends RoundedBitmapDrawable {
        DefaultRoundedBitmapDrawable(Resources res, Bitmap bitmap) {
            super(res, bitmap);
        }

        public void setMipMap(boolean mipMap) {
            if (this.mBitmap != null) {
                BitmapCompat.setHasMipMap(this.mBitmap, mipMap);
                invalidateSelf();
            }
        }

        public boolean hasMipMap() {
            return this.mBitmap != null && BitmapCompat.hasMipMap(this.mBitmap);
        }

        /* access modifiers changed from: 0000 */
        public void gravityCompatApply(int gravity, int bitmapWidth, int bitmapHeight, Rect bounds, Rect outRect) {
            GravityCompat.apply(gravity, bitmapWidth, bitmapHeight, bounds, outRect, 0);
        }
    }

    public static RoundedBitmapDrawable create(Resources res, Bitmap bitmap) {
        if (VERSION.SDK_INT >= 21) {
            return new RoundedBitmapDrawable21(res, bitmap);
        }
        return new DefaultRoundedBitmapDrawable(res, bitmap);
    }

    public static RoundedBitmapDrawable create(Resources res, String filepath) {
        RoundedBitmapDrawable drawable = create(res, BitmapFactory.decodeFile(filepath));
        if (drawable.getBitmap() == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("RoundedBitmapDrawable cannot decode ");
            sb.append(filepath);
            Log.w(TAG, sb.toString());
        }
        return drawable;
    }

    public static RoundedBitmapDrawable create(Resources res, InputStream is) {
        RoundedBitmapDrawable drawable = create(res, BitmapFactory.decodeStream(is));
        if (drawable.getBitmap() == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("RoundedBitmapDrawable cannot decode ");
            sb.append(is);
            Log.w(TAG, sb.toString());
        }
        return drawable;
    }

    private RoundedBitmapDrawableFactory() {
    }
}
