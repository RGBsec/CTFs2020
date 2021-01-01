package androidx.transition;

import android.animation.ObjectAnimator;
import android.graphics.Path;
import android.graphics.PointF;
import android.os.Build.VERSION;
import android.util.Property;

class ObjectAnimatorUtils {
    static <T> ObjectAnimator ofPointF(T target, Property<T, PointF> property, Path path) {
        if (VERSION.SDK_INT >= 21) {
            return ObjectAnimator.ofObject(target, property, null, path);
        }
        return ObjectAnimator.ofFloat(target, new PathProperty(property, path), new float[]{0.0f, 1.0f});
    }

    private ObjectAnimatorUtils() {
    }
}
