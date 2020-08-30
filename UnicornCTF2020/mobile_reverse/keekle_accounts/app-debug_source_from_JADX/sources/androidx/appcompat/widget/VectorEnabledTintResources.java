package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import java.lang.ref.WeakReference;

public class VectorEnabledTintResources extends Resources {
    public static final int MAX_SDK_WHERE_REQUIRED = 20;
    private static boolean sCompatVectorFromResourcesEnabled = false;
    private final WeakReference<Context> mContextRef;

    public static boolean shouldBeUsed() {
        return isCompatVectorFromResourcesEnabled() && VERSION.SDK_INT <= 20;
    }

    public VectorEnabledTintResources(Context context, Resources res) {
        super(res.getAssets(), res.getDisplayMetrics(), res.getConfiguration());
        this.mContextRef = new WeakReference<>(context);
    }

    public Drawable getDrawable(int id) throws NotFoundException {
        Context context = (Context) this.mContextRef.get();
        if (context != null) {
            return ResourceManagerInternal.get().onDrawableLoadedFromResources(context, this, id);
        }
        return super.getDrawable(id);
    }

    /* access modifiers changed from: 0000 */
    public final Drawable superGetDrawable(int id) {
        return super.getDrawable(id);
    }

    public static void setCompatVectorFromResourcesEnabled(boolean enabled) {
        sCompatVectorFromResourcesEnabled = enabled;
    }

    public static boolean isCompatVectorFromResourcesEnabled() {
        return sCompatVectorFromResourcesEnabled;
    }
}
