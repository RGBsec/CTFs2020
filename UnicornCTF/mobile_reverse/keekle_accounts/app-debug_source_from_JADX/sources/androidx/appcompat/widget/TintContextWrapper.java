package androidx.appcompat.widget;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.os.Build.VERSION;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

public class TintContextWrapper extends ContextWrapper {
    private static final Object CACHE_LOCK = new Object();
    private static ArrayList<WeakReference<TintContextWrapper>> sCache;
    private final Resources mResources;
    private final Theme mTheme;

    public static Context wrap(Context context) {
        if (!shouldWrap(context)) {
            return context;
        }
        synchronized (CACHE_LOCK) {
            if (sCache == null) {
                sCache = new ArrayList<>();
            } else {
                for (int i = sCache.size() - 1; i >= 0; i--) {
                    WeakReference<TintContextWrapper> ref = (WeakReference) sCache.get(i);
                    if (ref == null || ref.get() == null) {
                        sCache.remove(i);
                    }
                }
                for (int i2 = sCache.size() - 1; i2 >= 0; i2--) {
                    WeakReference<TintContextWrapper> ref2 = (WeakReference) sCache.get(i2);
                    TintContextWrapper wrapper = ref2 != null ? (TintContextWrapper) ref2.get() : null;
                    if (wrapper != null && wrapper.getBaseContext() == context) {
                        return wrapper;
                    }
                }
            }
            TintContextWrapper wrapper2 = new TintContextWrapper(context);
            sCache.add(new WeakReference(wrapper2));
            return wrapper2;
        }
    }

    private static boolean shouldWrap(Context context) {
        boolean z = false;
        if ((context instanceof TintContextWrapper) || (context.getResources() instanceof TintResources) || (context.getResources() instanceof VectorEnabledTintResources)) {
            return false;
        }
        if (VERSION.SDK_INT < 21 || VectorEnabledTintResources.shouldBeUsed()) {
            z = true;
        }
        return z;
    }

    private TintContextWrapper(Context base) {
        super(base);
        if (VectorEnabledTintResources.shouldBeUsed()) {
            VectorEnabledTintResources vectorEnabledTintResources = new VectorEnabledTintResources(this, base.getResources());
            this.mResources = vectorEnabledTintResources;
            Theme newTheme = vectorEnabledTintResources.newTheme();
            this.mTheme = newTheme;
            newTheme.setTo(base.getTheme());
            return;
        }
        this.mResources = new TintResources(this, base.getResources());
        this.mTheme = null;
    }

    public Theme getTheme() {
        Theme theme = this.mTheme;
        return theme == null ? super.getTheme() : theme;
    }

    public void setTheme(int resid) {
        Theme theme = this.mTheme;
        if (theme == null) {
            super.setTheme(resid);
        } else {
            theme.applyStyle(resid, true);
        }
    }

    public Resources getResources() {
        return this.mResources;
    }

    public AssetManager getAssets() {
        return this.mResources.getAssets();
    }
}
