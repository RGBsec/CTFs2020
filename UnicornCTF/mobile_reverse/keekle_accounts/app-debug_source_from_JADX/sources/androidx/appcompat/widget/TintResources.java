package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.graphics.drawable.Drawable;
import java.lang.ref.WeakReference;

class TintResources extends ResourcesWrapper {
    private final WeakReference<Context> mContextRef;

    public TintResources(Context context, Resources res) {
        super(res);
        this.mContextRef = new WeakReference<>(context);
    }

    public Drawable getDrawable(int id) throws NotFoundException {
        Drawable d = super.getDrawable(id);
        Context context = (Context) this.mContextRef.get();
        if (!(d == null || context == null)) {
            ResourceManagerInternal.get().tintDrawableUsingColorFilter(context, id, d);
        }
        return d;
    }
}
