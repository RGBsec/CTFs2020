package com.google.android.material.animation;

import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.Property;
import java.util.WeakHashMap;

public class DrawableAlphaProperty extends Property<Drawable, Integer> {
    public static final Property<Drawable, Integer> DRAWABLE_ALPHA_COMPAT = new DrawableAlphaProperty();
    private final WeakHashMap<Drawable, Integer> alphaCache = new WeakHashMap<>();

    private DrawableAlphaProperty() {
        super(Integer.class, "drawableAlphaCompat");
    }

    public Integer get(Drawable object) {
        if (VERSION.SDK_INT >= 19) {
            return Integer.valueOf(object.getAlpha());
        }
        if (this.alphaCache.containsKey(object)) {
            return (Integer) this.alphaCache.get(object);
        }
        return Integer.valueOf(255);
    }

    public void set(Drawable object, Integer value) {
        if (VERSION.SDK_INT < 19) {
            this.alphaCache.put(object, value);
        }
        object.setAlpha(value.intValue());
    }
}
