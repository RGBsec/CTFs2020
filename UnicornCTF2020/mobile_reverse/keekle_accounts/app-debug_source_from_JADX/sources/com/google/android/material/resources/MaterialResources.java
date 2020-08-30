package com.google.android.material.resources;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import androidx.appcompat.content.res.AppCompatResources;

public class MaterialResources {
    private MaterialResources() {
    }

    public static ColorStateList getColorStateList(Context context, TypedArray attributes, int index) {
        if (attributes.hasValue(index)) {
            int resourceId = attributes.getResourceId(index, 0);
            if (resourceId != 0) {
                ColorStateList value = AppCompatResources.getColorStateList(context, resourceId);
                if (value != null) {
                    return value;
                }
            }
        }
        return attributes.getColorStateList(index);
    }

    public static Drawable getDrawable(Context context, TypedArray attributes, int index) {
        if (attributes.hasValue(index)) {
            int resourceId = attributes.getResourceId(index, 0);
            if (resourceId != 0) {
                Drawable value = AppCompatResources.getDrawable(context, resourceId);
                if (value != null) {
                    return value;
                }
            }
        }
        return attributes.getDrawable(index);
    }

    public static TextAppearance getTextAppearance(Context context, TypedArray attributes, int index) {
        if (attributes.hasValue(index)) {
            int resourceId = attributes.getResourceId(index, 0);
            if (resourceId != 0) {
                return new TextAppearance(context, resourceId);
            }
        }
        return null;
    }

    static int getIndexWithValue(TypedArray attributes, int a, int b) {
        if (attributes.hasValue(a)) {
            return a;
        }
        return b;
    }
}
