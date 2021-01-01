package com.google.android.gms.internal.base;

import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;

final class zai extends ConstantState {
    int mChangingConfigurations;
    int zanw;

    zai(zai zai) {
        if (zai != null) {
            this.mChangingConfigurations = zai.mChangingConfigurations;
            this.zanw = zai.zanw;
        }
    }

    public final Drawable newDrawable() {
        return new zae(this);
    }

    public final int getChangingConfigurations() {
        return this.mChangingConfigurations;
    }
}
