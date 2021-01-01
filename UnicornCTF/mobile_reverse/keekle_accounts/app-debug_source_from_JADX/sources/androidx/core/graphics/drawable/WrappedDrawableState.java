package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.os.Build.VERSION;

final class WrappedDrawableState extends ConstantState {
    int mChangingConfigurations;
    ConstantState mDrawableState;
    ColorStateList mTint = null;
    Mode mTintMode = WrappedDrawableApi14.DEFAULT_TINT_MODE;

    WrappedDrawableState(WrappedDrawableState orig) {
        if (orig != null) {
            this.mChangingConfigurations = orig.mChangingConfigurations;
            this.mDrawableState = orig.mDrawableState;
            this.mTint = orig.mTint;
            this.mTintMode = orig.mTintMode;
        }
    }

    public Drawable newDrawable() {
        return newDrawable(null);
    }

    public Drawable newDrawable(Resources res) {
        if (VERSION.SDK_INT >= 21) {
            return new WrappedDrawableApi21(this, res);
        }
        return new WrappedDrawableApi14(this, res);
    }

    public int getChangingConfigurations() {
        int i = this.mChangingConfigurations;
        ConstantState constantState = this.mDrawableState;
        return i | (constantState != null ? constantState.getChangingConfigurations() : 0);
    }

    /* access modifiers changed from: 0000 */
    public boolean canConstantState() {
        return this.mDrawableState != null;
    }
}
