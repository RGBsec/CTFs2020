package androidx.cardview.widget;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

class RoundRectDrawable extends Drawable {
    private ColorStateList mBackground;
    private final RectF mBoundsF;
    private final Rect mBoundsI;
    private boolean mInsetForPadding = false;
    private boolean mInsetForRadius = true;
    private float mPadding;
    private final Paint mPaint;
    private float mRadius;
    private ColorStateList mTint;
    private PorterDuffColorFilter mTintFilter;
    private Mode mTintMode = Mode.SRC_IN;

    RoundRectDrawable(ColorStateList backgroundColor, float radius) {
        this.mRadius = radius;
        this.mPaint = new Paint(5);
        setBackground(backgroundColor);
        this.mBoundsF = new RectF();
        this.mBoundsI = new Rect();
    }

    private void setBackground(ColorStateList color) {
        ColorStateList valueOf = color == null ? ColorStateList.valueOf(0) : color;
        this.mBackground = valueOf;
        this.mPaint.setColor(valueOf.getColorForState(getState(), this.mBackground.getDefaultColor()));
    }

    /* access modifiers changed from: 0000 */
    public void setPadding(float padding, boolean insetForPadding, boolean insetForRadius) {
        if (padding != this.mPadding || this.mInsetForPadding != insetForPadding || this.mInsetForRadius != insetForRadius) {
            this.mPadding = padding;
            this.mInsetForPadding = insetForPadding;
            this.mInsetForRadius = insetForRadius;
            updateBounds(null);
            invalidateSelf();
        }
    }

    /* access modifiers changed from: 0000 */
    public float getPadding() {
        return this.mPadding;
    }

    public void draw(Canvas canvas) {
        boolean clearColorFilter;
        Paint paint = this.mPaint;
        if (this.mTintFilter == null || paint.getColorFilter() != null) {
            clearColorFilter = false;
        } else {
            paint.setColorFilter(this.mTintFilter);
            clearColorFilter = true;
        }
        RectF rectF = this.mBoundsF;
        float f = this.mRadius;
        canvas.drawRoundRect(rectF, f, f, paint);
        if (clearColorFilter) {
            paint.setColorFilter(null);
        }
    }

    private void updateBounds(Rect bounds) {
        if (bounds == null) {
            bounds = getBounds();
        }
        this.mBoundsF.set((float) bounds.left, (float) bounds.top, (float) bounds.right, (float) bounds.bottom);
        this.mBoundsI.set(bounds);
        if (this.mInsetForPadding) {
            float vInset = RoundRectDrawableWithShadow.calculateVerticalPadding(this.mPadding, this.mRadius, this.mInsetForRadius);
            this.mBoundsI.inset((int) Math.ceil((double) RoundRectDrawableWithShadow.calculateHorizontalPadding(this.mPadding, this.mRadius, this.mInsetForRadius)), (int) Math.ceil((double) vInset));
            this.mBoundsF.set(this.mBoundsI);
        }
    }

    /* access modifiers changed from: protected */
    public void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        updateBounds(bounds);
    }

    public void getOutline(Outline outline) {
        outline.setRoundRect(this.mBoundsI, this.mRadius);
    }

    /* access modifiers changed from: 0000 */
    public void setRadius(float radius) {
        if (radius != this.mRadius) {
            this.mRadius = radius;
            updateBounds(null);
            invalidateSelf();
        }
    }

    public void setAlpha(int alpha) {
        this.mPaint.setAlpha(alpha);
    }

    public void setColorFilter(ColorFilter cf) {
        this.mPaint.setColorFilter(cf);
    }

    public int getOpacity() {
        return -3;
    }

    public float getRadius() {
        return this.mRadius;
    }

    public void setColor(ColorStateList color) {
        setBackground(color);
        invalidateSelf();
    }

    public ColorStateList getColor() {
        return this.mBackground;
    }

    public void setTintList(ColorStateList tint) {
        this.mTint = tint;
        this.mTintFilter = createTintFilter(tint, this.mTintMode);
        invalidateSelf();
    }

    public void setTintMode(Mode tintMode) {
        this.mTintMode = tintMode;
        this.mTintFilter = createTintFilter(this.mTint, tintMode);
        invalidateSelf();
    }

    /* access modifiers changed from: protected */
    public boolean onStateChange(int[] stateSet) {
        ColorStateList colorStateList = this.mBackground;
        int newColor = colorStateList.getColorForState(stateSet, colorStateList.getDefaultColor());
        boolean colorChanged = newColor != this.mPaint.getColor();
        if (colorChanged) {
            this.mPaint.setColor(newColor);
        }
        ColorStateList colorStateList2 = this.mTint;
        if (colorStateList2 != null) {
            Mode mode = this.mTintMode;
            if (mode != null) {
                this.mTintFilter = createTintFilter(colorStateList2, mode);
                return true;
            }
        }
        return colorChanged;
    }

    public boolean isStateful() {
        ColorStateList colorStateList = this.mTint;
        if (colorStateList == null || !colorStateList.isStateful()) {
            ColorStateList colorStateList2 = this.mBackground;
            if ((colorStateList2 == null || !colorStateList2.isStateful()) && !super.isStateful()) {
                return false;
            }
        }
        return true;
    }

    private PorterDuffColorFilter createTintFilter(ColorStateList tint, Mode tintMode) {
        if (tint == null || tintMode == null) {
            return null;
        }
        return new PorterDuffColorFilter(tint.getColorForState(getState(), 0), tintMode);
    }
}
