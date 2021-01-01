package com.google.android.material.internal;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.Shader.TileMode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import androidx.core.graphics.ColorUtils;

public class CircularBorderDrawable extends Drawable {
    private static final float DRAW_STROKE_WIDTH_MULTIPLE = 1.3333f;
    private ColorStateList borderTint;
    float borderWidth;
    private int bottomInnerStrokeColor;
    private int bottomOuterStrokeColor;
    private int currentBorderTintColor;
    private boolean invalidateShader = true;
    final Paint paint;
    final Rect rect = new Rect();
    final RectF rectF = new RectF();
    private float rotation;
    final CircularBorderState state = new CircularBorderState();
    private int topInnerStrokeColor;
    private int topOuterStrokeColor;

    private class CircularBorderState extends ConstantState {
        private CircularBorderState() {
        }

        public Drawable newDrawable() {
            return CircularBorderDrawable.this;
        }

        public int getChangingConfigurations() {
            return 0;
        }
    }

    public CircularBorderDrawable() {
        Paint paint2 = new Paint(1);
        this.paint = paint2;
        paint2.setStyle(Style.STROKE);
    }

    public ConstantState getConstantState() {
        return this.state;
    }

    public void setGradientColors(int topOuterStrokeColor2, int topInnerStrokeColor2, int bottomOuterStrokeColor2, int bottomInnerStrokeColor2) {
        this.topOuterStrokeColor = topOuterStrokeColor2;
        this.topInnerStrokeColor = topInnerStrokeColor2;
        this.bottomOuterStrokeColor = bottomOuterStrokeColor2;
        this.bottomInnerStrokeColor = bottomInnerStrokeColor2;
    }

    public void setBorderWidth(float width) {
        if (this.borderWidth != width) {
            this.borderWidth = width;
            this.paint.setStrokeWidth(DRAW_STROKE_WIDTH_MULTIPLE * width);
            this.invalidateShader = true;
            invalidateSelf();
        }
    }

    public void draw(Canvas canvas) {
        if (this.invalidateShader) {
            this.paint.setShader(createGradientShader());
            this.invalidateShader = false;
        }
        float halfBorderWidth = this.paint.getStrokeWidth() / 2.0f;
        RectF rectF2 = this.rectF;
        copyBounds(this.rect);
        rectF2.set(this.rect);
        rectF2.left += halfBorderWidth;
        rectF2.top += halfBorderWidth;
        rectF2.right -= halfBorderWidth;
        rectF2.bottom -= halfBorderWidth;
        canvas.save();
        canvas.rotate(this.rotation, rectF2.centerX(), rectF2.centerY());
        canvas.drawOval(rectF2, this.paint);
        canvas.restore();
    }

    public boolean getPadding(Rect padding) {
        int borderWidth2 = Math.round(this.borderWidth);
        padding.set(borderWidth2, borderWidth2, borderWidth2, borderWidth2);
        return true;
    }

    public void setAlpha(int alpha) {
        this.paint.setAlpha(alpha);
        invalidateSelf();
    }

    public void setBorderTint(ColorStateList tint) {
        if (tint != null) {
            this.currentBorderTintColor = tint.getColorForState(getState(), this.currentBorderTintColor);
        }
        this.borderTint = tint;
        this.invalidateShader = true;
        invalidateSelf();
    }

    public void setColorFilter(ColorFilter colorFilter) {
        this.paint.setColorFilter(colorFilter);
        invalidateSelf();
    }

    public int getOpacity() {
        return this.borderWidth > 0.0f ? -3 : -2;
    }

    public final void setRotation(float rotation2) {
        if (rotation2 != this.rotation) {
            this.rotation = rotation2;
            invalidateSelf();
        }
    }

    /* access modifiers changed from: protected */
    public void onBoundsChange(Rect bounds) {
        this.invalidateShader = true;
    }

    public boolean isStateful() {
        ColorStateList colorStateList = this.borderTint;
        return (colorStateList != null && colorStateList.isStateful()) || super.isStateful();
    }

    /* access modifiers changed from: protected */
    public boolean onStateChange(int[] state2) {
        ColorStateList colorStateList = this.borderTint;
        if (colorStateList != null) {
            int newColor = colorStateList.getColorForState(state2, this.currentBorderTintColor);
            if (newColor != this.currentBorderTintColor) {
                this.invalidateShader = true;
                this.currentBorderTintColor = newColor;
            }
        }
        if (this.invalidateShader != 0) {
            invalidateSelf();
        }
        return this.invalidateShader;
    }

    private Shader createGradientShader() {
        Rect rect2 = this.rect;
        copyBounds(rect2);
        float borderRatio = this.borderWidth / ((float) rect2.height());
        LinearGradient linearGradient = new LinearGradient(0.0f, (float) rect2.top, 0.0f, (float) rect2.bottom, new int[]{ColorUtils.compositeColors(this.topOuterStrokeColor, this.currentBorderTintColor), ColorUtils.compositeColors(this.topInnerStrokeColor, this.currentBorderTintColor), ColorUtils.compositeColors(ColorUtils.setAlphaComponent(this.topInnerStrokeColor, 0), this.currentBorderTintColor), ColorUtils.compositeColors(ColorUtils.setAlphaComponent(this.bottomInnerStrokeColor, 0), this.currentBorderTintColor), ColorUtils.compositeColors(this.bottomInnerStrokeColor, this.currentBorderTintColor), ColorUtils.compositeColors(this.bottomOuterStrokeColor, this.currentBorderTintColor)}, new float[]{0.0f, borderRatio, 0.5f, 0.5f, 1.0f - borderRatio, 1.0f}, TileMode.CLAMP);
        return linearGradient;
    }
}
