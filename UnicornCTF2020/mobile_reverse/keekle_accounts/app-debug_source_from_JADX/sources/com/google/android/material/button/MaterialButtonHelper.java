package com.google.android.material.button;

import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build.VERSION;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.ripple.RippleUtils;

class MaterialButtonHelper {
    private static final float CORNER_RADIUS_ADJUSTMENT = 1.0E-5f;
    private static final int DEFAULT_BACKGROUND_COLOR = -1;
    private static final boolean IS_LOLLIPOP = (VERSION.SDK_INT >= 21);
    private GradientDrawable backgroundDrawableLollipop;
    private boolean backgroundOverwritten = false;
    private ColorStateList backgroundTint;
    private Mode backgroundTintMode;
    private final Rect bounds = new Rect();
    private final Paint buttonStrokePaint = new Paint(1);
    private GradientDrawable colorableBackgroundDrawableCompat;
    private int cornerRadius;
    private int insetBottom;
    private int insetLeft;
    private int insetRight;
    private int insetTop;
    private GradientDrawable maskDrawableLollipop;
    private final MaterialButton materialButton;
    private final RectF rectF = new RectF();
    private ColorStateList rippleColor;
    private GradientDrawable rippleDrawableCompat;
    private ColorStateList strokeColor;
    private GradientDrawable strokeDrawableLollipop;
    private int strokeWidth;
    private Drawable tintableBackgroundDrawableCompat;
    private Drawable tintableRippleDrawableCompat;

    public MaterialButtonHelper(MaterialButton button) {
        this.materialButton = button;
    }

    public void loadFromAttributes(TypedArray attributes) {
        int i = 0;
        this.insetLeft = attributes.getDimensionPixelOffset(C0078R.styleable.MaterialButton_android_insetLeft, 0);
        this.insetRight = attributes.getDimensionPixelOffset(C0078R.styleable.MaterialButton_android_insetRight, 0);
        this.insetTop = attributes.getDimensionPixelOffset(C0078R.styleable.MaterialButton_android_insetTop, 0);
        this.insetBottom = attributes.getDimensionPixelOffset(C0078R.styleable.MaterialButton_android_insetBottom, 0);
        this.cornerRadius = attributes.getDimensionPixelSize(C0078R.styleable.MaterialButton_cornerRadius, 0);
        this.strokeWidth = attributes.getDimensionPixelSize(C0078R.styleable.MaterialButton_strokeWidth, 0);
        this.backgroundTintMode = ViewUtils.parseTintMode(attributes.getInt(C0078R.styleable.MaterialButton_backgroundTintMode, -1), Mode.SRC_IN);
        this.backgroundTint = MaterialResources.getColorStateList(this.materialButton.getContext(), attributes, C0078R.styleable.MaterialButton_backgroundTint);
        this.strokeColor = MaterialResources.getColorStateList(this.materialButton.getContext(), attributes, C0078R.styleable.MaterialButton_strokeColor);
        this.rippleColor = MaterialResources.getColorStateList(this.materialButton.getContext(), attributes, C0078R.styleable.MaterialButton_rippleColor);
        this.buttonStrokePaint.setStyle(Style.STROKE);
        this.buttonStrokePaint.setStrokeWidth((float) this.strokeWidth);
        Paint paint = this.buttonStrokePaint;
        ColorStateList colorStateList = this.strokeColor;
        if (colorStateList != null) {
            i = colorStateList.getColorForState(this.materialButton.getDrawableState(), 0);
        }
        paint.setColor(i);
        int paddingStart = ViewCompat.getPaddingStart(this.materialButton);
        int paddingTop = this.materialButton.getPaddingTop();
        int paddingEnd = ViewCompat.getPaddingEnd(this.materialButton);
        int paddingBottom = this.materialButton.getPaddingBottom();
        this.materialButton.setInternalBackground(IS_LOLLIPOP ? createBackgroundLollipop() : createBackgroundCompat());
        ViewCompat.setPaddingRelative(this.materialButton, this.insetLeft + paddingStart, this.insetTop + paddingTop, this.insetRight + paddingEnd, this.insetBottom + paddingBottom);
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundOverwritten() {
        this.backgroundOverwritten = true;
        this.materialButton.setSupportBackgroundTintList(this.backgroundTint);
        this.materialButton.setSupportBackgroundTintMode(this.backgroundTintMode);
    }

    /* access modifiers changed from: 0000 */
    public boolean isBackgroundOverwritten() {
        return this.backgroundOverwritten;
    }

    /* access modifiers changed from: 0000 */
    public void drawStroke(Canvas canvas) {
        if (canvas != null && this.strokeColor != null && this.strokeWidth > 0) {
            this.bounds.set(this.materialButton.getBackground().getBounds());
            this.rectF.set(((float) this.bounds.left) + (((float) this.strokeWidth) / 2.0f) + ((float) this.insetLeft), ((float) this.bounds.top) + (((float) this.strokeWidth) / 2.0f) + ((float) this.insetTop), (((float) this.bounds.right) - (((float) this.strokeWidth) / 2.0f)) - ((float) this.insetRight), (((float) this.bounds.bottom) - (((float) this.strokeWidth) / 2.0f)) - ((float) this.insetBottom));
            float strokeCornerRadius = ((float) this.cornerRadius) - (((float) this.strokeWidth) / 2.0f);
            canvas.drawRoundRect(this.rectF, strokeCornerRadius, strokeCornerRadius, this.buttonStrokePaint);
        }
    }

    private Drawable createBackgroundCompat() {
        GradientDrawable gradientDrawable = new GradientDrawable();
        this.colorableBackgroundDrawableCompat = gradientDrawable;
        gradientDrawable.setCornerRadius(((float) this.cornerRadius) + CORNER_RADIUS_ADJUSTMENT);
        this.colorableBackgroundDrawableCompat.setColor(-1);
        Drawable wrap = DrawableCompat.wrap(this.colorableBackgroundDrawableCompat);
        this.tintableBackgroundDrawableCompat = wrap;
        DrawableCompat.setTintList(wrap, this.backgroundTint);
        Mode mode = this.backgroundTintMode;
        if (mode != null) {
            DrawableCompat.setTintMode(this.tintableBackgroundDrawableCompat, mode);
        }
        GradientDrawable gradientDrawable2 = new GradientDrawable();
        this.rippleDrawableCompat = gradientDrawable2;
        gradientDrawable2.setCornerRadius(((float) this.cornerRadius) + CORNER_RADIUS_ADJUSTMENT);
        this.rippleDrawableCompat.setColor(-1);
        Drawable wrap2 = DrawableCompat.wrap(this.rippleDrawableCompat);
        this.tintableRippleDrawableCompat = wrap2;
        DrawableCompat.setTintList(wrap2, this.rippleColor);
        return wrapDrawableWithInset(new LayerDrawable(new Drawable[]{this.tintableBackgroundDrawableCompat, this.tintableRippleDrawableCompat}));
    }

    private InsetDrawable wrapDrawableWithInset(Drawable drawable) {
        InsetDrawable insetDrawable = new InsetDrawable(drawable, this.insetLeft, this.insetTop, this.insetRight, this.insetBottom);
        return insetDrawable;
    }

    /* access modifiers changed from: 0000 */
    public void setSupportBackgroundTintList(ColorStateList tintList) {
        if (this.backgroundTint != tintList) {
            this.backgroundTint = tintList;
            if (IS_LOLLIPOP) {
                updateTintAndTintModeLollipop();
                return;
            }
            Drawable drawable = this.tintableBackgroundDrawableCompat;
            if (drawable != null) {
                DrawableCompat.setTintList(drawable, tintList);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getSupportBackgroundTintList() {
        return this.backgroundTint;
    }

    /* access modifiers changed from: 0000 */
    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.backgroundTintMode != mode) {
            this.backgroundTintMode = mode;
            if (IS_LOLLIPOP) {
                updateTintAndTintModeLollipop();
                return;
            }
            Drawable drawable = this.tintableBackgroundDrawableCompat;
            if (drawable != null && mode != null) {
                DrawableCompat.setTintMode(drawable, mode);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public Mode getSupportBackgroundTintMode() {
        return this.backgroundTintMode;
    }

    private void updateTintAndTintModeLollipop() {
        GradientDrawable gradientDrawable = this.backgroundDrawableLollipop;
        if (gradientDrawable != null) {
            DrawableCompat.setTintList(gradientDrawable, this.backgroundTint);
            Mode mode = this.backgroundTintMode;
            if (mode != null) {
                DrawableCompat.setTintMode(this.backgroundDrawableLollipop, mode);
            }
        }
    }

    private Drawable createBackgroundLollipop() {
        GradientDrawable gradientDrawable = new GradientDrawable();
        this.backgroundDrawableLollipop = gradientDrawable;
        gradientDrawable.setCornerRadius(((float) this.cornerRadius) + CORNER_RADIUS_ADJUSTMENT);
        this.backgroundDrawableLollipop.setColor(-1);
        updateTintAndTintModeLollipop();
        GradientDrawable gradientDrawable2 = new GradientDrawable();
        this.strokeDrawableLollipop = gradientDrawable2;
        gradientDrawable2.setCornerRadius(((float) this.cornerRadius) + CORNER_RADIUS_ADJUSTMENT);
        this.strokeDrawableLollipop.setColor(0);
        this.strokeDrawableLollipop.setStroke(this.strokeWidth, this.strokeColor);
        InsetDrawable bgInsetDrawable = wrapDrawableWithInset(new LayerDrawable(new Drawable[]{this.backgroundDrawableLollipop, this.strokeDrawableLollipop}));
        GradientDrawable gradientDrawable3 = new GradientDrawable();
        this.maskDrawableLollipop = gradientDrawable3;
        gradientDrawable3.setCornerRadius(((float) this.cornerRadius) + CORNER_RADIUS_ADJUSTMENT);
        this.maskDrawableLollipop.setColor(-1);
        return new MaterialButtonBackgroundDrawable(RippleUtils.convertToRippleDrawableColor(this.rippleColor), bgInsetDrawable, this.maskDrawableLollipop);
    }

    /* access modifiers changed from: 0000 */
    public void updateMaskBounds(int height, int width) {
        GradientDrawable gradientDrawable = this.maskDrawableLollipop;
        if (gradientDrawable != null) {
            gradientDrawable.setBounds(this.insetLeft, this.insetTop, width - this.insetRight, height - this.insetBottom);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundColor(int color) {
        if (IS_LOLLIPOP) {
            GradientDrawable gradientDrawable = this.backgroundDrawableLollipop;
            if (gradientDrawable != null) {
                gradientDrawable.setColor(color);
                return;
            }
        }
        if (!IS_LOLLIPOP) {
            GradientDrawable gradientDrawable2 = this.colorableBackgroundDrawableCompat;
            if (gradientDrawable2 != null) {
                gradientDrawable2.setColor(color);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void setRippleColor(ColorStateList rippleColor2) {
        if (this.rippleColor != rippleColor2) {
            this.rippleColor = rippleColor2;
            if (IS_LOLLIPOP && (this.materialButton.getBackground() instanceof RippleDrawable)) {
                ((RippleDrawable) this.materialButton.getBackground()).setColor(rippleColor2);
            } else if (!IS_LOLLIPOP) {
                Drawable drawable = this.tintableRippleDrawableCompat;
                if (drawable != null) {
                    DrawableCompat.setTintList(drawable, rippleColor2);
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getRippleColor() {
        return this.rippleColor;
    }

    /* access modifiers changed from: 0000 */
    public void setStrokeColor(ColorStateList strokeColor2) {
        if (this.strokeColor != strokeColor2) {
            this.strokeColor = strokeColor2;
            Paint paint = this.buttonStrokePaint;
            int i = 0;
            if (strokeColor2 != null) {
                i = strokeColor2.getColorForState(this.materialButton.getDrawableState(), 0);
            }
            paint.setColor(i);
            updateStroke();
        }
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getStrokeColor() {
        return this.strokeColor;
    }

    /* access modifiers changed from: 0000 */
    public void setStrokeWidth(int strokeWidth2) {
        if (this.strokeWidth != strokeWidth2) {
            this.strokeWidth = strokeWidth2;
            this.buttonStrokePaint.setStrokeWidth((float) strokeWidth2);
            updateStroke();
        }
    }

    /* access modifiers changed from: 0000 */
    public int getStrokeWidth() {
        return this.strokeWidth;
    }

    private void updateStroke() {
        if (IS_LOLLIPOP && this.strokeDrawableLollipop != null) {
            this.materialButton.setInternalBackground(createBackgroundLollipop());
        } else if (!IS_LOLLIPOP) {
            this.materialButton.invalidate();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setCornerRadius(int cornerRadius2) {
        if (this.cornerRadius != cornerRadius2) {
            this.cornerRadius = cornerRadius2;
            if (IS_LOLLIPOP && this.backgroundDrawableLollipop != null && this.strokeDrawableLollipop != null && this.maskDrawableLollipop != null) {
                if (VERSION.SDK_INT == 21) {
                    unwrapBackgroundDrawable().setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                    unwrapStrokeDrawable().setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                }
                this.backgroundDrawableLollipop.setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                this.strokeDrawableLollipop.setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                this.maskDrawableLollipop.setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
            } else if (!IS_LOLLIPOP) {
                GradientDrawable gradientDrawable = this.colorableBackgroundDrawableCompat;
                if (gradientDrawable != null && this.rippleDrawableCompat != null) {
                    gradientDrawable.setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                    this.rippleDrawableCompat.setCornerRadius(((float) cornerRadius2) + CORNER_RADIUS_ADJUSTMENT);
                    this.materialButton.invalidate();
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public int getCornerRadius() {
        return this.cornerRadius;
    }

    private GradientDrawable unwrapStrokeDrawable() {
        if (!IS_LOLLIPOP || this.materialButton.getBackground() == null) {
            return null;
        }
        return (GradientDrawable) ((LayerDrawable) ((InsetDrawable) ((RippleDrawable) this.materialButton.getBackground()).getDrawable(0)).getDrawable()).getDrawable(1);
    }

    private GradientDrawable unwrapBackgroundDrawable() {
        if (!IS_LOLLIPOP || this.materialButton.getBackground() == null) {
            return null;
        }
        return (GradientDrawable) ((LayerDrawable) ((InsetDrawable) ((RippleDrawable) this.materialButton.getBackground()).getDrawable(0)).getDrawable()).getDrawable(0);
    }
}
