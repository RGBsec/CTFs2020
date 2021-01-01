package com.google.android.material.internal;

import android.animation.TimeInterpolator;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.os.Build.VERSION;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextUtils.TruncateAt;
import android.view.View;
import androidx.appcompat.C0003R;
import androidx.appcompat.widget.TintTypedArray;
import androidx.core.math.MathUtils;
import androidx.core.text.TextDirectionHeuristicsCompat;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.animation.AnimationUtils;

public final class CollapsingTextHelper {
    private static final boolean DEBUG_DRAW = false;
    private static final Paint DEBUG_DRAW_PAINT;
    private static final boolean USE_SCALING_TEXTURE = (VERSION.SDK_INT < 18);
    private boolean boundsChanged;
    private final Rect collapsedBounds;
    private float collapsedDrawX;
    private float collapsedDrawY;
    private int collapsedShadowColor;
    private float collapsedShadowDx;
    private float collapsedShadowDy;
    private float collapsedShadowRadius;
    private ColorStateList collapsedTextColor;
    private int collapsedTextGravity = 16;
    private float collapsedTextSize = 15.0f;
    private Typeface collapsedTypeface;
    private final RectF currentBounds;
    private float currentDrawX;
    private float currentDrawY;
    private float currentTextSize;
    private Typeface currentTypeface;
    private boolean drawTitle;
    private final Rect expandedBounds;
    private float expandedDrawX;
    private float expandedDrawY;
    private float expandedFraction;
    private int expandedShadowColor;
    private float expandedShadowDx;
    private float expandedShadowDy;
    private float expandedShadowRadius;
    private ColorStateList expandedTextColor;
    private int expandedTextGravity = 16;
    private float expandedTextSize = 15.0f;
    private Bitmap expandedTitleTexture;
    private Typeface expandedTypeface;
    private boolean isRtl;
    private TimeInterpolator positionInterpolator;
    private float scale;
    private int[] state;
    private CharSequence text;
    private final TextPaint textPaint;
    private TimeInterpolator textSizeInterpolator;
    private CharSequence textToDraw;
    private float textureAscent;
    private float textureDescent;
    private Paint texturePaint;
    private final TextPaint tmpPaint;
    private boolean useTexture;
    private final View view;

    static {
        Paint paint = null;
        DEBUG_DRAW_PAINT = paint;
        if (paint != null) {
            paint.setAntiAlias(true);
            DEBUG_DRAW_PAINT.setColor(-65281);
        }
    }

    public CollapsingTextHelper(View view2) {
        this.view = view2;
        this.textPaint = new TextPaint(129);
        this.tmpPaint = new TextPaint(this.textPaint);
        this.collapsedBounds = new Rect();
        this.expandedBounds = new Rect();
        this.currentBounds = new RectF();
    }

    public void setTextSizeInterpolator(TimeInterpolator interpolator) {
        this.textSizeInterpolator = interpolator;
        recalculate();
    }

    public void setPositionInterpolator(TimeInterpolator interpolator) {
        this.positionInterpolator = interpolator;
        recalculate();
    }

    public void setExpandedTextSize(float textSize) {
        if (this.expandedTextSize != textSize) {
            this.expandedTextSize = textSize;
            recalculate();
        }
    }

    public void setCollapsedTextSize(float textSize) {
        if (this.collapsedTextSize != textSize) {
            this.collapsedTextSize = textSize;
            recalculate();
        }
    }

    public void setCollapsedTextColor(ColorStateList textColor) {
        if (this.collapsedTextColor != textColor) {
            this.collapsedTextColor = textColor;
            recalculate();
        }
    }

    public void setExpandedTextColor(ColorStateList textColor) {
        if (this.expandedTextColor != textColor) {
            this.expandedTextColor = textColor;
            recalculate();
        }
    }

    public void setExpandedBounds(int left, int top, int right, int bottom) {
        if (!rectEquals(this.expandedBounds, left, top, right, bottom)) {
            this.expandedBounds.set(left, top, right, bottom);
            this.boundsChanged = true;
            onBoundsChanged();
        }
    }

    public void setCollapsedBounds(int left, int top, int right, int bottom) {
        if (!rectEquals(this.collapsedBounds, left, top, right, bottom)) {
            this.collapsedBounds.set(left, top, right, bottom);
            this.boundsChanged = true;
            onBoundsChanged();
        }
    }

    public float calculateCollapsedTextWidth() {
        if (this.text == null) {
            return 0.0f;
        }
        getTextPaintCollapsed(this.tmpPaint);
        TextPaint textPaint2 = this.tmpPaint;
        CharSequence charSequence = this.text;
        return textPaint2.measureText(charSequence, 0, charSequence.length());
    }

    public float getCollapsedTextHeight() {
        getTextPaintCollapsed(this.tmpPaint);
        return -this.tmpPaint.ascent();
    }

    public void getCollapsedTextActualBounds(RectF bounds) {
        float f;
        boolean isRtl2 = calculateIsRtl(this.text);
        Rect rect = this.collapsedBounds;
        if (!isRtl2) {
            f = (float) rect.left;
        } else {
            f = ((float) rect.right) - calculateCollapsedTextWidth();
        }
        bounds.left = f;
        bounds.top = (float) this.collapsedBounds.top;
        bounds.right = !isRtl2 ? bounds.left + calculateCollapsedTextWidth() : (float) this.collapsedBounds.right;
        bounds.bottom = ((float) this.collapsedBounds.top) + getCollapsedTextHeight();
    }

    private void getTextPaintCollapsed(TextPaint textPaint2) {
        textPaint2.setTextSize(this.collapsedTextSize);
        textPaint2.setTypeface(this.collapsedTypeface);
    }

    /* access modifiers changed from: 0000 */
    public void onBoundsChanged() {
        this.drawTitle = this.collapsedBounds.width() > 0 && this.collapsedBounds.height() > 0 && this.expandedBounds.width() > 0 && this.expandedBounds.height() > 0;
    }

    public void setExpandedTextGravity(int gravity) {
        if (this.expandedTextGravity != gravity) {
            this.expandedTextGravity = gravity;
            recalculate();
        }
    }

    public int getExpandedTextGravity() {
        return this.expandedTextGravity;
    }

    public void setCollapsedTextGravity(int gravity) {
        if (this.collapsedTextGravity != gravity) {
            this.collapsedTextGravity = gravity;
            recalculate();
        }
    }

    public int getCollapsedTextGravity() {
        return this.collapsedTextGravity;
    }

    public void setCollapsedTextAppearance(int resId) {
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(this.view.getContext(), resId, C0003R.styleable.TextAppearance);
        if (a.hasValue(C0003R.styleable.TextAppearance_android_textColor)) {
            this.collapsedTextColor = a.getColorStateList(C0003R.styleable.TextAppearance_android_textColor);
        }
        if (a.hasValue(C0003R.styleable.TextAppearance_android_textSize)) {
            this.collapsedTextSize = (float) a.getDimensionPixelSize(C0003R.styleable.TextAppearance_android_textSize, (int) this.collapsedTextSize);
        }
        this.collapsedShadowColor = a.getInt(C0003R.styleable.TextAppearance_android_shadowColor, 0);
        this.collapsedShadowDx = a.getFloat(C0003R.styleable.TextAppearance_android_shadowDx, 0.0f);
        this.collapsedShadowDy = a.getFloat(C0003R.styleable.TextAppearance_android_shadowDy, 0.0f);
        this.collapsedShadowRadius = a.getFloat(C0003R.styleable.TextAppearance_android_shadowRadius, 0.0f);
        a.recycle();
        if (VERSION.SDK_INT >= 16) {
            this.collapsedTypeface = readFontFamilyTypeface(resId);
        }
        recalculate();
    }

    public void setExpandedTextAppearance(int resId) {
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(this.view.getContext(), resId, C0003R.styleable.TextAppearance);
        if (a.hasValue(C0003R.styleable.TextAppearance_android_textColor)) {
            this.expandedTextColor = a.getColorStateList(C0003R.styleable.TextAppearance_android_textColor);
        }
        if (a.hasValue(C0003R.styleable.TextAppearance_android_textSize)) {
            this.expandedTextSize = (float) a.getDimensionPixelSize(C0003R.styleable.TextAppearance_android_textSize, (int) this.expandedTextSize);
        }
        this.expandedShadowColor = a.getInt(C0003R.styleable.TextAppearance_android_shadowColor, 0);
        this.expandedShadowDx = a.getFloat(C0003R.styleable.TextAppearance_android_shadowDx, 0.0f);
        this.expandedShadowDy = a.getFloat(C0003R.styleable.TextAppearance_android_shadowDy, 0.0f);
        this.expandedShadowRadius = a.getFloat(C0003R.styleable.TextAppearance_android_shadowRadius, 0.0f);
        a.recycle();
        if (VERSION.SDK_INT >= 16) {
            this.expandedTypeface = readFontFamilyTypeface(resId);
        }
        recalculate();
    }

    private Typeface readFontFamilyTypeface(int resId) {
        TypedArray a = this.view.getContext().obtainStyledAttributes(resId, new int[]{16843692});
        try {
            String family = a.getString(0);
            if (family != null) {
                return Typeface.create(family, 0);
            }
            a.recycle();
            return null;
        } finally {
            a.recycle();
        }
    }

    public void setCollapsedTypeface(Typeface typeface) {
        if (this.collapsedTypeface != typeface) {
            this.collapsedTypeface = typeface;
            recalculate();
        }
    }

    public void setExpandedTypeface(Typeface typeface) {
        if (this.expandedTypeface != typeface) {
            this.expandedTypeface = typeface;
            recalculate();
        }
    }

    public void setTypefaces(Typeface typeface) {
        this.expandedTypeface = typeface;
        this.collapsedTypeface = typeface;
        recalculate();
    }

    public Typeface getCollapsedTypeface() {
        Typeface typeface = this.collapsedTypeface;
        return typeface != null ? typeface : Typeface.DEFAULT;
    }

    public Typeface getExpandedTypeface() {
        Typeface typeface = this.expandedTypeface;
        return typeface != null ? typeface : Typeface.DEFAULT;
    }

    public void setExpansionFraction(float fraction) {
        float fraction2 = MathUtils.clamp(fraction, 0.0f, 1.0f);
        if (fraction2 != this.expandedFraction) {
            this.expandedFraction = fraction2;
            calculateCurrentOffsets();
        }
    }

    public final boolean setState(int[] state2) {
        this.state = state2;
        if (!isStateful()) {
            return false;
        }
        recalculate();
        return true;
    }

    public final boolean isStateful() {
        ColorStateList colorStateList = this.collapsedTextColor;
        if (colorStateList == null || !colorStateList.isStateful()) {
            ColorStateList colorStateList2 = this.expandedTextColor;
            if (colorStateList2 == null || !colorStateList2.isStateful()) {
                return false;
            }
        }
        return true;
    }

    public float getExpansionFraction() {
        return this.expandedFraction;
    }

    public float getCollapsedTextSize() {
        return this.collapsedTextSize;
    }

    public float getExpandedTextSize() {
        return this.expandedTextSize;
    }

    private void calculateCurrentOffsets() {
        calculateOffsets(this.expandedFraction);
    }

    private void calculateOffsets(float fraction) {
        interpolateBounds(fraction);
        this.currentDrawX = lerp(this.expandedDrawX, this.collapsedDrawX, fraction, this.positionInterpolator);
        this.currentDrawY = lerp(this.expandedDrawY, this.collapsedDrawY, fraction, this.positionInterpolator);
        setInterpolatedTextSize(lerp(this.expandedTextSize, this.collapsedTextSize, fraction, this.textSizeInterpolator));
        if (this.collapsedTextColor != this.expandedTextColor) {
            this.textPaint.setColor(blendColors(getCurrentExpandedTextColor(), getCurrentCollapsedTextColor(), fraction));
        } else {
            this.textPaint.setColor(getCurrentCollapsedTextColor());
        }
        this.textPaint.setShadowLayer(lerp(this.expandedShadowRadius, this.collapsedShadowRadius, fraction, null), lerp(this.expandedShadowDx, this.collapsedShadowDx, fraction, null), lerp(this.expandedShadowDy, this.collapsedShadowDy, fraction, null), blendColors(this.expandedShadowColor, this.collapsedShadowColor, fraction));
        ViewCompat.postInvalidateOnAnimation(this.view);
    }

    private int getCurrentExpandedTextColor() {
        int[] iArr = this.state;
        if (iArr != null) {
            return this.expandedTextColor.getColorForState(iArr, 0);
        }
        return this.expandedTextColor.getDefaultColor();
    }

    public int getCurrentCollapsedTextColor() {
        int[] iArr = this.state;
        if (iArr != null) {
            return this.collapsedTextColor.getColorForState(iArr, 0);
        }
        return this.collapsedTextColor.getDefaultColor();
    }

    private void calculateBaseOffsets() {
        float currentTextSize2 = this.currentTextSize;
        calculateUsingTextSize(this.collapsedTextSize);
        CharSequence charSequence = this.textToDraw;
        float f = 0.0f;
        float width = charSequence != null ? this.textPaint.measureText(charSequence, 0, charSequence.length()) : 0.0f;
        int collapsedAbsGravity = GravityCompat.getAbsoluteGravity(this.collapsedTextGravity, this.isRtl ? 1 : 0);
        int i = collapsedAbsGravity & 112;
        if (i == 48) {
            this.collapsedDrawY = ((float) this.collapsedBounds.top) - this.textPaint.ascent();
        } else if (i != 80) {
            this.collapsedDrawY = ((float) this.collapsedBounds.centerY()) + (((this.textPaint.descent() - this.textPaint.ascent()) / 2.0f) - this.textPaint.descent());
        } else {
            this.collapsedDrawY = (float) this.collapsedBounds.bottom;
        }
        int i2 = collapsedAbsGravity & GravityCompat.RELATIVE_HORIZONTAL_GRAVITY_MASK;
        if (i2 == 1) {
            this.collapsedDrawX = ((float) this.collapsedBounds.centerX()) - (width / 2.0f);
        } else if (i2 != 5) {
            this.collapsedDrawX = (float) this.collapsedBounds.left;
        } else {
            this.collapsedDrawX = ((float) this.collapsedBounds.right) - width;
        }
        calculateUsingTextSize(this.expandedTextSize);
        CharSequence charSequence2 = this.textToDraw;
        if (charSequence2 != null) {
            f = this.textPaint.measureText(charSequence2, 0, charSequence2.length());
        }
        float width2 = f;
        int expandedAbsGravity = GravityCompat.getAbsoluteGravity(this.expandedTextGravity, this.isRtl ? 1 : 0);
        int i3 = expandedAbsGravity & 112;
        if (i3 == 48) {
            this.expandedDrawY = ((float) this.expandedBounds.top) - this.textPaint.ascent();
        } else if (i3 != 80) {
            this.expandedDrawY = ((float) this.expandedBounds.centerY()) + (((this.textPaint.descent() - this.textPaint.ascent()) / 2.0f) - this.textPaint.descent());
        } else {
            this.expandedDrawY = (float) this.expandedBounds.bottom;
        }
        int i4 = expandedAbsGravity & GravityCompat.RELATIVE_HORIZONTAL_GRAVITY_MASK;
        if (i4 == 1) {
            this.expandedDrawX = ((float) this.expandedBounds.centerX()) - (width2 / 2.0f);
        } else if (i4 != 5) {
            this.expandedDrawX = (float) this.expandedBounds.left;
        } else {
            this.expandedDrawX = ((float) this.expandedBounds.right) - width2;
        }
        clearTexture();
        setInterpolatedTextSize(currentTextSize2);
    }

    private void interpolateBounds(float fraction) {
        this.currentBounds.left = lerp((float) this.expandedBounds.left, (float) this.collapsedBounds.left, fraction, this.positionInterpolator);
        this.currentBounds.top = lerp(this.expandedDrawY, this.collapsedDrawY, fraction, this.positionInterpolator);
        this.currentBounds.right = lerp((float) this.expandedBounds.right, (float) this.collapsedBounds.right, fraction, this.positionInterpolator);
        this.currentBounds.bottom = lerp((float) this.expandedBounds.bottom, (float) this.collapsedBounds.bottom, fraction, this.positionInterpolator);
    }

    public void draw(Canvas canvas) {
        float ascent;
        float y;
        int saveCount = canvas.save();
        if (this.textToDraw != null && this.drawTitle) {
            float x = this.currentDrawX;
            float y2 = this.currentDrawY;
            boolean drawTexture = this.useTexture && this.expandedTitleTexture != null;
            if (drawTexture) {
                float f = this.textureAscent;
                float f2 = this.scale;
                ascent = f * f2;
                float f3 = this.textureDescent * f2;
            } else {
                ascent = this.textPaint.ascent() * this.scale;
                float descent = this.scale * this.textPaint.descent();
            }
            if (drawTexture) {
                y = y2 + ascent;
            } else {
                y = y2;
            }
            float y3 = this.scale;
            if (y3 != 1.0f) {
                canvas.scale(y3, y3, x, y);
            }
            if (drawTexture) {
                canvas.drawBitmap(this.expandedTitleTexture, x, y, this.texturePaint);
            } else {
                CharSequence charSequence = this.textToDraw;
                canvas.drawText(charSequence, 0, charSequence.length(), x, y, this.textPaint);
            }
        }
        canvas.restoreToCount(saveCount);
    }

    private boolean calculateIsRtl(CharSequence text2) {
        boolean z = true;
        if (ViewCompat.getLayoutDirection(this.view) != 1) {
            z = false;
        }
        return (z ? TextDirectionHeuristicsCompat.FIRSTSTRONG_RTL : TextDirectionHeuristicsCompat.FIRSTSTRONG_LTR).isRtl(text2, 0, text2.length());
    }

    private void setInterpolatedTextSize(float textSize) {
        calculateUsingTextSize(textSize);
        boolean z = USE_SCALING_TEXTURE && this.scale != 1.0f;
        this.useTexture = z;
        if (z) {
            ensureExpandedTexture();
        }
        ViewCompat.postInvalidateOnAnimation(this.view);
    }

    private void calculateUsingTextSize(float textSize) {
        float textSizeRatio;
        float newTextSize;
        if (this.text != null) {
            float collapsedWidth = (float) this.collapsedBounds.width();
            float expandedWidth = (float) this.expandedBounds.width();
            boolean updateDrawText = false;
            if (isClose(textSize, this.collapsedTextSize)) {
                newTextSize = this.collapsedTextSize;
                this.scale = 1.0f;
                Typeface typeface = this.currentTypeface;
                Typeface typeface2 = this.collapsedTypeface;
                if (typeface != typeface2) {
                    this.currentTypeface = typeface2;
                    updateDrawText = true;
                }
                textSizeRatio = collapsedWidth;
            } else {
                newTextSize = this.expandedTextSize;
                Typeface typeface3 = this.currentTypeface;
                Typeface typeface4 = this.expandedTypeface;
                if (typeface3 != typeface4) {
                    this.currentTypeface = typeface4;
                    updateDrawText = true;
                }
                if (isClose(textSize, this.expandedTextSize)) {
                    this.scale = 1.0f;
                } else {
                    this.scale = textSize / this.expandedTextSize;
                }
                float textSizeRatio2 = this.collapsedTextSize / this.expandedTextSize;
                if (expandedWidth * textSizeRatio2 > collapsedWidth) {
                    textSizeRatio = Math.min(collapsedWidth / textSizeRatio2, expandedWidth);
                } else {
                    textSizeRatio = expandedWidth;
                }
            }
            boolean z = true;
            if (textSizeRatio > 0.0f) {
                updateDrawText = this.currentTextSize != newTextSize || this.boundsChanged || updateDrawText;
                this.currentTextSize = newTextSize;
                this.boundsChanged = false;
            }
            if (this.textToDraw == null || updateDrawText) {
                this.textPaint.setTextSize(this.currentTextSize);
                this.textPaint.setTypeface(this.currentTypeface);
                TextPaint textPaint2 = this.textPaint;
                if (this.scale == 1.0f) {
                    z = false;
                }
                textPaint2.setLinearText(z);
                CharSequence title = TextUtils.ellipsize(this.text, this.textPaint, textSizeRatio, TruncateAt.END);
                if (!TextUtils.equals(title, this.textToDraw)) {
                    this.textToDraw = title;
                    this.isRtl = calculateIsRtl(title);
                }
            }
        }
    }

    private void ensureExpandedTexture() {
        if (this.expandedTitleTexture == null && !this.expandedBounds.isEmpty() && !TextUtils.isEmpty(this.textToDraw)) {
            calculateOffsets(0.0f);
            this.textureAscent = this.textPaint.ascent();
            this.textureDescent = this.textPaint.descent();
            TextPaint textPaint2 = this.textPaint;
            CharSequence charSequence = this.textToDraw;
            int w = Math.round(textPaint2.measureText(charSequence, 0, charSequence.length()));
            int h = Math.round(this.textureDescent - this.textureAscent);
            if (w > 0 && h > 0) {
                this.expandedTitleTexture = Bitmap.createBitmap(w, h, Config.ARGB_8888);
                Canvas c = new Canvas(this.expandedTitleTexture);
                CharSequence charSequence2 = this.textToDraw;
                c.drawText(charSequence2, 0, charSequence2.length(), 0.0f, ((float) h) - this.textPaint.descent(), this.textPaint);
                if (this.texturePaint == null) {
                    this.texturePaint = new Paint(3);
                }
            }
        }
    }

    public void recalculate() {
        if (this.view.getHeight() > 0 && this.view.getWidth() > 0) {
            calculateBaseOffsets();
            calculateCurrentOffsets();
        }
    }

    public void setText(CharSequence text2) {
        if (text2 == null || !text2.equals(this.text)) {
            this.text = text2;
            this.textToDraw = null;
            clearTexture();
            recalculate();
        }
    }

    public CharSequence getText() {
        return this.text;
    }

    private void clearTexture() {
        Bitmap bitmap = this.expandedTitleTexture;
        if (bitmap != null) {
            bitmap.recycle();
            this.expandedTitleTexture = null;
        }
    }

    private static boolean isClose(float value, float targetValue) {
        return Math.abs(value - targetValue) < 0.001f;
    }

    public ColorStateList getExpandedTextColor() {
        return this.expandedTextColor;
    }

    public ColorStateList getCollapsedTextColor() {
        return this.collapsedTextColor;
    }

    private static int blendColors(int color1, int color2, float ratio) {
        float inverseRatio = 1.0f - ratio;
        return Color.argb((int) ((((float) Color.alpha(color1)) * inverseRatio) + (((float) Color.alpha(color2)) * ratio)), (int) ((((float) Color.red(color1)) * inverseRatio) + (((float) Color.red(color2)) * ratio)), (int) ((((float) Color.green(color1)) * inverseRatio) + (((float) Color.green(color2)) * ratio)), (int) ((((float) Color.blue(color1)) * inverseRatio) + (((float) Color.blue(color2)) * ratio)));
    }

    private static float lerp(float startValue, float endValue, float fraction, TimeInterpolator interpolator) {
        if (interpolator != null) {
            fraction = interpolator.getInterpolation(fraction);
        }
        return AnimationUtils.lerp(startValue, endValue, fraction);
    }

    private static boolean rectEquals(Rect r, int left, int top, int right, int bottom) {
        return r.left == left && r.top == top && r.right == right && r.bottom == bottom;
    }
}
