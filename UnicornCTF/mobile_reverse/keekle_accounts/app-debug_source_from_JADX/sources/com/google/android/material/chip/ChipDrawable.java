package com.google.android.material.chip;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources.NotFoundException;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Paint.Align;
import android.graphics.Paint.FontMetrics;
import android.graphics.Paint.Style;
import android.graphics.PointF;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextUtils.TruncateAt;
import android.util.AttributeSet;
import android.util.Xml;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.res.ResourcesCompat.FontCallback;
import androidx.core.graphics.ColorUtils;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.graphics.drawable.TintAwareDrawable;
import androidx.core.internal.view.SupportMenu;
import androidx.core.text.BidiFormatter;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.canvas.CanvasCompat;
import com.google.android.material.drawable.DrawableUtils;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.resources.TextAppearance;
import com.google.android.material.ripple.RippleUtils;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class ChipDrawable extends Drawable implements TintAwareDrawable, Callback {
    private static final boolean DEBUG = false;
    private static final int[] DEFAULT_STATE = {16842910};
    private static final String NAMESPACE_APP = "http://schemas.android.com/apk/res-auto";
    private int alpha = 255;
    private boolean checkable;
    private Drawable checkedIcon;
    private boolean checkedIconVisible;
    private ColorStateList chipBackgroundColor;
    private float chipCornerRadius;
    private float chipEndPadding;
    private Drawable chipIcon;
    private float chipIconSize;
    private ColorStateList chipIconTint;
    private boolean chipIconVisible;
    private float chipMinHeight;
    private final Paint chipPaint = new Paint(1);
    private float chipStartPadding;
    private ColorStateList chipStrokeColor;
    private float chipStrokeWidth;
    private Drawable closeIcon;
    private CharSequence closeIconContentDescription;
    private float closeIconEndPadding;
    private float closeIconSize;
    private float closeIconStartPadding;
    private int[] closeIconStateSet;
    private ColorStateList closeIconTint;
    private boolean closeIconVisible;
    private ColorFilter colorFilter;
    private ColorStateList compatRippleColor;
    private final Context context;
    private boolean currentChecked;
    private int currentChipBackgroundColor;
    private int currentChipStrokeColor;
    private int currentCompatRippleColor;
    private int currentTextColor;
    private int currentTint;
    private final Paint debugPaint;
    private WeakReference<Delegate> delegate;
    private final FontCallback fontCallback = new FontCallback() {
        public void onFontRetrieved(Typeface typeface) {
            ChipDrawable.this.textWidthDirty = true;
            ChipDrawable.this.onSizeChange();
            ChipDrawable.this.invalidateSelf();
        }

        public void onFontRetrievalFailed(int reason) {
        }
    };
    private final FontMetrics fontMetrics = new FontMetrics();
    private MotionSpec hideMotionSpec;
    private float iconEndPadding;
    private float iconStartPadding;
    private int maxWidth;
    private final PointF pointF = new PointF();
    private CharSequence rawText;
    private final RectF rectF = new RectF();
    private ColorStateList rippleColor;
    private boolean shouldDrawText;
    private MotionSpec showMotionSpec;
    private TextAppearance textAppearance;
    private float textEndPadding;
    private final TextPaint textPaint = new TextPaint(1);
    private float textStartPadding;
    private float textWidth;
    /* access modifiers changed from: private */
    public boolean textWidthDirty;
    private ColorStateList tint;
    private PorterDuffColorFilter tintFilter;
    private Mode tintMode = Mode.SRC_IN;
    private TruncateAt truncateAt;
    private CharSequence unicodeWrappedText;
    private boolean useCompatRipple;

    public interface Delegate {
        void onChipDrawableSizeChange();
    }

    public static ChipDrawable createFromAttributes(Context context2, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        ChipDrawable chip = new ChipDrawable(context2);
        chip.loadFromAttributes(attrs, defStyleAttr, defStyleRes);
        return chip;
    }

    public static ChipDrawable createFromResource(Context context2, int id) {
        int type;
        try {
            XmlPullParser parser = context2.getResources().getXml(id);
            do {
                type = parser.next();
                if (type == 2) {
                    break;
                }
            } while (type != 1);
            if (type != 2) {
                throw new XmlPullParserException("No start tag found");
            } else if (TextUtils.equals(parser.getName(), "chip")) {
                AttributeSet attrs = Xml.asAttributeSet(parser);
                int style = attrs.getStyleAttribute();
                if (style == 0) {
                    style = C0078R.style.Widget_MaterialComponents_Chip_Entry;
                }
                return createFromAttributes(context2, attrs, C0078R.attr.chipStandaloneStyle, style);
            } else {
                throw new XmlPullParserException("Must have a <chip> start tag");
            }
        } catch (IOException | XmlPullParserException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("Can't load chip resource ID #0x");
            sb.append(Integer.toHexString(id));
            NotFoundException exception = new NotFoundException(sb.toString());
            exception.initCause(e);
            throw exception;
        }
    }

    private ChipDrawable(Context context2) {
        Paint paint = null;
        this.delegate = new WeakReference<>(paint);
        this.textWidthDirty = true;
        this.context = context2;
        this.rawText = "";
        this.textPaint.density = context2.getResources().getDisplayMetrics().density;
        this.debugPaint = paint;
        if (paint != null) {
            paint.setStyle(Style.STROKE);
        }
        setState(DEFAULT_STATE);
        setCloseIconState(DEFAULT_STATE);
        this.shouldDrawText = true;
    }

    private void loadFromAttributes(AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(this.context, attrs, C0078R.styleable.Chip, defStyleAttr, defStyleRes, new int[0]);
        setChipBackgroundColor(MaterialResources.getColorStateList(this.context, a, C0078R.styleable.Chip_chipBackgroundColor));
        setChipMinHeight(a.getDimension(C0078R.styleable.Chip_chipMinHeight, 0.0f));
        setChipCornerRadius(a.getDimension(C0078R.styleable.Chip_chipCornerRadius, 0.0f));
        setChipStrokeColor(MaterialResources.getColorStateList(this.context, a, C0078R.styleable.Chip_chipStrokeColor));
        setChipStrokeWidth(a.getDimension(C0078R.styleable.Chip_chipStrokeWidth, 0.0f));
        setRippleColor(MaterialResources.getColorStateList(this.context, a, C0078R.styleable.Chip_rippleColor));
        setText(a.getText(C0078R.styleable.Chip_android_text));
        setTextAppearance(MaterialResources.getTextAppearance(this.context, a, C0078R.styleable.Chip_android_textAppearance));
        int ellipsize = a.getInt(C0078R.styleable.Chip_android_ellipsize, 0);
        if (ellipsize == 1) {
            setEllipsize(TruncateAt.START);
        } else if (ellipsize == 2) {
            setEllipsize(TruncateAt.MIDDLE);
        } else if (ellipsize == 3) {
            setEllipsize(TruncateAt.END);
        }
        setChipIconVisible(a.getBoolean(C0078R.styleable.Chip_chipIconVisible, false));
        String str = NAMESPACE_APP;
        if (!(attrs == null || attrs.getAttributeValue(str, "chipIconEnabled") == null || attrs.getAttributeValue(str, "chipIconVisible") != null)) {
            setChipIconVisible(a.getBoolean(C0078R.styleable.Chip_chipIconEnabled, false));
        }
        setChipIcon(MaterialResources.getDrawable(this.context, a, C0078R.styleable.Chip_chipIcon));
        setChipIconTint(MaterialResources.getColorStateList(this.context, a, C0078R.styleable.Chip_chipIconTint));
        setChipIconSize(a.getDimension(C0078R.styleable.Chip_chipIconSize, 0.0f));
        setCloseIconVisible(a.getBoolean(C0078R.styleable.Chip_closeIconVisible, false));
        if (!(attrs == null || attrs.getAttributeValue(str, "closeIconEnabled") == null || attrs.getAttributeValue(str, "closeIconVisible") != null)) {
            setCloseIconVisible(a.getBoolean(C0078R.styleable.Chip_closeIconEnabled, false));
        }
        setCloseIcon(MaterialResources.getDrawable(this.context, a, C0078R.styleable.Chip_closeIcon));
        setCloseIconTint(MaterialResources.getColorStateList(this.context, a, C0078R.styleable.Chip_closeIconTint));
        setCloseIconSize(a.getDimension(C0078R.styleable.Chip_closeIconSize, 0.0f));
        setCheckable(a.getBoolean(C0078R.styleable.Chip_android_checkable, false));
        setCheckedIconVisible(a.getBoolean(C0078R.styleable.Chip_checkedIconVisible, false));
        if (!(attrs == null || attrs.getAttributeValue(str, "checkedIconEnabled") == null || attrs.getAttributeValue(str, "checkedIconVisible") != null)) {
            setCheckedIconVisible(a.getBoolean(C0078R.styleable.Chip_checkedIconEnabled, false));
        }
        setCheckedIcon(MaterialResources.getDrawable(this.context, a, C0078R.styleable.Chip_checkedIcon));
        setShowMotionSpec(MotionSpec.createFromAttribute(this.context, a, C0078R.styleable.Chip_showMotionSpec));
        setHideMotionSpec(MotionSpec.createFromAttribute(this.context, a, C0078R.styleable.Chip_hideMotionSpec));
        setChipStartPadding(a.getDimension(C0078R.styleable.Chip_chipStartPadding, 0.0f));
        setIconStartPadding(a.getDimension(C0078R.styleable.Chip_iconStartPadding, 0.0f));
        setIconEndPadding(a.getDimension(C0078R.styleable.Chip_iconEndPadding, 0.0f));
        setTextStartPadding(a.getDimension(C0078R.styleable.Chip_textStartPadding, 0.0f));
        setTextEndPadding(a.getDimension(C0078R.styleable.Chip_textEndPadding, 0.0f));
        setCloseIconStartPadding(a.getDimension(C0078R.styleable.Chip_closeIconStartPadding, 0.0f));
        setCloseIconEndPadding(a.getDimension(C0078R.styleable.Chip_closeIconEndPadding, 0.0f));
        setChipEndPadding(a.getDimension(C0078R.styleable.Chip_chipEndPadding, 0.0f));
        setMaxWidth(a.getDimensionPixelSize(C0078R.styleable.Chip_android_maxWidth, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED));
        a.recycle();
    }

    public void setUseCompatRipple(boolean useCompatRipple2) {
        if (this.useCompatRipple != useCompatRipple2) {
            this.useCompatRipple = useCompatRipple2;
            updateCompatRippleColor();
            onStateChange(getState());
        }
    }

    public boolean getUseCompatRipple() {
        return this.useCompatRipple;
    }

    public void setDelegate(Delegate delegate2) {
        this.delegate = new WeakReference<>(delegate2);
    }

    /* access modifiers changed from: protected */
    public void onSizeChange() {
        Delegate delegate2 = (Delegate) this.delegate.get();
        if (delegate2 != null) {
            delegate2.onChipDrawableSizeChange();
        }
    }

    public void getChipTouchBounds(RectF bounds) {
        calculateChipTouchBounds(getBounds(), bounds);
    }

    public void getCloseIconTouchBounds(RectF bounds) {
        calculateCloseIconTouchBounds(getBounds(), bounds);
    }

    public int getIntrinsicWidth() {
        return Math.min(Math.round(this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding + getTextWidth() + this.textEndPadding + calculateCloseIconWidth() + this.chipEndPadding), this.maxWidth);
    }

    public int getIntrinsicHeight() {
        return (int) this.chipMinHeight;
    }

    private boolean showsChipIcon() {
        return this.chipIconVisible && this.chipIcon != null;
    }

    private boolean showsCheckedIcon() {
        return this.checkedIconVisible && this.checkedIcon != null && this.currentChecked;
    }

    private boolean showsCloseIcon() {
        return this.closeIconVisible && this.closeIcon != null;
    }

    private boolean canShowCheckedIcon() {
        return this.checkedIconVisible && this.checkedIcon != null && this.checkable;
    }

    /* access modifiers changed from: 0000 */
    public float calculateChipIconWidth() {
        if (showsChipIcon() || showsCheckedIcon()) {
            return this.iconStartPadding + this.chipIconSize + this.iconEndPadding;
        }
        return 0.0f;
    }

    private float getTextWidth() {
        if (!this.textWidthDirty) {
            return this.textWidth;
        }
        float calculateTextWidth = calculateTextWidth(this.unicodeWrappedText);
        this.textWidth = calculateTextWidth;
        this.textWidthDirty = false;
        return calculateTextWidth;
    }

    private float calculateTextWidth(CharSequence charSequence) {
        if (charSequence == null) {
            return 0.0f;
        }
        return this.textPaint.measureText(charSequence, 0, charSequence.length());
    }

    private float calculateCloseIconWidth() {
        if (showsCloseIcon()) {
            return this.closeIconStartPadding + this.closeIconSize + this.closeIconEndPadding;
        }
        return 0.0f;
    }

    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        if (!bounds.isEmpty() && getAlpha() != 0) {
            int saveCount = 0;
            if (this.alpha < 255) {
                saveCount = CanvasCompat.saveLayerAlpha(canvas, (float) bounds.left, (float) bounds.top, (float) bounds.right, (float) bounds.bottom, this.alpha);
            }
            drawChipBackground(canvas, bounds);
            drawChipStroke(canvas, bounds);
            drawCompatRipple(canvas, bounds);
            drawChipIcon(canvas, bounds);
            drawCheckedIcon(canvas, bounds);
            if (this.shouldDrawText) {
                drawText(canvas, bounds);
            }
            drawCloseIcon(canvas, bounds);
            drawDebug(canvas, bounds);
            if (this.alpha < 255) {
                canvas.restoreToCount(saveCount);
            }
        }
    }

    private void drawChipBackground(Canvas canvas, Rect bounds) {
        this.chipPaint.setColor(this.currentChipBackgroundColor);
        this.chipPaint.setStyle(Style.FILL);
        this.chipPaint.setColorFilter(getTintColorFilter());
        this.rectF.set(bounds);
        RectF rectF2 = this.rectF;
        float f = this.chipCornerRadius;
        canvas.drawRoundRect(rectF2, f, f, this.chipPaint);
    }

    private void drawChipStroke(Canvas canvas, Rect bounds) {
        if (this.chipStrokeWidth > 0.0f) {
            this.chipPaint.setColor(this.currentChipStrokeColor);
            this.chipPaint.setStyle(Style.STROKE);
            this.chipPaint.setColorFilter(getTintColorFilter());
            this.rectF.set(((float) bounds.left) + (this.chipStrokeWidth / 2.0f), ((float) bounds.top) + (this.chipStrokeWidth / 2.0f), ((float) bounds.right) - (this.chipStrokeWidth / 2.0f), ((float) bounds.bottom) - (this.chipStrokeWidth / 2.0f));
            float strokeCornerRadius = this.chipCornerRadius - (this.chipStrokeWidth / 2.0f);
            canvas.drawRoundRect(this.rectF, strokeCornerRadius, strokeCornerRadius, this.chipPaint);
        }
    }

    private void drawCompatRipple(Canvas canvas, Rect bounds) {
        this.chipPaint.setColor(this.currentCompatRippleColor);
        this.chipPaint.setStyle(Style.FILL);
        this.rectF.set(bounds);
        RectF rectF2 = this.rectF;
        float f = this.chipCornerRadius;
        canvas.drawRoundRect(rectF2, f, f, this.chipPaint);
    }

    private void drawChipIcon(Canvas canvas, Rect bounds) {
        if (showsChipIcon()) {
            calculateChipIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.chipIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            this.chipIcon.draw(canvas);
            canvas.translate(-tx, -ty);
        }
    }

    private void drawCheckedIcon(Canvas canvas, Rect bounds) {
        if (showsCheckedIcon()) {
            calculateChipIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.checkedIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            this.checkedIcon.draw(canvas);
            canvas.translate(-tx, -ty);
        }
    }

    private void drawText(Canvas canvas, Rect bounds) {
        if (this.unicodeWrappedText != null) {
            Align align = calculateTextOriginAndAlignment(bounds, this.pointF);
            calculateTextBounds(bounds, this.rectF);
            if (this.textAppearance != null) {
                this.textPaint.drawableState = getState();
                this.textAppearance.updateDrawState(this.context, this.textPaint, this.fontCallback);
            }
            this.textPaint.setTextAlign(align);
            boolean clip = Math.round(getTextWidth()) > Math.round(this.rectF.width());
            int saveCount = 0;
            if (clip) {
                saveCount = canvas.save();
                canvas.clipRect(this.rectF);
            }
            CharSequence finalText = this.unicodeWrappedText;
            if (clip && this.truncateAt != null) {
                finalText = TextUtils.ellipsize(this.unicodeWrappedText, this.textPaint, this.rectF.width(), this.truncateAt);
            }
            canvas.drawText(finalText, 0, finalText.length(), this.pointF.x, this.pointF.y, this.textPaint);
            if (clip) {
                canvas.restoreToCount(saveCount);
            }
        }
    }

    private void drawCloseIcon(Canvas canvas, Rect bounds) {
        if (showsCloseIcon()) {
            calculateCloseIconBounds(bounds, this.rectF);
            float tx = this.rectF.left;
            float ty = this.rectF.top;
            canvas.translate(tx, ty);
            this.closeIcon.setBounds(0, 0, (int) this.rectF.width(), (int) this.rectF.height());
            this.closeIcon.draw(canvas);
            canvas.translate(-tx, -ty);
        }
    }

    private void drawDebug(Canvas canvas, Rect bounds) {
        Paint paint = this.debugPaint;
        if (paint != null) {
            paint.setColor(ColorUtils.setAlphaComponent(ViewCompat.MEASURED_STATE_MASK, 127));
            canvas.drawRect(bounds, this.debugPaint);
            if (showsChipIcon() || showsCheckedIcon()) {
                calculateChipIconBounds(bounds, this.rectF);
                canvas.drawRect(this.rectF, this.debugPaint);
            }
            if (this.unicodeWrappedText != null) {
                canvas.drawLine((float) bounds.left, bounds.exactCenterY(), (float) bounds.right, bounds.exactCenterY(), this.debugPaint);
            }
            if (showsCloseIcon()) {
                calculateCloseIconBounds(bounds, this.rectF);
                canvas.drawRect(this.rectF, this.debugPaint);
            }
            this.debugPaint.setColor(ColorUtils.setAlphaComponent(SupportMenu.CATEGORY_MASK, 127));
            calculateChipTouchBounds(bounds, this.rectF);
            canvas.drawRect(this.rectF, this.debugPaint);
            this.debugPaint.setColor(ColorUtils.setAlphaComponent(-16711936, 127));
            calculateCloseIconTouchBounds(bounds, this.rectF);
            canvas.drawRect(this.rectF, this.debugPaint);
        }
    }

    private void calculateChipIconBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsChipIcon() || showsCheckedIcon()) {
            float offsetFromStart = this.chipStartPadding + this.iconStartPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.left = ((float) bounds.left) + offsetFromStart;
                outBounds.right = outBounds.left + this.chipIconSize;
            } else {
                outBounds.right = ((float) bounds.right) - offsetFromStart;
                outBounds.left = outBounds.right - this.chipIconSize;
            }
            outBounds.top = bounds.exactCenterY() - (this.chipIconSize / 2.0f);
            outBounds.bottom = outBounds.top + this.chipIconSize;
        }
    }

    /* access modifiers changed from: 0000 */
    public Align calculateTextOriginAndAlignment(Rect bounds, PointF pointF2) {
        pointF2.set(0.0f, 0.0f);
        Align align = Align.LEFT;
        if (this.unicodeWrappedText != null) {
            float offsetFromStart = this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                pointF2.x = ((float) bounds.left) + offsetFromStart;
                align = Align.LEFT;
            } else {
                pointF2.x = ((float) bounds.right) - offsetFromStart;
                align = Align.RIGHT;
            }
            pointF2.y = ((float) bounds.centerY()) - calculateTextCenterFromBaseline();
        }
        return align;
    }

    private float calculateTextCenterFromBaseline() {
        this.textPaint.getFontMetrics(this.fontMetrics);
        return (this.fontMetrics.descent + this.fontMetrics.ascent) / 2.0f;
    }

    private void calculateTextBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (this.unicodeWrappedText != null) {
            float offsetFromStart = this.chipStartPadding + calculateChipIconWidth() + this.textStartPadding;
            float offsetFromEnd = this.chipEndPadding + calculateCloseIconWidth() + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.left = ((float) bounds.left) + offsetFromStart;
                outBounds.right = ((float) bounds.right) - offsetFromEnd;
            } else {
                outBounds.left = ((float) bounds.left) + offsetFromEnd;
                outBounds.right = ((float) bounds.right) - offsetFromStart;
            }
            outBounds.top = (float) bounds.top;
            outBounds.bottom = (float) bounds.bottom;
        }
    }

    private void calculateCloseIconBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = ((float) bounds.right) - offsetFromEnd;
                outBounds.left = outBounds.right - this.closeIconSize;
            } else {
                outBounds.left = ((float) bounds.left) + offsetFromEnd;
                outBounds.right = outBounds.left + this.closeIconSize;
            }
            outBounds.top = bounds.exactCenterY() - (this.closeIconSize / 2.0f);
            outBounds.bottom = outBounds.top + this.closeIconSize;
        }
    }

    private void calculateChipTouchBounds(Rect bounds, RectF outBounds) {
        outBounds.set(bounds);
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding + this.closeIconSize + this.closeIconStartPadding + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = ((float) bounds.right) - offsetFromEnd;
            } else {
                outBounds.left = ((float) bounds.left) + offsetFromEnd;
            }
        }
    }

    private void calculateCloseIconTouchBounds(Rect bounds, RectF outBounds) {
        outBounds.setEmpty();
        if (showsCloseIcon()) {
            float offsetFromEnd = this.chipEndPadding + this.closeIconEndPadding + this.closeIconSize + this.closeIconStartPadding + this.textEndPadding;
            if (DrawableCompat.getLayoutDirection(this) == 0) {
                outBounds.right = (float) bounds.right;
                outBounds.left = outBounds.right - offsetFromEnd;
            } else {
                outBounds.left = (float) bounds.left;
                outBounds.right = ((float) bounds.left) + offsetFromEnd;
            }
            outBounds.top = (float) bounds.top;
            outBounds.bottom = (float) bounds.bottom;
        }
    }

    public boolean isStateful() {
        return isStateful(this.chipBackgroundColor) || isStateful(this.chipStrokeColor) || (this.useCompatRipple && isStateful(this.compatRippleColor)) || isStateful(this.textAppearance) || canShowCheckedIcon() || isStateful(this.chipIcon) || isStateful(this.checkedIcon) || isStateful(this.tint);
    }

    public boolean isCloseIconStateful() {
        return isStateful(this.closeIcon);
    }

    public boolean setCloseIconState(int[] stateSet) {
        if (!Arrays.equals(this.closeIconStateSet, stateSet)) {
            this.closeIconStateSet = stateSet;
            if (showsCloseIcon()) {
                return onStateChange(getState(), stateSet);
            }
        }
        return false;
    }

    public int[] getCloseIconState() {
        return this.closeIconStateSet;
    }

    /* access modifiers changed from: protected */
    public boolean onStateChange(int[] state) {
        return onStateChange(state, getCloseIconState());
    }

    private boolean onStateChange(int[] chipState, int[] closeIconState) {
        boolean invalidate = super.onStateChange(chipState);
        boolean sizeChanged = false;
        ColorStateList colorStateList = this.chipBackgroundColor;
        int newTint = 0;
        int newChipBackgroundColor = colorStateList != null ? colorStateList.getColorForState(chipState, this.currentChipBackgroundColor) : 0;
        if (this.currentChipBackgroundColor != newChipBackgroundColor) {
            this.currentChipBackgroundColor = newChipBackgroundColor;
            invalidate = true;
        }
        ColorStateList colorStateList2 = this.chipStrokeColor;
        int newChipStrokeColor = colorStateList2 != null ? colorStateList2.getColorForState(chipState, this.currentChipStrokeColor) : 0;
        if (this.currentChipStrokeColor != newChipStrokeColor) {
            this.currentChipStrokeColor = newChipStrokeColor;
            invalidate = true;
        }
        ColorStateList colorStateList3 = this.compatRippleColor;
        int newCompatRippleColor = colorStateList3 != null ? colorStateList3.getColorForState(chipState, this.currentCompatRippleColor) : 0;
        if (this.currentCompatRippleColor != newCompatRippleColor) {
            this.currentCompatRippleColor = newCompatRippleColor;
            if (this.useCompatRipple) {
                invalidate = true;
            }
        }
        TextAppearance textAppearance2 = this.textAppearance;
        int newTextColor = (textAppearance2 == null || textAppearance2.textColor == null) ? 0 : this.textAppearance.textColor.getColorForState(chipState, this.currentTextColor);
        if (this.currentTextColor != newTextColor) {
            this.currentTextColor = newTextColor;
            invalidate = true;
        }
        boolean newChecked = hasState(getState(), 16842912) && this.checkable;
        if (!(this.currentChecked == newChecked || this.checkedIcon == null)) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.currentChecked = newChecked;
            invalidate = true;
            if (oldChipIconWidth != calculateChipIconWidth()) {
                sizeChanged = true;
            }
        }
        ColorStateList colorStateList4 = this.tint;
        if (colorStateList4 != null) {
            newTint = colorStateList4.getColorForState(chipState, this.currentTint);
        }
        if (this.currentTint != newTint) {
            this.currentTint = newTint;
            this.tintFilter = DrawableUtils.updateTintFilter(this, this.tint, this.tintMode);
            invalidate = true;
        }
        if (isStateful(this.chipIcon)) {
            invalidate |= this.chipIcon.setState(chipState);
        }
        if (isStateful(this.checkedIcon)) {
            invalidate |= this.checkedIcon.setState(chipState);
        }
        if (isStateful(this.closeIcon)) {
            invalidate |= this.closeIcon.setState(closeIconState);
        }
        if (invalidate) {
            invalidateSelf();
        }
        if (sizeChanged) {
            onSizeChange();
        }
        return invalidate;
    }

    private static boolean isStateful(ColorStateList colorStateList) {
        return colorStateList != null && colorStateList.isStateful();
    }

    private static boolean isStateful(Drawable drawable) {
        return drawable != null && drawable.isStateful();
    }

    private static boolean isStateful(TextAppearance textAppearance2) {
        return (textAppearance2 == null || textAppearance2.textColor == null || !textAppearance2.textColor.isStateful()) ? false : true;
    }

    public boolean onLayoutDirectionChanged(int layoutDirection) {
        boolean invalidate = super.onLayoutDirectionChanged(layoutDirection);
        if (showsChipIcon()) {
            invalidate |= this.chipIcon.setLayoutDirection(layoutDirection);
        }
        if (showsCheckedIcon()) {
            invalidate |= this.checkedIcon.setLayoutDirection(layoutDirection);
        }
        if (showsCloseIcon()) {
            invalidate |= this.closeIcon.setLayoutDirection(layoutDirection);
        }
        if (invalidate) {
            invalidateSelf();
        }
        return true;
    }

    /* access modifiers changed from: protected */
    public boolean onLevelChange(int level) {
        boolean invalidate = super.onLevelChange(level);
        if (showsChipIcon()) {
            invalidate |= this.chipIcon.setLevel(level);
        }
        if (showsCheckedIcon()) {
            invalidate |= this.checkedIcon.setLevel(level);
        }
        if (showsCloseIcon()) {
            invalidate |= this.closeIcon.setLevel(level);
        }
        if (invalidate) {
            invalidateSelf();
        }
        return invalidate;
    }

    public boolean setVisible(boolean visible, boolean restart) {
        boolean invalidate = super.setVisible(visible, restart);
        if (showsChipIcon()) {
            invalidate |= this.chipIcon.setVisible(visible, restart);
        }
        if (showsCheckedIcon()) {
            invalidate |= this.checkedIcon.setVisible(visible, restart);
        }
        if (showsCloseIcon()) {
            invalidate |= this.closeIcon.setVisible(visible, restart);
        }
        if (invalidate) {
            invalidateSelf();
        }
        return invalidate;
    }

    public void setAlpha(int alpha2) {
        if (this.alpha != alpha2) {
            this.alpha = alpha2;
            invalidateSelf();
        }
    }

    public int getAlpha() {
        return this.alpha;
    }

    public void setColorFilter(ColorFilter colorFilter2) {
        if (this.colorFilter != colorFilter2) {
            this.colorFilter = colorFilter2;
            invalidateSelf();
        }
    }

    public ColorFilter getColorFilter() {
        return this.colorFilter;
    }

    public void setTintList(ColorStateList tint2) {
        if (this.tint != tint2) {
            this.tint = tint2;
            onStateChange(getState());
        }
    }

    public void setTintMode(Mode tintMode2) {
        if (this.tintMode != tintMode2) {
            this.tintMode = tintMode2;
            this.tintFilter = DrawableUtils.updateTintFilter(this, this.tint, tintMode2);
            invalidateSelf();
        }
    }

    public int getOpacity() {
        return -3;
    }

    public void getOutline(Outline outline) {
        Rect bounds = getBounds();
        if (!bounds.isEmpty()) {
            outline.setRoundRect(bounds, this.chipCornerRadius);
        } else {
            outline.setRoundRect(0, 0, getIntrinsicWidth(), getIntrinsicHeight(), this.chipCornerRadius);
        }
        outline.setAlpha(((float) getAlpha()) / 255.0f);
    }

    public void invalidateDrawable(Drawable who) {
        Callback callback = getCallback();
        if (callback != null) {
            callback.invalidateDrawable(this);
        }
    }

    public void scheduleDrawable(Drawable who, Runnable what, long when) {
        Callback callback = getCallback();
        if (callback != null) {
            callback.scheduleDrawable(this, what, when);
        }
    }

    public void unscheduleDrawable(Drawable who, Runnable what) {
        Callback callback = getCallback();
        if (callback != null) {
            callback.unscheduleDrawable(this, what);
        }
    }

    private void unapplyChildDrawable(Drawable drawable) {
        if (drawable != null) {
            drawable.setCallback(null);
        }
    }

    private void applyChildDrawable(Drawable drawable) {
        if (drawable != null) {
            drawable.setCallback(this);
            DrawableCompat.setLayoutDirection(drawable, DrawableCompat.getLayoutDirection(this));
            drawable.setLevel(getLevel());
            drawable.setVisible(isVisible(), false);
            if (drawable == this.closeIcon) {
                if (drawable.isStateful()) {
                    drawable.setState(getCloseIconState());
                }
                DrawableCompat.setTintList(drawable, this.closeIconTint);
            } else if (drawable.isStateful()) {
                drawable.setState(getState());
            }
        }
    }

    private ColorFilter getTintColorFilter() {
        ColorFilter colorFilter2 = this.colorFilter;
        return colorFilter2 != null ? colorFilter2 : this.tintFilter;
    }

    private void updateCompatRippleColor() {
        this.compatRippleColor = this.useCompatRipple ? RippleUtils.convertToRippleDrawableColor(this.rippleColor) : null;
    }

    private static boolean hasState(int[] stateSet, int state) {
        if (stateSet == null) {
            return false;
        }
        for (int s : stateSet) {
            if (s == state) {
                return true;
            }
        }
        return false;
    }

    public ColorStateList getChipBackgroundColor() {
        return this.chipBackgroundColor;
    }

    public void setChipBackgroundColorResource(int id) {
        setChipBackgroundColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipBackgroundColor(ColorStateList chipBackgroundColor2) {
        if (this.chipBackgroundColor != chipBackgroundColor2) {
            this.chipBackgroundColor = chipBackgroundColor2;
            onStateChange(getState());
        }
    }

    public float getChipMinHeight() {
        return this.chipMinHeight;
    }

    public void setChipMinHeightResource(int id) {
        setChipMinHeight(this.context.getResources().getDimension(id));
    }

    public void setChipMinHeight(float chipMinHeight2) {
        if (this.chipMinHeight != chipMinHeight2) {
            this.chipMinHeight = chipMinHeight2;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getChipCornerRadius() {
        return this.chipCornerRadius;
    }

    public void setChipCornerRadiusResource(int id) {
        setChipCornerRadius(this.context.getResources().getDimension(id));
    }

    public void setChipCornerRadius(float chipCornerRadius2) {
        if (this.chipCornerRadius != chipCornerRadius2) {
            this.chipCornerRadius = chipCornerRadius2;
            invalidateSelf();
        }
    }

    public ColorStateList getChipStrokeColor() {
        return this.chipStrokeColor;
    }

    public void setChipStrokeColorResource(int id) {
        setChipStrokeColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipStrokeColor(ColorStateList chipStrokeColor2) {
        if (this.chipStrokeColor != chipStrokeColor2) {
            this.chipStrokeColor = chipStrokeColor2;
            onStateChange(getState());
        }
    }

    public float getChipStrokeWidth() {
        return this.chipStrokeWidth;
    }

    public void setChipStrokeWidthResource(int id) {
        setChipStrokeWidth(this.context.getResources().getDimension(id));
    }

    public void setChipStrokeWidth(float chipStrokeWidth2) {
        if (this.chipStrokeWidth != chipStrokeWidth2) {
            this.chipStrokeWidth = chipStrokeWidth2;
            this.chipPaint.setStrokeWidth(chipStrokeWidth2);
            invalidateSelf();
        }
    }

    public ColorStateList getRippleColor() {
        return this.rippleColor;
    }

    public void setRippleColorResource(int id) {
        setRippleColor(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setRippleColor(ColorStateList rippleColor2) {
        if (this.rippleColor != rippleColor2) {
            this.rippleColor = rippleColor2;
            updateCompatRippleColor();
            onStateChange(getState());
        }
    }

    public CharSequence getText() {
        return this.rawText;
    }

    public void setTextResource(int id) {
        setText(this.context.getResources().getString(id));
    }

    public void setText(CharSequence text) {
        if (text == null) {
            text = "";
        }
        if (this.rawText != text) {
            this.rawText = text;
            this.unicodeWrappedText = BidiFormatter.getInstance().unicodeWrap(text);
            this.textWidthDirty = true;
            invalidateSelf();
            onSizeChange();
        }
    }

    public TextAppearance getTextAppearance() {
        return this.textAppearance;
    }

    public void setTextAppearanceResource(int id) {
        setTextAppearance(new TextAppearance(this.context, id));
    }

    public void setTextAppearance(TextAppearance textAppearance2) {
        if (this.textAppearance != textAppearance2) {
            this.textAppearance = textAppearance2;
            if (textAppearance2 != null) {
                textAppearance2.updateMeasureState(this.context, this.textPaint, this.fontCallback);
                this.textWidthDirty = true;
            }
            onStateChange(getState());
            onSizeChange();
        }
    }

    public TruncateAt getEllipsize() {
        return this.truncateAt;
    }

    public void setEllipsize(TruncateAt truncateAt2) {
        this.truncateAt = truncateAt2;
    }

    public boolean isChipIconVisible() {
        return this.chipIconVisible;
    }

    @Deprecated
    public boolean isChipIconEnabled() {
        return isChipIconVisible();
    }

    public void setChipIconVisible(int id) {
        setChipIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setChipIconVisible(boolean chipIconVisible2) {
        if (this.chipIconVisible != chipIconVisible2) {
            boolean oldShowsChipIcon = showsChipIcon();
            this.chipIconVisible = chipIconVisible2;
            boolean newShowsChipIcon = showsChipIcon();
            if (oldShowsChipIcon != newShowsChipIcon) {
                if (newShowsChipIcon) {
                    applyChildDrawable(this.chipIcon);
                } else {
                    unapplyChildDrawable(this.chipIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setChipIconEnabledResource(int id) {
        setChipIconVisible(id);
    }

    @Deprecated
    public void setChipIconEnabled(boolean chipIconEnabled) {
        setChipIconVisible(chipIconEnabled);
    }

    public Drawable getChipIcon() {
        Drawable drawable = this.chipIcon;
        if (drawable != null) {
            return DrawableCompat.unwrap(drawable);
        }
        return null;
    }

    public void setChipIconResource(int id) {
        setChipIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setChipIcon(Drawable chipIcon2) {
        Drawable oldChipIcon = getChipIcon();
        if (oldChipIcon != chipIcon2) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.chipIcon = chipIcon2 != null ? DrawableCompat.wrap(chipIcon2).mutate() : null;
            float newChipIconWidth = calculateChipIconWidth();
            unapplyChildDrawable(oldChipIcon);
            if (showsChipIcon()) {
                applyChildDrawable(this.chipIcon);
            }
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public ColorStateList getChipIconTint() {
        return this.chipIconTint;
    }

    public void setChipIconTintResource(int id) {
        setChipIconTint(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setChipIconTint(ColorStateList chipIconTint2) {
        if (this.chipIconTint != chipIconTint2) {
            this.chipIconTint = chipIconTint2;
            if (showsChipIcon()) {
                DrawableCompat.setTintList(this.chipIcon, chipIconTint2);
            }
            onStateChange(getState());
        }
    }

    public float getChipIconSize() {
        return this.chipIconSize;
    }

    public void setChipIconSizeResource(int id) {
        setChipIconSize(this.context.getResources().getDimension(id));
    }

    public void setChipIconSize(float chipIconSize2) {
        if (this.chipIconSize != chipIconSize2) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.chipIconSize = chipIconSize2;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public boolean isCloseIconVisible() {
        return this.closeIconVisible;
    }

    @Deprecated
    public boolean isCloseIconEnabled() {
        return isCloseIconVisible();
    }

    public void setCloseIconVisible(int id) {
        setCloseIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setCloseIconVisible(boolean closeIconVisible2) {
        if (this.closeIconVisible != closeIconVisible2) {
            boolean oldShowsCloseIcon = showsCloseIcon();
            this.closeIconVisible = closeIconVisible2;
            boolean newShowsCloseIcon = showsCloseIcon();
            if (oldShowsCloseIcon != newShowsCloseIcon) {
                if (newShowsCloseIcon) {
                    applyChildDrawable(this.closeIcon);
                } else {
                    unapplyChildDrawable(this.closeIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setCloseIconEnabledResource(int id) {
        setCloseIconVisible(id);
    }

    @Deprecated
    public void setCloseIconEnabled(boolean closeIconEnabled) {
        setCloseIconVisible(closeIconEnabled);
    }

    public Drawable getCloseIcon() {
        Drawable drawable = this.closeIcon;
        if (drawable != null) {
            return DrawableCompat.unwrap(drawable);
        }
        return null;
    }

    public void setCloseIconResource(int id) {
        setCloseIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setCloseIcon(Drawable closeIcon2) {
        Drawable oldCloseIcon = getCloseIcon();
        if (oldCloseIcon != closeIcon2) {
            float oldCloseIconWidth = calculateCloseIconWidth();
            this.closeIcon = closeIcon2 != null ? DrawableCompat.wrap(closeIcon2).mutate() : null;
            float newCloseIconWidth = calculateCloseIconWidth();
            unapplyChildDrawable(oldCloseIcon);
            if (showsCloseIcon()) {
                applyChildDrawable(this.closeIcon);
            }
            invalidateSelf();
            if (oldCloseIconWidth != newCloseIconWidth) {
                onSizeChange();
            }
        }
    }

    public ColorStateList getCloseIconTint() {
        return this.closeIconTint;
    }

    public void setCloseIconTintResource(int id) {
        setCloseIconTint(AppCompatResources.getColorStateList(this.context, id));
    }

    public void setCloseIconTint(ColorStateList closeIconTint2) {
        if (this.closeIconTint != closeIconTint2) {
            this.closeIconTint = closeIconTint2;
            if (showsCloseIcon()) {
                DrawableCompat.setTintList(this.closeIcon, closeIconTint2);
            }
            onStateChange(getState());
        }
    }

    public float getCloseIconSize() {
        return this.closeIconSize;
    }

    public void setCloseIconSizeResource(int id) {
        setCloseIconSize(this.context.getResources().getDimension(id));
    }

    public void setCloseIconSize(float closeIconSize2) {
        if (this.closeIconSize != closeIconSize2) {
            this.closeIconSize = closeIconSize2;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public void setCloseIconContentDescription(CharSequence closeIconContentDescription2) {
        if (this.closeIconContentDescription != closeIconContentDescription2) {
            this.closeIconContentDescription = BidiFormatter.getInstance().unicodeWrap(closeIconContentDescription2);
            invalidateSelf();
        }
    }

    public CharSequence getCloseIconContentDescription() {
        return this.closeIconContentDescription;
    }

    public boolean isCheckable() {
        return this.checkable;
    }

    public void setCheckableResource(int id) {
        setCheckable(this.context.getResources().getBoolean(id));
    }

    public void setCheckable(boolean checkable2) {
        if (this.checkable != checkable2) {
            this.checkable = checkable2;
            float oldChipIconWidth = calculateChipIconWidth();
            if (!checkable2 && this.currentChecked) {
                this.currentChecked = false;
            }
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public boolean isCheckedIconVisible() {
        return this.checkedIconVisible;
    }

    @Deprecated
    public boolean isCheckedIconEnabled() {
        return isCheckedIconVisible();
    }

    public void setCheckedIconVisible(int id) {
        setCheckedIconVisible(this.context.getResources().getBoolean(id));
    }

    public void setCheckedIconVisible(boolean checkedIconVisible2) {
        if (this.checkedIconVisible != checkedIconVisible2) {
            boolean oldShowsCheckedIcon = showsCheckedIcon();
            this.checkedIconVisible = checkedIconVisible2;
            boolean newShowsCheckedIcon = showsCheckedIcon();
            if (oldShowsCheckedIcon != newShowsCheckedIcon) {
                if (newShowsCheckedIcon) {
                    applyChildDrawable(this.checkedIcon);
                } else {
                    unapplyChildDrawable(this.checkedIcon);
                }
                invalidateSelf();
                onSizeChange();
            }
        }
    }

    @Deprecated
    public void setCheckedIconEnabledResource(int id) {
        setCheckedIconVisible(this.context.getResources().getBoolean(id));
    }

    @Deprecated
    public void setCheckedIconEnabled(boolean checkedIconEnabled) {
        setCheckedIconVisible(checkedIconEnabled);
    }

    public Drawable getCheckedIcon() {
        return this.checkedIcon;
    }

    public void setCheckedIconResource(int id) {
        setCheckedIcon(AppCompatResources.getDrawable(this.context, id));
    }

    public void setCheckedIcon(Drawable checkedIcon2) {
        if (this.checkedIcon != checkedIcon2) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.checkedIcon = checkedIcon2;
            float newChipIconWidth = calculateChipIconWidth();
            unapplyChildDrawable(this.checkedIcon);
            applyChildDrawable(this.checkedIcon);
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public MotionSpec getShowMotionSpec() {
        return this.showMotionSpec;
    }

    public void setShowMotionSpecResource(int id) {
        setShowMotionSpec(MotionSpec.createFromResource(this.context, id));
    }

    public void setShowMotionSpec(MotionSpec showMotionSpec2) {
        this.showMotionSpec = showMotionSpec2;
    }

    public MotionSpec getHideMotionSpec() {
        return this.hideMotionSpec;
    }

    public void setHideMotionSpecResource(int id) {
        setHideMotionSpec(MotionSpec.createFromResource(this.context, id));
    }

    public void setHideMotionSpec(MotionSpec hideMotionSpec2) {
        this.hideMotionSpec = hideMotionSpec2;
    }

    public float getChipStartPadding() {
        return this.chipStartPadding;
    }

    public void setChipStartPaddingResource(int id) {
        setChipStartPadding(this.context.getResources().getDimension(id));
    }

    public void setChipStartPadding(float chipStartPadding2) {
        if (this.chipStartPadding != chipStartPadding2) {
            this.chipStartPadding = chipStartPadding2;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getIconStartPadding() {
        return this.iconStartPadding;
    }

    public void setIconStartPaddingResource(int id) {
        setIconStartPadding(this.context.getResources().getDimension(id));
    }

    public void setIconStartPadding(float iconStartPadding2) {
        if (this.iconStartPadding != iconStartPadding2) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.iconStartPadding = iconStartPadding2;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public float getIconEndPadding() {
        return this.iconEndPadding;
    }

    public void setIconEndPaddingResource(int id) {
        setIconEndPadding(this.context.getResources().getDimension(id));
    }

    public void setIconEndPadding(float iconEndPadding2) {
        if (this.iconEndPadding != iconEndPadding2) {
            float oldChipIconWidth = calculateChipIconWidth();
            this.iconEndPadding = iconEndPadding2;
            float newChipIconWidth = calculateChipIconWidth();
            invalidateSelf();
            if (oldChipIconWidth != newChipIconWidth) {
                onSizeChange();
            }
        }
    }

    public float getTextStartPadding() {
        return this.textStartPadding;
    }

    public void setTextStartPaddingResource(int id) {
        setTextStartPadding(this.context.getResources().getDimension(id));
    }

    public void setTextStartPadding(float textStartPadding2) {
        if (this.textStartPadding != textStartPadding2) {
            this.textStartPadding = textStartPadding2;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getTextEndPadding() {
        return this.textEndPadding;
    }

    public void setTextEndPaddingResource(int id) {
        setTextEndPadding(this.context.getResources().getDimension(id));
    }

    public void setTextEndPadding(float textEndPadding2) {
        if (this.textEndPadding != textEndPadding2) {
            this.textEndPadding = textEndPadding2;
            invalidateSelf();
            onSizeChange();
        }
    }

    public float getCloseIconStartPadding() {
        return this.closeIconStartPadding;
    }

    public void setCloseIconStartPaddingResource(int id) {
        setCloseIconStartPadding(this.context.getResources().getDimension(id));
    }

    public void setCloseIconStartPadding(float closeIconStartPadding2) {
        if (this.closeIconStartPadding != closeIconStartPadding2) {
            this.closeIconStartPadding = closeIconStartPadding2;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public float getCloseIconEndPadding() {
        return this.closeIconEndPadding;
    }

    public void setCloseIconEndPaddingResource(int id) {
        setCloseIconEndPadding(this.context.getResources().getDimension(id));
    }

    public void setCloseIconEndPadding(float closeIconEndPadding2) {
        if (this.closeIconEndPadding != closeIconEndPadding2) {
            this.closeIconEndPadding = closeIconEndPadding2;
            invalidateSelf();
            if (showsCloseIcon()) {
                onSizeChange();
            }
        }
    }

    public float getChipEndPadding() {
        return this.chipEndPadding;
    }

    public void setChipEndPaddingResource(int id) {
        setChipEndPadding(this.context.getResources().getDimension(id));
    }

    public void setChipEndPadding(float chipEndPadding2) {
        if (this.chipEndPadding != chipEndPadding2) {
            this.chipEndPadding = chipEndPadding2;
            invalidateSelf();
            onSizeChange();
        }
    }

    public int getMaxWidth() {
        return this.maxWidth;
    }

    public void setMaxWidth(int maxWidth2) {
        this.maxWidth = maxWidth2;
    }

    /* access modifiers changed from: 0000 */
    public boolean shouldDrawText() {
        return this.shouldDrawText;
    }

    /* access modifiers changed from: 0000 */
    public void setShouldDrawText(boolean shouldDrawText2) {
        this.shouldDrawText = shouldDrawText2;
    }
}
