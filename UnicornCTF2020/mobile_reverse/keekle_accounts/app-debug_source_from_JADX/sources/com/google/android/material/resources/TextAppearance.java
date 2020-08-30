package com.google.android.material.resources;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources.NotFoundException;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.text.TextPaint;
import android.util.Log;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.content.res.ResourcesCompat.FontCallback;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;

public class TextAppearance {
    private static final String TAG = "TextAppearance";
    private static final int TYPEFACE_MONOSPACE = 3;
    private static final int TYPEFACE_SANS = 1;
    private static final int TYPEFACE_SERIF = 2;
    /* access modifiers changed from: private */
    public Typeface font;
    public final String fontFamily;
    private final int fontFamilyResourceId;
    /* access modifiers changed from: private */
    public boolean fontResolved = false;
    public final ColorStateList shadowColor;
    public final float shadowDx;
    public final float shadowDy;
    public final float shadowRadius;
    public final boolean textAllCaps;
    public final ColorStateList textColor;
    public final ColorStateList textColorHint;
    public final ColorStateList textColorLink;
    public final float textSize;
    public final int textStyle;
    public final int typeface;

    public TextAppearance(Context context, int id) {
        TypedArray a = context.obtainStyledAttributes(id, C0078R.styleable.TextAppearance);
        this.textSize = a.getDimension(C0078R.styleable.TextAppearance_android_textSize, 0.0f);
        this.textColor = MaterialResources.getColorStateList(context, a, C0078R.styleable.TextAppearance_android_textColor);
        this.textColorHint = MaterialResources.getColorStateList(context, a, C0078R.styleable.TextAppearance_android_textColorHint);
        this.textColorLink = MaterialResources.getColorStateList(context, a, C0078R.styleable.TextAppearance_android_textColorLink);
        this.textStyle = a.getInt(C0078R.styleable.TextAppearance_android_textStyle, 0);
        this.typeface = a.getInt(C0078R.styleable.TextAppearance_android_typeface, 1);
        int fontFamilyIndex = MaterialResources.getIndexWithValue(a, C0078R.styleable.TextAppearance_fontFamily, C0078R.styleable.TextAppearance_android_fontFamily);
        this.fontFamilyResourceId = a.getResourceId(fontFamilyIndex, 0);
        this.fontFamily = a.getString(fontFamilyIndex);
        this.textAllCaps = a.getBoolean(C0078R.styleable.TextAppearance_textAllCaps, false);
        this.shadowColor = MaterialResources.getColorStateList(context, a, C0078R.styleable.TextAppearance_android_shadowColor);
        this.shadowDx = a.getFloat(C0078R.styleable.TextAppearance_android_shadowDx, 0.0f);
        this.shadowDy = a.getFloat(C0078R.styleable.TextAppearance_android_shadowDy, 0.0f);
        this.shadowRadius = a.getFloat(C0078R.styleable.TextAppearance_android_shadowRadius, 0.0f);
        a.recycle();
    }

    public Typeface getFont(Context context) {
        if (this.fontResolved) {
            return this.font;
        }
        if (!context.isRestricted()) {
            try {
                Typeface font2 = ResourcesCompat.getFont(context, this.fontFamilyResourceId);
                this.font = font2;
                if (font2 != null) {
                    this.font = Typeface.create(font2, this.textStyle);
                }
            } catch (NotFoundException | UnsupportedOperationException e) {
            } catch (Exception e2) {
                StringBuilder sb = new StringBuilder();
                sb.append("Error loading font ");
                sb.append(this.fontFamily);
                Log.d(TAG, sb.toString(), e2);
            }
        }
        createFallbackTypeface();
        this.fontResolved = true;
        return this.font;
    }

    public void getFontAsync(Context context, final TextPaint textPaint, final FontCallback callback) {
        if (this.fontResolved) {
            updateTextPaintMeasureState(textPaint, this.font);
            return;
        }
        createFallbackTypeface();
        if (context.isRestricted()) {
            this.fontResolved = true;
            updateTextPaintMeasureState(textPaint, this.font);
            return;
        }
        try {
            ResourcesCompat.getFont(context, this.fontFamilyResourceId, new FontCallback() {
                public void onFontRetrieved(Typeface typeface) {
                    TextAppearance textAppearance = TextAppearance.this;
                    textAppearance.font = Typeface.create(typeface, textAppearance.textStyle);
                    TextAppearance.this.updateTextPaintMeasureState(textPaint, typeface);
                    TextAppearance.this.fontResolved = true;
                    callback.onFontRetrieved(typeface);
                }

                public void onFontRetrievalFailed(int reason) {
                    TextAppearance.this.createFallbackTypeface();
                    TextAppearance.this.fontResolved = true;
                    callback.onFontRetrievalFailed(reason);
                }
            }, null);
        } catch (NotFoundException | UnsupportedOperationException e) {
        } catch (Exception e2) {
            StringBuilder sb = new StringBuilder();
            sb.append("Error loading font ");
            sb.append(this.fontFamily);
            Log.d(TAG, sb.toString(), e2);
        }
    }

    /* access modifiers changed from: private */
    public void createFallbackTypeface() {
        if (this.font == null) {
            this.font = Typeface.create(this.fontFamily, this.textStyle);
        }
        if (this.font == null) {
            int i = this.typeface;
            if (i == 1) {
                this.font = Typeface.SANS_SERIF;
            } else if (i == 2) {
                this.font = Typeface.SERIF;
            } else if (i != 3) {
                this.font = Typeface.DEFAULT;
            } else {
                this.font = Typeface.MONOSPACE;
            }
            Typeface typeface2 = this.font;
            if (typeface2 != null) {
                this.font = Typeface.create(typeface2, this.textStyle);
            }
        }
    }

    public void updateDrawState(Context context, TextPaint textPaint, FontCallback callback) {
        updateMeasureState(context, textPaint, callback);
        ColorStateList colorStateList = this.textColor;
        textPaint.setColor(colorStateList != null ? colorStateList.getColorForState(textPaint.drawableState, this.textColor.getDefaultColor()) : ViewCompat.MEASURED_STATE_MASK);
        float f = this.shadowRadius;
        float f2 = this.shadowDx;
        float f3 = this.shadowDy;
        ColorStateList colorStateList2 = this.shadowColor;
        textPaint.setShadowLayer(f, f2, f3, colorStateList2 != null ? colorStateList2.getColorForState(textPaint.drawableState, this.shadowColor.getDefaultColor()) : 0);
    }

    public void updateMeasureState(Context context, TextPaint textPaint, FontCallback callback) {
        if (TextAppearanceConfig.shouldLoadFontSynchronously()) {
            updateTextPaintMeasureState(textPaint, getFont(context));
            return;
        }
        getFontAsync(context, textPaint, callback);
        if (!this.fontResolved) {
            updateTextPaintMeasureState(textPaint, this.font);
        }
    }

    public void updateTextPaintMeasureState(TextPaint textPaint, Typeface typeface2) {
        textPaint.setTypeface(typeface2);
        int fake = this.textStyle & (~typeface2.getStyle());
        textPaint.setFakeBoldText((fake & 1) != 0);
        textPaint.setTextSkewX((fake & 2) != 0 ? -0.25f : 0.0f);
        textPaint.setTextSize(this.textSize);
    }
}
