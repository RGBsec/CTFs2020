package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources.NotFoundException;
import android.graphics.PorterDuff.Mode;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.LocaleList;
import android.text.method.PasswordTransformationMethod;
import android.util.AttributeSet;
import android.widget.TextView;
import androidx.appcompat.C0003R;
import androidx.core.content.res.ResourcesCompat.FontCallback;
import androidx.core.widget.AutoSizeableTextView;
import androidx.core.widget.TextViewCompat;
import java.lang.ref.WeakReference;
import java.util.Locale;

class AppCompatTextHelper {
    private static final int MONOSPACE = 3;
    private static final int SANS = 1;
    private static final int SERIF = 2;
    private static final int TEXT_FONT_WEIGHT_UNSPECIFIED = -1;
    private boolean mAsyncFontPending;
    private final AppCompatTextViewAutoSizeHelper mAutoSizeTextHelper;
    private TintInfo mDrawableBottomTint;
    private TintInfo mDrawableEndTint;
    private TintInfo mDrawableLeftTint;
    private TintInfo mDrawableRightTint;
    private TintInfo mDrawableStartTint;
    private TintInfo mDrawableTint;
    private TintInfo mDrawableTopTint;
    private Typeface mFontTypeface;
    private int mFontWeight = -1;
    private int mStyle = 0;
    private final TextView mView;

    private static class ApplyTextViewCallback extends FontCallback {
        private final int mFontWeight;
        private final WeakReference<AppCompatTextHelper> mParent;
        private final int mStyle;

        private class TypefaceApplyCallback implements Runnable {
            private final WeakReference<AppCompatTextHelper> mParent;
            private final Typeface mTypeface;

            TypefaceApplyCallback(WeakReference<AppCompatTextHelper> parent, Typeface tf) {
                this.mParent = parent;
                this.mTypeface = tf;
            }

            public void run() {
                AppCompatTextHelper parent = (AppCompatTextHelper) this.mParent.get();
                if (parent != null) {
                    parent.setTypefaceByCallback(this.mTypeface);
                }
            }
        }

        ApplyTextViewCallback(AppCompatTextHelper parent, int fontWeight, int style) {
            this.mParent = new WeakReference<>(parent);
            this.mFontWeight = fontWeight;
            this.mStyle = style;
        }

        public void onFontRetrieved(Typeface typeface) {
            AppCompatTextHelper parent = (AppCompatTextHelper) this.mParent.get();
            if (parent != null) {
                if (VERSION.SDK_INT >= 28) {
                    int i = this.mFontWeight;
                    if (i != -1) {
                        typeface = Typeface.create(typeface, i, (this.mStyle & 2) != 0);
                    }
                }
                parent.runOnUiThread(new TypefaceApplyCallback(this.mParent, typeface));
            }
        }

        public void onFontRetrievalFailed(int reason) {
        }
    }

    AppCompatTextHelper(TextView view) {
        this.mView = view;
        this.mAutoSizeTextHelper = new AppCompatTextViewAutoSizeHelper(this.mView);
    }

    /* access modifiers changed from: 0000 */
    public void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        boolean allCapsSet;
        boolean allCaps;
        ColorStateList textColorLink;
        ColorStateList textColor;
        String localeListString;
        Drawable drawableRight;
        Drawable drawableBottom;
        Drawable drawableStart;
        AttributeSet attributeSet = attrs;
        int i = defStyleAttr;
        Context context = this.mView.getContext();
        AppCompatDrawableManager drawableManager = AppCompatDrawableManager.get();
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, attributeSet, C0003R.styleable.AppCompatTextHelper, i, 0);
        int ap = a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_textAppearance, -1);
        if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableLeft)) {
            this.mDrawableLeftTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableLeft, 0));
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableTop)) {
            this.mDrawableTopTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableTop, 0));
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableRight)) {
            this.mDrawableRightTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableRight, 0));
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableBottom)) {
            this.mDrawableBottomTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableBottom, 0));
        }
        if (VERSION.SDK_INT >= 17) {
            if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableStart)) {
                this.mDrawableStartTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableStart, 0));
            }
            if (a.hasValue(C0003R.styleable.AppCompatTextHelper_android_drawableEnd)) {
                this.mDrawableEndTint = createTintInfo(context, drawableManager, a.getResourceId(C0003R.styleable.AppCompatTextHelper_android_drawableEnd, 0));
            }
        }
        a.recycle();
        boolean hasPwdTm = this.mView.getTransformationMethod() instanceof PasswordTransformationMethod;
        boolean allCaps2 = false;
        boolean allCapsSet2 = false;
        ColorStateList textColor2 = null;
        ColorStateList textColorHint = null;
        ColorStateList textColorLink2 = null;
        String fontVariation = null;
        String localeListString2 = null;
        if (ap != -1) {
            TintTypedArray a2 = TintTypedArray.obtainStyledAttributes(context, ap, C0003R.styleable.TextAppearance);
            if (!hasPwdTm && a2.hasValue(C0003R.styleable.TextAppearance_textAllCaps)) {
                allCapsSet2 = true;
                allCaps2 = a2.getBoolean(C0003R.styleable.TextAppearance_textAllCaps, false);
            }
            updateTypefaceAndStyle(context, a2);
            if (VERSION.SDK_INT < 23) {
                if (a2.hasValue(C0003R.styleable.TextAppearance_android_textColor)) {
                    textColor2 = a2.getColorStateList(C0003R.styleable.TextAppearance_android_textColor);
                }
                if (a2.hasValue(C0003R.styleable.TextAppearance_android_textColorHint)) {
                    textColorHint = a2.getColorStateList(C0003R.styleable.TextAppearance_android_textColorHint);
                }
                if (a2.hasValue(C0003R.styleable.TextAppearance_android_textColorLink)) {
                    textColorLink2 = a2.getColorStateList(C0003R.styleable.TextAppearance_android_textColorLink);
                }
            }
            if (a2.hasValue(C0003R.styleable.TextAppearance_textLocale)) {
                localeListString2 = a2.getString(C0003R.styleable.TextAppearance_textLocale);
            }
            if (VERSION.SDK_INT >= 26 && a2.hasValue(C0003R.styleable.TextAppearance_fontVariationSettings)) {
                fontVariation = a2.getString(C0003R.styleable.TextAppearance_fontVariationSettings);
            }
            a2.recycle();
        }
        TintTypedArray a3 = TintTypedArray.obtainStyledAttributes(context, attributeSet, C0003R.styleable.TextAppearance, i, 0);
        if (hasPwdTm || !a3.hasValue(C0003R.styleable.TextAppearance_textAllCaps)) {
            allCaps = allCaps2;
            allCapsSet = allCapsSet2;
        } else {
            allCaps = a3.getBoolean(C0003R.styleable.TextAppearance_textAllCaps, false);
            allCapsSet = true;
        }
        if (VERSION.SDK_INT < 23) {
            if (a3.hasValue(C0003R.styleable.TextAppearance_android_textColor)) {
                textColor2 = a3.getColorStateList(C0003R.styleable.TextAppearance_android_textColor);
            }
            if (a3.hasValue(C0003R.styleable.TextAppearance_android_textColorHint)) {
                textColorHint = a3.getColorStateList(C0003R.styleable.TextAppearance_android_textColorHint);
            }
            if (a3.hasValue(C0003R.styleable.TextAppearance_android_textColorLink)) {
                textColorLink = textColor2;
                textColor = a3.getColorStateList(C0003R.styleable.TextAppearance_android_textColorLink);
            } else {
                ColorStateList colorStateList = textColorLink2;
                textColorLink = textColor2;
                textColor = colorStateList;
            }
        } else {
            ColorStateList colorStateList2 = textColorLink2;
            textColorLink = textColor2;
            textColor = colorStateList2;
        }
        if (a3.hasValue(C0003R.styleable.TextAppearance_textLocale)) {
            localeListString = a3.getString(C0003R.styleable.TextAppearance_textLocale);
        } else {
            localeListString = localeListString2;
        }
        if (VERSION.SDK_INT >= 26 && a3.hasValue(C0003R.styleable.TextAppearance_fontVariationSettings)) {
            fontVariation = a3.getString(C0003R.styleable.TextAppearance_fontVariationSettings);
        }
        if (VERSION.SDK_INT < 28) {
        } else if (!a3.hasValue(C0003R.styleable.TextAppearance_android_textSize)) {
        } else if (a3.getDimensionPixelSize(C0003R.styleable.TextAppearance_android_textSize, -1) == 0) {
            int i2 = ap;
            this.mView.setTextSize(0, 0.0f);
        }
        updateTypefaceAndStyle(context, a3);
        a3.recycle();
        if (textColorLink != null) {
            this.mView.setTextColor(textColorLink);
        }
        if (textColorHint != null) {
            this.mView.setHintTextColor(textColorHint);
        }
        if (textColor != null) {
            this.mView.setLinkTextColor(textColor);
        }
        if (!hasPwdTm && allCapsSet) {
            setAllCaps(allCaps);
        }
        Typeface typeface = this.mFontTypeface;
        if (typeface != null) {
            if (this.mFontWeight == -1) {
                this.mView.setTypeface(typeface, this.mStyle);
            } else {
                this.mView.setTypeface(typeface);
            }
        }
        if (fontVariation != null) {
            this.mView.setFontVariationSettings(fontVariation);
        }
        if (localeListString != null) {
            if (VERSION.SDK_INT >= 24) {
                this.mView.setTextLocales(LocaleList.forLanguageTags(localeListString));
            } else if (VERSION.SDK_INT >= 21) {
                this.mView.setTextLocale(Locale.forLanguageTag(localeListString.substring(0, localeListString.indexOf(44))));
            }
        }
        this.mAutoSizeTextHelper.loadFromAttributes(attributeSet, i);
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE) {
            String str = localeListString;
            ColorStateList colorStateList3 = textColor;
        } else if (this.mAutoSizeTextHelper.getAutoSizeTextType() != 0) {
            int[] autoSizeTextSizesInPx = this.mAutoSizeTextHelper.getAutoSizeTextAvailableSizes();
            if (autoSizeTextSizesInPx.length <= 0) {
                String str2 = localeListString;
                ColorStateList colorStateList4 = textColor;
            } else if (((float) this.mView.getAutoSizeStepGranularity()) != -1.0f) {
                TintTypedArray tintTypedArray = a3;
                String str3 = localeListString;
                ColorStateList colorStateList5 = textColor;
                this.mView.setAutoSizeTextTypeUniformWithConfiguration(this.mAutoSizeTextHelper.getAutoSizeMinTextSize(), this.mAutoSizeTextHelper.getAutoSizeMaxTextSize(), this.mAutoSizeTextHelper.getAutoSizeStepGranularity(), 0);
            } else {
                String str4 = localeListString;
                ColorStateList colorStateList6 = textColor;
                this.mView.setAutoSizeTextTypeUniformWithPresetSizes(autoSizeTextSizesInPx, 0);
            }
        } else {
            String str5 = localeListString;
            ColorStateList colorStateList7 = textColor;
        }
        TintTypedArray a4 = TintTypedArray.obtainStyledAttributes(context, attributeSet, C0003R.styleable.AppCompatTextView);
        Drawable drawableEnd = null;
        Drawable drawableLeft = null;
        Drawable drawableTop = null;
        int drawableLeftId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableLeftCompat, -1);
        if (drawableLeftId != -1) {
            drawableLeft = drawableManager.getDrawable(context, drawableLeftId);
        }
        int i3 = drawableLeftId;
        int drawableTopId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableTopCompat, -1);
        if (drawableTopId != -1) {
            drawableTop = drawableManager.getDrawable(context, drawableTopId);
        }
        int i4 = drawableTopId;
        int drawableRightId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableRightCompat, -1);
        if (drawableRightId != -1) {
            drawableRight = drawableManager.getDrawable(context, drawableRightId);
        } else {
            drawableRight = null;
        }
        int drawableBottomId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableBottomCompat, -1);
        if (drawableBottomId != -1) {
            drawableBottom = drawableManager.getDrawable(context, drawableBottomId);
        } else {
            drawableBottom = null;
        }
        int drawableStartId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableStartCompat, -1);
        if (drawableStartId != -1) {
            drawableStart = drawableManager.getDrawable(context, drawableStartId);
        } else {
            drawableStart = null;
        }
        int drawableEndId = a4.getResourceId(C0003R.styleable.AppCompatTextView_drawableEndCompat, -1);
        if (drawableEndId != -1) {
            drawableEnd = drawableManager.getDrawable(context, drawableEndId);
        }
        int i5 = drawableRightId;
        int i6 = drawableBottomId;
        int i7 = drawableStartId;
        int i8 = drawableEndId;
        ColorStateList colorStateList8 = textColorHint;
        ColorStateList colorStateList9 = textColorLink;
        setCompoundDrawables(drawableLeft, drawableTop, drawableRight, drawableBottom, drawableStart, drawableEnd);
        if (a4.hasValue(C0003R.styleable.AppCompatTextView_drawableTint)) {
            TextViewCompat.setCompoundDrawableTintList(this.mView, a4.getColorStateList(C0003R.styleable.AppCompatTextView_drawableTint));
        }
        if (a4.hasValue(C0003R.styleable.AppCompatTextView_drawableTintMode)) {
            TextViewCompat.setCompoundDrawableTintMode(this.mView, DrawableUtils.parseTintMode(a4.getInt(C0003R.styleable.AppCompatTextView_drawableTintMode, -1), null));
        }
        int firstBaselineToTopHeight = a4.getDimensionPixelSize(C0003R.styleable.AppCompatTextView_firstBaselineToTopHeight, -1);
        int lastBaselineToBottomHeight = a4.getDimensionPixelSize(C0003R.styleable.AppCompatTextView_lastBaselineToBottomHeight, -1);
        int lineHeight = a4.getDimensionPixelSize(C0003R.styleable.AppCompatTextView_lineHeight, -1);
        a4.recycle();
        if (firstBaselineToTopHeight != -1) {
            TextViewCompat.setFirstBaselineToTopHeight(this.mView, firstBaselineToTopHeight);
        }
        if (lastBaselineToBottomHeight != -1) {
            TextViewCompat.setLastBaselineToBottomHeight(this.mView, lastBaselineToBottomHeight);
        }
        if (lineHeight != -1) {
            TextViewCompat.setLineHeight(this.mView, lineHeight);
        }
    }

    public void setTypefaceByCallback(Typeface typeface) {
        if (this.mAsyncFontPending) {
            this.mView.setTypeface(typeface);
            this.mFontTypeface = typeface;
        }
    }

    public void runOnUiThread(Runnable runnable) {
        this.mView.post(runnable);
    }

    private void updateTypefaceAndStyle(Context context, TintTypedArray a) {
        this.mStyle = a.getInt(C0003R.styleable.TextAppearance_android_textStyle, this.mStyle);
        boolean z = false;
        if (VERSION.SDK_INT >= 28) {
            int i = a.getInt(C0003R.styleable.TextAppearance_android_textFontWeight, -1);
            this.mFontWeight = i;
            if (i != -1) {
                this.mStyle = (this.mStyle & 2) | 0;
            }
        }
        if (a.hasValue(C0003R.styleable.TextAppearance_android_fontFamily) || a.hasValue(C0003R.styleable.TextAppearance_fontFamily)) {
            this.mFontTypeface = null;
            int fontFamilyId = a.hasValue(C0003R.styleable.TextAppearance_fontFamily) ? C0003R.styleable.TextAppearance_fontFamily : C0003R.styleable.TextAppearance_android_fontFamily;
            int fontWeight = this.mFontWeight;
            int style = this.mStyle;
            if (!context.isRestricted()) {
                try {
                    Typeface typeface = a.getFont(fontFamilyId, this.mStyle, new ApplyTextViewCallback(this, fontWeight, style));
                    if (typeface != null) {
                        if (VERSION.SDK_INT < 28 || this.mFontWeight == -1) {
                            this.mFontTypeface = typeface;
                        } else {
                            this.mFontTypeface = Typeface.create(Typeface.create(typeface, 0), this.mFontWeight, (this.mStyle & 2) != 0);
                        }
                    }
                    this.mAsyncFontPending = this.mFontTypeface == null;
                } catch (NotFoundException | UnsupportedOperationException e) {
                }
            }
            if (this.mFontTypeface == null) {
                String fontFamilyName = a.getString(fontFamilyId);
                if (fontFamilyName != null) {
                    if (VERSION.SDK_INT < 28 || this.mFontWeight == -1) {
                        this.mFontTypeface = Typeface.create(fontFamilyName, this.mStyle);
                    } else {
                        Typeface create = Typeface.create(fontFamilyName, 0);
                        int i2 = this.mFontWeight;
                        if ((2 & this.mStyle) != 0) {
                            z = true;
                        }
                        this.mFontTypeface = Typeface.create(create, i2, z);
                    }
                }
            }
            return;
        }
        if (a.hasValue(C0003R.styleable.TextAppearance_android_typeface)) {
            this.mAsyncFontPending = false;
            int typefaceIndex = a.getInt(C0003R.styleable.TextAppearance_android_typeface, 1);
            if (typefaceIndex == 1) {
                this.mFontTypeface = Typeface.SANS_SERIF;
            } else if (typefaceIndex == 2) {
                this.mFontTypeface = Typeface.SERIF;
            } else if (typefaceIndex == 3) {
                this.mFontTypeface = Typeface.MONOSPACE;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void onSetTextAppearance(Context context, int resId) {
        TintTypedArray a = TintTypedArray.obtainStyledAttributes(context, resId, C0003R.styleable.TextAppearance);
        if (a.hasValue(C0003R.styleable.TextAppearance_textAllCaps)) {
            setAllCaps(a.getBoolean(C0003R.styleable.TextAppearance_textAllCaps, false));
        }
        if (VERSION.SDK_INT < 23 && a.hasValue(C0003R.styleable.TextAppearance_android_textColor)) {
            ColorStateList textColor = a.getColorStateList(C0003R.styleable.TextAppearance_android_textColor);
            if (textColor != null) {
                this.mView.setTextColor(textColor);
            }
        }
        if (a.hasValue(C0003R.styleable.TextAppearance_android_textSize) && a.getDimensionPixelSize(C0003R.styleable.TextAppearance_android_textSize, -1) == 0) {
            this.mView.setTextSize(0, 0.0f);
        }
        updateTypefaceAndStyle(context, a);
        if (VERSION.SDK_INT >= 26 && a.hasValue(C0003R.styleable.TextAppearance_fontVariationSettings)) {
            String fontVariation = a.getString(C0003R.styleable.TextAppearance_fontVariationSettings);
            if (fontVariation != null) {
                this.mView.setFontVariationSettings(fontVariation);
            }
        }
        a.recycle();
        Typeface typeface = this.mFontTypeface;
        if (typeface != null) {
            this.mView.setTypeface(typeface, this.mStyle);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setAllCaps(boolean allCaps) {
        this.mView.setAllCaps(allCaps);
    }

    /* access modifiers changed from: 0000 */
    public void onSetCompoundDrawables() {
        applyCompoundDrawablesTints();
    }

    /* access modifiers changed from: 0000 */
    public void applyCompoundDrawablesTints() {
        if (!(this.mDrawableLeftTint == null && this.mDrawableTopTint == null && this.mDrawableRightTint == null && this.mDrawableBottomTint == null)) {
            Drawable[] compoundDrawables = this.mView.getCompoundDrawables();
            applyCompoundDrawableTint(compoundDrawables[0], this.mDrawableLeftTint);
            applyCompoundDrawableTint(compoundDrawables[1], this.mDrawableTopTint);
            applyCompoundDrawableTint(compoundDrawables[2], this.mDrawableRightTint);
            applyCompoundDrawableTint(compoundDrawables[3], this.mDrawableBottomTint);
        }
        if (VERSION.SDK_INT < 17) {
            return;
        }
        if (this.mDrawableStartTint != null || this.mDrawableEndTint != null) {
            Drawable[] compoundDrawables2 = this.mView.getCompoundDrawablesRelative();
            applyCompoundDrawableTint(compoundDrawables2[0], this.mDrawableStartTint);
            applyCompoundDrawableTint(compoundDrawables2[2], this.mDrawableEndTint);
        }
    }

    private void applyCompoundDrawableTint(Drawable drawable, TintInfo info) {
        if (drawable != null && info != null) {
            AppCompatDrawableManager.tintDrawable(drawable, info, this.mView.getDrawableState());
        }
    }

    private static TintInfo createTintInfo(Context context, AppCompatDrawableManager drawableManager, int drawableId) {
        ColorStateList tintList = drawableManager.getTintList(context, drawableId);
        if (tintList == null) {
            return null;
        }
        TintInfo tintInfo = new TintInfo();
        tintInfo.mHasTintList = true;
        tintInfo.mTintList = tintList;
        return tintInfo;
    }

    /* access modifiers changed from: 0000 */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE) {
            autoSizeText();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setTextSize(int unit, float size) {
        if (!AutoSizeableTextView.PLATFORM_SUPPORTS_AUTOSIZE && !isAutoSizeEnabled()) {
            setTextSizeInternal(unit, size);
        }
    }

    /* access modifiers changed from: 0000 */
    public void autoSizeText() {
        this.mAutoSizeTextHelper.autoSizeText();
    }

    /* access modifiers changed from: 0000 */
    public boolean isAutoSizeEnabled() {
        return this.mAutoSizeTextHelper.isAutoSizeEnabled();
    }

    private void setTextSizeInternal(int unit, float size) {
        this.mAutoSizeTextHelper.setTextSizeInternal(unit, size);
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeWithDefaults(int autoSizeTextType) {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeWithDefaults(autoSizeTextType);
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeUniformWithConfiguration(int autoSizeMinTextSize, int autoSizeMaxTextSize, int autoSizeStepGranularity, int unit) throws IllegalArgumentException {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeUniformWithConfiguration(autoSizeMinTextSize, autoSizeMaxTextSize, autoSizeStepGranularity, unit);
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeUniformWithPresetSizes(int[] presetSizes, int unit) throws IllegalArgumentException {
        this.mAutoSizeTextHelper.setAutoSizeTextTypeUniformWithPresetSizes(presetSizes, unit);
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeTextType() {
        return this.mAutoSizeTextHelper.getAutoSizeTextType();
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeStepGranularity() {
        return this.mAutoSizeTextHelper.getAutoSizeStepGranularity();
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeMinTextSize() {
        return this.mAutoSizeTextHelper.getAutoSizeMinTextSize();
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeMaxTextSize() {
        return this.mAutoSizeTextHelper.getAutoSizeMaxTextSize();
    }

    /* access modifiers changed from: 0000 */
    public int[] getAutoSizeTextAvailableSizes() {
        return this.mAutoSizeTextHelper.getAutoSizeTextAvailableSizes();
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getCompoundDrawableTintList() {
        TintInfo tintInfo = this.mDrawableTint;
        if (tintInfo != null) {
            return tintInfo.mTintList;
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void setCompoundDrawableTintList(ColorStateList tintList) {
        if (this.mDrawableTint == null) {
            this.mDrawableTint = new TintInfo();
        }
        this.mDrawableTint.mTintList = tintList;
        this.mDrawableTint.mHasTintList = tintList != null;
        setCompoundTints();
    }

    /* access modifiers changed from: 0000 */
    public Mode getCompoundDrawableTintMode() {
        TintInfo tintInfo = this.mDrawableTint;
        if (tintInfo != null) {
            return tintInfo.mTintMode;
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void setCompoundDrawableTintMode(Mode tintMode) {
        if (this.mDrawableTint == null) {
            this.mDrawableTint = new TintInfo();
        }
        this.mDrawableTint.mTintMode = tintMode;
        this.mDrawableTint.mHasTintMode = tintMode != null;
        setCompoundTints();
    }

    private void setCompoundTints() {
        TintInfo tintInfo = this.mDrawableTint;
        this.mDrawableLeftTint = tintInfo;
        this.mDrawableTopTint = tintInfo;
        this.mDrawableRightTint = tintInfo;
        this.mDrawableBottomTint = tintInfo;
        this.mDrawableStartTint = tintInfo;
        this.mDrawableEndTint = tintInfo;
    }

    private void setCompoundDrawables(Drawable drawableLeft, Drawable drawableTop, Drawable drawableRight, Drawable drawableBottom, Drawable drawableStart, Drawable drawableEnd) {
        if (VERSION.SDK_INT >= 17 && (drawableStart != null || drawableEnd != null)) {
            Drawable[] existingRel = this.mView.getCompoundDrawablesRelative();
            this.mView.setCompoundDrawablesRelativeWithIntrinsicBounds(drawableStart != null ? drawableStart : existingRel[0], drawableTop != null ? drawableTop : existingRel[1], drawableEnd != null ? drawableEnd : existingRel[2], drawableBottom != null ? drawableBottom : existingRel[3]);
        } else if (!(drawableLeft == null && drawableTop == null && drawableRight == null && drawableBottom == null)) {
            if (VERSION.SDK_INT >= 17) {
                Drawable[] existingRel2 = this.mView.getCompoundDrawablesRelative();
                if (!(existingRel2[0] == null && existingRel2[2] == null)) {
                    this.mView.setCompoundDrawablesRelativeWithIntrinsicBounds(existingRel2[0], drawableTop != null ? drawableTop : existingRel2[1], existingRel2[2], drawableBottom != null ? drawableBottom : existingRel2[3]);
                    return;
                }
            }
            Drawable[] existingAbs = this.mView.getCompoundDrawables();
            this.mView.setCompoundDrawablesWithIntrinsicBounds(drawableLeft != null ? drawableLeft : existingAbs[0], drawableTop != null ? drawableTop : existingAbs[1], drawableRight != null ? drawableRight : existingAbs[2], drawableBottom != null ? drawableBottom : existingAbs[3]);
        }
    }
}
