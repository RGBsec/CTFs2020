package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.view.ActionMode.Callback;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.textclassifier.TextClassifier;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.graphics.TypefaceCompat;
import androidx.core.text.PrecomputedTextCompat;
import androidx.core.text.PrecomputedTextCompat.Params;
import androidx.core.view.TintableBackgroundView;
import androidx.core.widget.AutoSizeableTextView;
import androidx.core.widget.TextViewCompat;
import androidx.core.widget.TintableCompoundDrawablesView;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class AppCompatTextView extends TextView implements TintableBackgroundView, TintableCompoundDrawablesView, AutoSizeableTextView {
    private final AppCompatBackgroundHelper mBackgroundTintHelper;
    private Future<PrecomputedTextCompat> mPrecomputedTextFuture;
    private final AppCompatTextClassifierHelper mTextClassifierHelper;
    private final AppCompatTextHelper mTextHelper;

    public AppCompatTextView(Context context) {
        this(context, null);
    }

    public AppCompatTextView(Context context, AttributeSet attrs) {
        this(context, attrs, 16842884);
    }

    public AppCompatTextView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(TintContextWrapper.wrap(context), attrs, defStyleAttr);
        AppCompatBackgroundHelper appCompatBackgroundHelper = new AppCompatBackgroundHelper(this);
        this.mBackgroundTintHelper = appCompatBackgroundHelper;
        appCompatBackgroundHelper.loadFromAttributes(attrs, defStyleAttr);
        AppCompatTextHelper appCompatTextHelper = new AppCompatTextHelper(this);
        this.mTextHelper = appCompatTextHelper;
        appCompatTextHelper.loadFromAttributes(attrs, defStyleAttr);
        this.mTextHelper.applyCompoundDrawablesTints();
        this.mTextClassifierHelper = new AppCompatTextClassifierHelper(this);
    }

    public void setBackgroundResource(int resId) {
        super.setBackgroundResource(resId);
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            appCompatBackgroundHelper.onSetBackgroundResource(resId);
        }
    }

    public void setBackgroundDrawable(Drawable background) {
        super.setBackgroundDrawable(background);
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            appCompatBackgroundHelper.onSetBackgroundDrawable(background);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList tint) {
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            appCompatBackgroundHelper.setSupportBackgroundTintList(tint);
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            return appCompatBackgroundHelper.getSupportBackgroundTintList();
        }
        return null;
    }

    public void setSupportBackgroundTintMode(Mode tintMode) {
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            appCompatBackgroundHelper.setSupportBackgroundTintMode(tintMode);
        }
    }

    public Mode getSupportBackgroundTintMode() {
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            return appCompatBackgroundHelper.getSupportBackgroundTintMode();
        }
        return null;
    }

    public void setTextAppearance(Context context, int resId) {
        super.setTextAppearance(context, resId);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetTextAppearance(context, resId);
        }
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        super.drawableStateChanged();
        AppCompatBackgroundHelper appCompatBackgroundHelper = this.mBackgroundTintHelper;
        if (appCompatBackgroundHelper != null) {
            appCompatBackgroundHelper.applySupportBackgroundTint();
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.applyCompoundDrawablesTints();
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onLayout(changed, left, top, right, bottom);
        }
    }

    public void setTextSize(int unit, float size) {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            super.setTextSize(unit, size);
            return;
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.setTextSize(unit, size);
        }
    }

    /* access modifiers changed from: protected */
    public void onTextChanged(CharSequence text, int start, int lengthBefore, int lengthAfter) {
        super.onTextChanged(text, start, lengthBefore, lengthAfter);
        if (this.mTextHelper != null && !PLATFORM_SUPPORTS_AUTOSIZE && this.mTextHelper.isAutoSizeEnabled()) {
            this.mTextHelper.autoSizeText();
        }
    }

    public void setAutoSizeTextTypeWithDefaults(int autoSizeTextType) {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            super.setAutoSizeTextTypeWithDefaults(autoSizeTextType);
            return;
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.setAutoSizeTextTypeWithDefaults(autoSizeTextType);
        }
    }

    public void setAutoSizeTextTypeUniformWithConfiguration(int autoSizeMinTextSize, int autoSizeMaxTextSize, int autoSizeStepGranularity, int unit) throws IllegalArgumentException {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            super.setAutoSizeTextTypeUniformWithConfiguration(autoSizeMinTextSize, autoSizeMaxTextSize, autoSizeStepGranularity, unit);
            return;
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.setAutoSizeTextTypeUniformWithConfiguration(autoSizeMinTextSize, autoSizeMaxTextSize, autoSizeStepGranularity, unit);
        }
    }

    public void setAutoSizeTextTypeUniformWithPresetSizes(int[] presetSizes, int unit) throws IllegalArgumentException {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            super.setAutoSizeTextTypeUniformWithPresetSizes(presetSizes, unit);
            return;
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.setAutoSizeTextTypeUniformWithPresetSizes(presetSizes, unit);
        }
    }

    public int getAutoSizeTextType() {
        int i = 0;
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            if (super.getAutoSizeTextType() == 1) {
                i = 1;
            }
            return i;
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            return appCompatTextHelper.getAutoSizeTextType();
        }
        return 0;
    }

    public int getAutoSizeStepGranularity() {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            return super.getAutoSizeStepGranularity();
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            return appCompatTextHelper.getAutoSizeStepGranularity();
        }
        return -1;
    }

    public int getAutoSizeMinTextSize() {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            return super.getAutoSizeMinTextSize();
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            return appCompatTextHelper.getAutoSizeMinTextSize();
        }
        return -1;
    }

    public int getAutoSizeMaxTextSize() {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            return super.getAutoSizeMaxTextSize();
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            return appCompatTextHelper.getAutoSizeMaxTextSize();
        }
        return -1;
    }

    public int[] getAutoSizeTextAvailableSizes() {
        if (PLATFORM_SUPPORTS_AUTOSIZE) {
            return super.getAutoSizeTextAvailableSizes();
        }
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            return appCompatTextHelper.getAutoSizeTextAvailableSizes();
        }
        return new int[0];
    }

    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        return AppCompatHintHelper.onCreateInputConnection(super.onCreateInputConnection(outAttrs), outAttrs, this);
    }

    public void setFirstBaselineToTopHeight(int firstBaselineToTopHeight) {
        if (VERSION.SDK_INT >= 28) {
            super.setFirstBaselineToTopHeight(firstBaselineToTopHeight);
        } else {
            TextViewCompat.setFirstBaselineToTopHeight(this, firstBaselineToTopHeight);
        }
    }

    public void setLastBaselineToBottomHeight(int lastBaselineToBottomHeight) {
        if (VERSION.SDK_INT >= 28) {
            super.setLastBaselineToBottomHeight(lastBaselineToBottomHeight);
        } else {
            TextViewCompat.setLastBaselineToBottomHeight(this, lastBaselineToBottomHeight);
        }
    }

    public int getFirstBaselineToTopHeight() {
        return TextViewCompat.getFirstBaselineToTopHeight(this);
    }

    public int getLastBaselineToBottomHeight() {
        return TextViewCompat.getLastBaselineToBottomHeight(this);
    }

    public void setLineHeight(int lineHeight) {
        TextViewCompat.setLineHeight(this, lineHeight);
    }

    public void setCustomSelectionActionModeCallback(Callback actionModeCallback) {
        super.setCustomSelectionActionModeCallback(TextViewCompat.wrapCustomSelectionActionModeCallback(this, actionModeCallback));
    }

    public Params getTextMetricsParamsCompat() {
        return TextViewCompat.getTextMetricsParams(this);
    }

    public void setTextMetricsParamsCompat(Params params) {
        TextViewCompat.setTextMetricsParams(this, params);
    }

    public void setPrecomputedText(PrecomputedTextCompat precomputed) {
        TextViewCompat.setPrecomputedText(this, precomputed);
    }

    private void consumeTextFutureAndSetBlocking() {
        Future<PrecomputedTextCompat> future = this.mPrecomputedTextFuture;
        if (future != null) {
            try {
                this.mPrecomputedTextFuture = null;
                TextViewCompat.setPrecomputedText(this, (PrecomputedTextCompat) future.get());
            } catch (InterruptedException | ExecutionException e) {
            }
        }
    }

    public CharSequence getText() {
        consumeTextFutureAndSetBlocking();
        return super.getText();
    }

    public void setTextClassifier(TextClassifier textClassifier) {
        if (VERSION.SDK_INT < 28) {
            AppCompatTextClassifierHelper appCompatTextClassifierHelper = this.mTextClassifierHelper;
            if (appCompatTextClassifierHelper != null) {
                appCompatTextClassifierHelper.setTextClassifier(textClassifier);
                return;
            }
        }
        super.setTextClassifier(textClassifier);
    }

    public TextClassifier getTextClassifier() {
        if (VERSION.SDK_INT < 28) {
            AppCompatTextClassifierHelper appCompatTextClassifierHelper = this.mTextClassifierHelper;
            if (appCompatTextClassifierHelper != null) {
                return appCompatTextClassifierHelper.getTextClassifier();
            }
        }
        return super.getTextClassifier();
    }

    public void setTextFuture(Future<PrecomputedTextCompat> future) {
        this.mPrecomputedTextFuture = future;
        if (future != null) {
            requestLayout();
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        consumeTextFutureAndSetBlocking();
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    public void setCompoundDrawables(Drawable left, Drawable top, Drawable right, Drawable bottom) {
        super.setCompoundDrawables(left, top, right, bottom);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public void setCompoundDrawablesRelative(Drawable start, Drawable top, Drawable end, Drawable bottom) {
        super.setCompoundDrawablesRelative(start, top, end, bottom);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public void setCompoundDrawablesWithIntrinsicBounds(Drawable left, Drawable top, Drawable right, Drawable bottom) {
        super.setCompoundDrawablesWithIntrinsicBounds(left, top, right, bottom);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public void setCompoundDrawablesWithIntrinsicBounds(int left, int top, int right, int bottom) {
        Context context = getContext();
        Drawable drawable = null;
        Drawable drawable2 = left != 0 ? AppCompatResources.getDrawable(context, left) : null;
        Drawable drawable3 = top != 0 ? AppCompatResources.getDrawable(context, top) : null;
        Drawable drawable4 = right != 0 ? AppCompatResources.getDrawable(context, right) : null;
        if (bottom != 0) {
            drawable = AppCompatResources.getDrawable(context, bottom);
        }
        setCompoundDrawablesWithIntrinsicBounds(drawable2, drawable3, drawable4, drawable);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public void setCompoundDrawablesRelativeWithIntrinsicBounds(Drawable start, Drawable top, Drawable end, Drawable bottom) {
        super.setCompoundDrawablesRelativeWithIntrinsicBounds(start, top, end, bottom);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public void setCompoundDrawablesRelativeWithIntrinsicBounds(int start, int top, int end, int bottom) {
        Context context = getContext();
        Drawable drawable = null;
        Drawable drawable2 = start != 0 ? AppCompatResources.getDrawable(context, start) : null;
        Drawable drawable3 = top != 0 ? AppCompatResources.getDrawable(context, top) : null;
        Drawable drawable4 = end != 0 ? AppCompatResources.getDrawable(context, end) : null;
        if (bottom != 0) {
            drawable = AppCompatResources.getDrawable(context, bottom);
        }
        setCompoundDrawablesRelativeWithIntrinsicBounds(drawable2, drawable3, drawable4, drawable);
        AppCompatTextHelper appCompatTextHelper = this.mTextHelper;
        if (appCompatTextHelper != null) {
            appCompatTextHelper.onSetCompoundDrawables();
        }
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.mTextHelper.getCompoundDrawableTintList();
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList tintList) {
        this.mTextHelper.setCompoundDrawableTintList(tintList);
        this.mTextHelper.applyCompoundDrawablesTints();
    }

    public Mode getSupportCompoundDrawablesTintMode() {
        return this.mTextHelper.getCompoundDrawableTintMode();
    }

    public void setSupportCompoundDrawablesTintMode(Mode tintMode) {
        this.mTextHelper.setCompoundDrawableTintMode(tintMode);
        this.mTextHelper.applyCompoundDrawablesTints();
    }

    public void setTypeface(Typeface tf, int style) {
        Typeface finalTypeface = null;
        if (tf != null && style > 0) {
            finalTypeface = TypefaceCompat.create(getContext(), tf, style);
        }
        super.setTypeface(finalTypeface != null ? finalTypeface : tf, style);
    }
}
