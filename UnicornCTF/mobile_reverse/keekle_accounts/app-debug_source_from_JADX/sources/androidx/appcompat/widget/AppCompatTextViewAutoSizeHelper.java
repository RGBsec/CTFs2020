package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.RectF;
import android.os.Build.VERSION;
import android.text.Layout.Alignment;
import android.text.StaticLayout;
import android.text.StaticLayout.Builder;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.text.TextPaint;
import android.text.method.TransformationMethod;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.TypedValue;
import android.widget.TextView;
import androidx.appcompat.C0003R;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

class AppCompatTextViewAutoSizeHelper {
    private static final int DEFAULT_AUTO_SIZE_GRANULARITY_IN_PX = 1;
    private static final int DEFAULT_AUTO_SIZE_MAX_TEXT_SIZE_IN_SP = 112;
    private static final int DEFAULT_AUTO_SIZE_MIN_TEXT_SIZE_IN_SP = 12;
    private static final String TAG = "ACTVAutoSizeHelper";
    private static final RectF TEMP_RECTF = new RectF();
    static final float UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE = -1.0f;
    private static final int VERY_WIDE = 1048576;
    private static ConcurrentHashMap<String, Field> sTextViewFieldByNameCache = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String, Method> sTextViewMethodByNameCache = new ConcurrentHashMap<>();
    private float mAutoSizeMaxTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
    private float mAutoSizeMinTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
    private float mAutoSizeStepGranularityInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
    private int[] mAutoSizeTextSizesInPx = new int[0];
    private int mAutoSizeTextType = 0;
    private final Context mContext;
    private boolean mHasPresetAutoSizeValues = false;
    private boolean mNeedsAutoSizeText = false;
    private TextPaint mTempTextPaint;
    private final TextView mTextView;

    AppCompatTextViewAutoSizeHelper(TextView textView) {
        this.mTextView = textView;
        this.mContext = textView.getContext();
    }

    /* access modifiers changed from: 0000 */
    public void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        float autoSizeMinTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        float autoSizeMaxTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        float autoSizeStepGranularityInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        TypedArray a = this.mContext.obtainStyledAttributes(attrs, C0003R.styleable.AppCompatTextView, defStyleAttr, 0);
        if (a.hasValue(C0003R.styleable.AppCompatTextView_autoSizeTextType)) {
            this.mAutoSizeTextType = a.getInt(C0003R.styleable.AppCompatTextView_autoSizeTextType, 0);
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextView_autoSizeStepGranularity)) {
            autoSizeStepGranularityInPx = a.getDimension(C0003R.styleable.AppCompatTextView_autoSizeStepGranularity, UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE);
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextView_autoSizeMinTextSize)) {
            autoSizeMinTextSizeInPx = a.getDimension(C0003R.styleable.AppCompatTextView_autoSizeMinTextSize, UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE);
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextView_autoSizeMaxTextSize)) {
            autoSizeMaxTextSizeInPx = a.getDimension(C0003R.styleable.AppCompatTextView_autoSizeMaxTextSize, UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE);
        }
        if (a.hasValue(C0003R.styleable.AppCompatTextView_autoSizePresetSizes)) {
            int autoSizeStepSizeArrayResId = a.getResourceId(C0003R.styleable.AppCompatTextView_autoSizePresetSizes, 0);
            if (autoSizeStepSizeArrayResId > 0) {
                TypedArray autoSizePreDefTextSizes = a.getResources().obtainTypedArray(autoSizeStepSizeArrayResId);
                setupAutoSizeUniformPresetSizes(autoSizePreDefTextSizes);
                autoSizePreDefTextSizes.recycle();
            }
        }
        a.recycle();
        if (!supportsAutoSizeText()) {
            this.mAutoSizeTextType = 0;
        } else if (this.mAutoSizeTextType == 1) {
            if (!this.mHasPresetAutoSizeValues) {
                DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
                if (autoSizeMinTextSizeInPx == UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE) {
                    autoSizeMinTextSizeInPx = TypedValue.applyDimension(2, 12.0f, displayMetrics);
                }
                if (autoSizeMaxTextSizeInPx == UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE) {
                    autoSizeMaxTextSizeInPx = TypedValue.applyDimension(2, 112.0f, displayMetrics);
                }
                if (autoSizeStepGranularityInPx == UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE) {
                    autoSizeStepGranularityInPx = 1.0f;
                }
                validateAndSetAutoSizeTextTypeUniformConfiguration(autoSizeMinTextSizeInPx, autoSizeMaxTextSizeInPx, autoSizeStepGranularityInPx);
            }
            setupAutoSizeText();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeWithDefaults(int autoSizeTextType) {
        if (!supportsAutoSizeText()) {
            return;
        }
        if (autoSizeTextType == 0) {
            clearAutoSizeConfiguration();
        } else if (autoSizeTextType == 1) {
            DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
            validateAndSetAutoSizeTextTypeUniformConfiguration(TypedValue.applyDimension(2, 12.0f, displayMetrics), TypedValue.applyDimension(2, 112.0f, displayMetrics), 1.0f);
            if (setupAutoSizeText()) {
                autoSizeText();
            }
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("Unknown auto-size text type: ");
            sb.append(autoSizeTextType);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeUniformWithConfiguration(int autoSizeMinTextSize, int autoSizeMaxTextSize, int autoSizeStepGranularity, int unit) throws IllegalArgumentException {
        if (supportsAutoSizeText()) {
            DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
            validateAndSetAutoSizeTextTypeUniformConfiguration(TypedValue.applyDimension(unit, (float) autoSizeMinTextSize, displayMetrics), TypedValue.applyDimension(unit, (float) autoSizeMaxTextSize, displayMetrics), TypedValue.applyDimension(unit, (float) autoSizeStepGranularity, displayMetrics));
            if (setupAutoSizeText()) {
                autoSizeText();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void setAutoSizeTextTypeUniformWithPresetSizes(int[] presetSizes, int unit) throws IllegalArgumentException {
        if (supportsAutoSizeText()) {
            int presetSizesLength = presetSizes.length;
            if (presetSizesLength > 0) {
                int[] presetSizesInPx = new int[presetSizesLength];
                if (unit == 0) {
                    presetSizesInPx = Arrays.copyOf(presetSizes, presetSizesLength);
                } else {
                    DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
                    for (int i = 0; i < presetSizesLength; i++) {
                        presetSizesInPx[i] = Math.round(TypedValue.applyDimension(unit, (float) presetSizes[i], displayMetrics));
                    }
                }
                this.mAutoSizeTextSizesInPx = cleanupAutoSizePresetSizes(presetSizesInPx);
                if (!setupAutoSizeUniformPresetSizesConfiguration()) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("None of the preset sizes is valid: ");
                    sb.append(Arrays.toString(presetSizes));
                    throw new IllegalArgumentException(sb.toString());
                }
            } else {
                this.mHasPresetAutoSizeValues = false;
            }
            if (setupAutoSizeText()) {
                autoSizeText();
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeTextType() {
        return this.mAutoSizeTextType;
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeStepGranularity() {
        return Math.round(this.mAutoSizeStepGranularityInPx);
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeMinTextSize() {
        return Math.round(this.mAutoSizeMinTextSizeInPx);
    }

    /* access modifiers changed from: 0000 */
    public int getAutoSizeMaxTextSize() {
        return Math.round(this.mAutoSizeMaxTextSizeInPx);
    }

    /* access modifiers changed from: 0000 */
    public int[] getAutoSizeTextAvailableSizes() {
        return this.mAutoSizeTextSizesInPx;
    }

    private void setupAutoSizeUniformPresetSizes(TypedArray textSizes) {
        int textSizesLength = textSizes.length();
        int[] parsedSizes = new int[textSizesLength];
        if (textSizesLength > 0) {
            for (int i = 0; i < textSizesLength; i++) {
                parsedSizes[i] = textSizes.getDimensionPixelSize(i, -1);
            }
            this.mAutoSizeTextSizesInPx = cleanupAutoSizePresetSizes(parsedSizes);
            setupAutoSizeUniformPresetSizesConfiguration();
        }
    }

    private boolean setupAutoSizeUniformPresetSizesConfiguration() {
        int sizesLength = this.mAutoSizeTextSizesInPx.length;
        boolean z = sizesLength > 0;
        this.mHasPresetAutoSizeValues = z;
        if (z) {
            this.mAutoSizeTextType = 1;
            int[] iArr = this.mAutoSizeTextSizesInPx;
            this.mAutoSizeMinTextSizeInPx = (float) iArr[0];
            this.mAutoSizeMaxTextSizeInPx = (float) iArr[sizesLength - 1];
            this.mAutoSizeStepGranularityInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        }
        return this.mHasPresetAutoSizeValues;
    }

    private int[] cleanupAutoSizePresetSizes(int[] presetValues) {
        if (presetValuesLength == 0) {
            return presetValues;
        }
        Arrays.sort(presetValues);
        List<Integer> uniqueValidSizes = new ArrayList<>();
        for (int currentPresetValue : presetValues) {
            if (currentPresetValue > 0 && Collections.binarySearch(uniqueValidSizes, Integer.valueOf(currentPresetValue)) < 0) {
                uniqueValidSizes.add(Integer.valueOf(currentPresetValue));
            }
        }
        if (presetValuesLength == uniqueValidSizes.size()) {
            return presetValues;
        }
        int uniqueValidSizesLength = uniqueValidSizes.size();
        int[] cleanedUpSizes = new int[uniqueValidSizesLength];
        for (int i = 0; i < uniqueValidSizesLength; i++) {
            cleanedUpSizes[i] = ((Integer) uniqueValidSizes.get(i)).intValue();
        }
        return cleanedUpSizes;
    }

    private void validateAndSetAutoSizeTextTypeUniformConfiguration(float autoSizeMinTextSizeInPx, float autoSizeMaxTextSizeInPx, float autoSizeStepGranularityInPx) throws IllegalArgumentException {
        String str = "px) is less or equal to (0px)";
        if (autoSizeMinTextSizeInPx <= 0.0f) {
            StringBuilder sb = new StringBuilder();
            sb.append("Minimum auto-size text size (");
            sb.append(autoSizeMinTextSizeInPx);
            sb.append(str);
            throw new IllegalArgumentException(sb.toString());
        } else if (autoSizeMaxTextSizeInPx <= autoSizeMinTextSizeInPx) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Maximum auto-size text size (");
            sb2.append(autoSizeMaxTextSizeInPx);
            sb2.append("px) is less or equal to minimum auto-size text size (");
            sb2.append(autoSizeMinTextSizeInPx);
            sb2.append("px)");
            throw new IllegalArgumentException(sb2.toString());
        } else if (autoSizeStepGranularityInPx > 0.0f) {
            this.mAutoSizeTextType = 1;
            this.mAutoSizeMinTextSizeInPx = autoSizeMinTextSizeInPx;
            this.mAutoSizeMaxTextSizeInPx = autoSizeMaxTextSizeInPx;
            this.mAutoSizeStepGranularityInPx = autoSizeStepGranularityInPx;
            this.mHasPresetAutoSizeValues = false;
        } else {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("The auto-size step granularity (");
            sb3.append(autoSizeStepGranularityInPx);
            sb3.append(str);
            throw new IllegalArgumentException(sb3.toString());
        }
    }

    private boolean setupAutoSizeText() {
        if (!supportsAutoSizeText() || this.mAutoSizeTextType != 1) {
            this.mNeedsAutoSizeText = false;
        } else {
            if (!this.mHasPresetAutoSizeValues || this.mAutoSizeTextSizesInPx.length == 0) {
                int autoSizeValuesLength = ((int) Math.floor((double) ((this.mAutoSizeMaxTextSizeInPx - this.mAutoSizeMinTextSizeInPx) / this.mAutoSizeStepGranularityInPx))) + 1;
                int[] autoSizeTextSizesInPx = new int[autoSizeValuesLength];
                for (int i = 0; i < autoSizeValuesLength; i++) {
                    autoSizeTextSizesInPx[i] = Math.round(this.mAutoSizeMinTextSizeInPx + (((float) i) * this.mAutoSizeStepGranularityInPx));
                }
                this.mAutoSizeTextSizesInPx = cleanupAutoSizePresetSizes(autoSizeTextSizesInPx);
            }
            this.mNeedsAutoSizeText = true;
        }
        return this.mNeedsAutoSizeText;
    }

    /* access modifiers changed from: 0000 */
    public void autoSizeText() {
        boolean horizontallyScrolling;
        int availableWidth;
        if (isAutoSizeEnabled()) {
            if (this.mNeedsAutoSizeText) {
                if (this.mTextView.getMeasuredHeight() > 0 && this.mTextView.getMeasuredWidth() > 0) {
                    if (VERSION.SDK_INT >= 29) {
                        horizontallyScrolling = this.mTextView.isHorizontallyScrollable();
                    } else {
                        horizontallyScrolling = ((Boolean) invokeAndReturnWithDefault(this.mTextView, "getHorizontallyScrolling", Boolean.valueOf(false))).booleanValue();
                    }
                    if (horizontallyScrolling) {
                        availableWidth = 1048576;
                    } else {
                        availableWidth = (this.mTextView.getMeasuredWidth() - this.mTextView.getTotalPaddingLeft()) - this.mTextView.getTotalPaddingRight();
                    }
                    int availableHeight = (this.mTextView.getHeight() - this.mTextView.getCompoundPaddingBottom()) - this.mTextView.getCompoundPaddingTop();
                    if (availableWidth > 0 && availableHeight > 0) {
                        synchronized (TEMP_RECTF) {
                            TEMP_RECTF.setEmpty();
                            TEMP_RECTF.right = (float) availableWidth;
                            TEMP_RECTF.bottom = (float) availableHeight;
                            float optimalTextSize = (float) findLargestTextSizeWhichFits(TEMP_RECTF);
                            if (optimalTextSize != this.mTextView.getTextSize()) {
                                setTextSizeInternal(0, optimalTextSize);
                            }
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            }
            this.mNeedsAutoSizeText = true;
        }
    }

    private void clearAutoSizeConfiguration() {
        this.mAutoSizeTextType = 0;
        this.mAutoSizeMinTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        this.mAutoSizeMaxTextSizeInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        this.mAutoSizeStepGranularityInPx = UNSET_AUTO_SIZE_UNIFORM_CONFIGURATION_VALUE;
        this.mAutoSizeTextSizesInPx = new int[0];
        this.mNeedsAutoSizeText = false;
    }

    /* access modifiers changed from: 0000 */
    public void setTextSizeInternal(int unit, float size) {
        Resources res;
        Context context = this.mContext;
        if (context == null) {
            res = Resources.getSystem();
        } else {
            res = context.getResources();
        }
        setRawTextSize(TypedValue.applyDimension(unit, size, res.getDisplayMetrics()));
    }

    private void setRawTextSize(float size) {
        if (size != this.mTextView.getPaint().getTextSize()) {
            this.mTextView.getPaint().setTextSize(size);
            boolean isInLayout = false;
            if (VERSION.SDK_INT >= 18) {
                isInLayout = this.mTextView.isInLayout();
            }
            if (this.mTextView.getLayout() != null) {
                this.mNeedsAutoSizeText = false;
                String str = "nullLayouts";
                try {
                    Method method = getTextViewMethod("nullLayouts");
                    if (method != null) {
                        method.invoke(this.mTextView, new Object[0]);
                    }
                } catch (Exception ex) {
                    Log.w(TAG, "Failed to invoke TextView#nullLayouts() method", ex);
                }
                if (!isInLayout) {
                    this.mTextView.requestLayout();
                } else {
                    this.mTextView.forceLayout();
                }
                this.mTextView.invalidate();
            }
        }
    }

    private int findLargestTextSizeWhichFits(RectF availableSpace) {
        int sizesCount = this.mAutoSizeTextSizesInPx.length;
        if (sizesCount != 0) {
            int bestSizeIndex = 0;
            int lowIndex = 0 + 1;
            int highIndex = sizesCount - 1;
            while (lowIndex <= highIndex) {
                int sizeToTryIndex = (lowIndex + highIndex) / 2;
                if (suggestedSizeFitsInSpace(this.mAutoSizeTextSizesInPx[sizeToTryIndex], availableSpace)) {
                    bestSizeIndex = lowIndex;
                    lowIndex = sizeToTryIndex + 1;
                } else {
                    highIndex = sizeToTryIndex - 1;
                    bestSizeIndex = highIndex;
                }
            }
            return this.mAutoSizeTextSizesInPx[bestSizeIndex];
        }
        throw new IllegalStateException("No available text sizes to choose from.");
    }

    /* access modifiers changed from: 0000 */
    public void initTempTextPaint(int suggestedSizeInPx) {
        TextPaint textPaint = this.mTempTextPaint;
        if (textPaint == null) {
            this.mTempTextPaint = new TextPaint();
        } else {
            textPaint.reset();
        }
        this.mTempTextPaint.set(this.mTextView.getPaint());
        this.mTempTextPaint.setTextSize((float) suggestedSizeInPx);
    }

    /* access modifiers changed from: 0000 */
    public StaticLayout createLayout(CharSequence text, Alignment alignment, int availableWidth, int maxLines) {
        if (VERSION.SDK_INT >= 23) {
            return createStaticLayoutForMeasuring(text, alignment, availableWidth, maxLines);
        }
        if (VERSION.SDK_INT >= 16) {
            return createStaticLayoutForMeasuringPre23(text, alignment, availableWidth);
        }
        return createStaticLayoutForMeasuringPre16(text, alignment, availableWidth);
    }

    private boolean suggestedSizeFitsInSpace(int suggestedSizeInPx, RectF availableSpace) {
        CharSequence text = this.mTextView.getText();
        TransformationMethod transformationMethod = this.mTextView.getTransformationMethod();
        if (transformationMethod != null) {
            CharSequence transformedText = transformationMethod.getTransformation(text, this.mTextView);
            if (transformedText != null) {
                text = transformedText;
            }
        }
        int maxLines = VERSION.SDK_INT >= 16 ? this.mTextView.getMaxLines() : -1;
        initTempTextPaint(suggestedSizeInPx);
        StaticLayout layout = createLayout(text, (Alignment) invokeAndReturnWithDefault(this.mTextView, "getLayoutAlignment", Alignment.ALIGN_NORMAL), Math.round(availableSpace.right), maxLines);
        return (maxLines == -1 || (layout.getLineCount() <= maxLines && layout.getLineEnd(layout.getLineCount() - 1) == text.length())) && ((float) layout.getHeight()) <= availableSpace.bottom;
    }

    private StaticLayout createStaticLayoutForMeasuring(CharSequence text, Alignment alignment, int availableWidth, int maxLines) {
        TextDirectionHeuristic textDirectionHeuristic;
        Builder layoutBuilder = Builder.obtain(text, 0, text.length(), this.mTempTextPaint, availableWidth);
        layoutBuilder.setAlignment(alignment).setLineSpacing(this.mTextView.getLineSpacingExtra(), this.mTextView.getLineSpacingMultiplier()).setIncludePad(this.mTextView.getIncludeFontPadding()).setBreakStrategy(this.mTextView.getBreakStrategy()).setHyphenationFrequency(this.mTextView.getHyphenationFrequency()).setMaxLines(maxLines == -1 ? ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED : maxLines);
        try {
            if (VERSION.SDK_INT >= 29) {
                textDirectionHeuristic = this.mTextView.getTextDirectionHeuristic();
            } else {
                textDirectionHeuristic = (TextDirectionHeuristic) invokeAndReturnWithDefault(this.mTextView, "getTextDirectionHeuristic", TextDirectionHeuristics.FIRSTSTRONG_LTR);
            }
            layoutBuilder.setTextDirection(textDirectionHeuristic);
        } catch (ClassCastException e) {
            Log.w(TAG, "Failed to obtain TextDirectionHeuristic, auto size may be incorrect");
        }
        return layoutBuilder.build();
    }

    private StaticLayout createStaticLayoutForMeasuringPre23(CharSequence text, Alignment alignment, int availableWidth) {
        CharSequence charSequence = text;
        StaticLayout staticLayout = new StaticLayout(charSequence, this.mTempTextPaint, availableWidth, alignment, this.mTextView.getLineSpacingMultiplier(), this.mTextView.getLineSpacingExtra(), this.mTextView.getIncludeFontPadding());
        return staticLayout;
    }

    private StaticLayout createStaticLayoutForMeasuringPre16(CharSequence text, Alignment alignment, int availableWidth) {
        CharSequence charSequence = text;
        StaticLayout staticLayout = new StaticLayout(charSequence, this.mTempTextPaint, availableWidth, alignment, ((Float) accessAndReturnWithDefault(this.mTextView, "mSpacingMult", Float.valueOf(1.0f))).floatValue(), ((Float) accessAndReturnWithDefault(this.mTextView, "mSpacingAdd", Float.valueOf(0.0f))).floatValue(), ((Boolean) accessAndReturnWithDefault(this.mTextView, "mIncludePad", Boolean.valueOf(true))).booleanValue());
        return staticLayout;
    }

    private static <T> T invokeAndReturnWithDefault(Object object, String methodName, T defaultValue) {
        try {
            Object invoke = getTextViewMethod(methodName).invoke(object, new Object[0]);
            if (invoke != null || 0 == 0) {
                return invoke;
            }
        } catch (Exception ex) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to invoke TextView#");
            sb.append(methodName);
            sb.append("() method");
            Log.w(str, sb.toString(), ex);
            if (0 != 0 || 1 == 0) {
                return null;
            }
        } catch (Throwable th) {
            if (0 == 0 && 1 != 0) {
                T result = defaultValue;
            }
            throw th;
        }
        return defaultValue;
    }

    private static <T> T accessAndReturnWithDefault(Object object, String fieldName, T defaultValue) {
        try {
            Field field = getTextViewField(fieldName);
            if (field == null) {
                return defaultValue;
            }
            return field.get(object);
        } catch (IllegalAccessException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to access TextView#");
            sb.append(fieldName);
            sb.append(" member");
            Log.w(TAG, sb.toString(), e);
            return defaultValue;
        }
    }

    private static Method getTextViewMethod(String methodName) {
        try {
            Method method = (Method) sTextViewMethodByNameCache.get(methodName);
            if (method == null) {
                method = TextView.class.getDeclaredMethod(methodName, new Class[0]);
                if (method != null) {
                    method.setAccessible(true);
                    sTextViewMethodByNameCache.put(methodName, method);
                }
            }
            return method;
        } catch (Exception ex) {
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to retrieve TextView#");
            sb.append(methodName);
            sb.append("() method");
            Log.w(TAG, sb.toString(), ex);
            return null;
        }
    }

    private static Field getTextViewField(String fieldName) {
        try {
            Field field = (Field) sTextViewFieldByNameCache.get(fieldName);
            if (field == null) {
                field = TextView.class.getDeclaredField(fieldName);
                if (field != null) {
                    field.setAccessible(true);
                    sTextViewFieldByNameCache.put(fieldName, field);
                }
            }
            return field;
        } catch (NoSuchFieldException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("Failed to access TextView#");
            sb.append(fieldName);
            sb.append(" member");
            Log.w(TAG, sb.toString(), e);
            return null;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isAutoSizeEnabled() {
        return supportsAutoSizeText() && this.mAutoSizeTextType != 0;
    }

    private boolean supportsAutoSizeText() {
        return !(this.mTextView instanceof AppCompatEditText);
    }
}
