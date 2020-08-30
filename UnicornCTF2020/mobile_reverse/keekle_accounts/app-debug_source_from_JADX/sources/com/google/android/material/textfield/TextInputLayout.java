package com.google.android.material.textfield;

import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.DrawableContainer;
import android.graphics.drawable.GradientDrawable;
import android.os.Build.VERSION;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewStructure;
import android.view.accessibility.AccessibilityEvent;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.AppCompatDrawableManager;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.DrawableUtils;
import androidx.appcompat.widget.TintTypedArray;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.widget.TextViewCompat;
import androidx.customview.view.AbsSavedState;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.internal.CheckableImageButton;
import com.google.android.material.internal.CollapsingTextHelper;
import com.google.android.material.internal.DescendantOffsetUtils;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.ViewUtils;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

public class TextInputLayout extends LinearLayout {
    public static final int BOX_BACKGROUND_FILLED = 1;
    public static final int BOX_BACKGROUND_NONE = 0;
    public static final int BOX_BACKGROUND_OUTLINE = 2;
    private static final int INVALID_MAX_LENGTH = -1;
    private static final int LABEL_SCALE_ANIMATION_DURATION = 167;
    private static final String LOG_TAG = "TextInputLayout";
    private ValueAnimator animator;
    private GradientDrawable boxBackground;
    private int boxBackgroundColor;
    private int boxBackgroundMode;
    private final int boxBottomOffsetPx;
    private final int boxCollapsedPaddingTopPx;
    private float boxCornerRadiusBottomEnd;
    private float boxCornerRadiusBottomStart;
    private float boxCornerRadiusTopEnd;
    private float boxCornerRadiusTopStart;
    private final int boxLabelCutoutPaddingPx;
    private int boxStrokeColor;
    private final int boxStrokeWidthDefaultPx;
    private final int boxStrokeWidthFocusedPx;
    private int boxStrokeWidthPx;
    final CollapsingTextHelper collapsingTextHelper;
    boolean counterEnabled;
    private int counterMaxLength;
    private final int counterOverflowTextAppearance;
    private boolean counterOverflowed;
    private final int counterTextAppearance;
    private TextView counterView;
    private ColorStateList defaultHintTextColor;
    private final int defaultStrokeColor;
    private final int disabledColor;
    EditText editText;
    private Drawable editTextOriginalDrawable;
    private int focusedStrokeColor;
    private ColorStateList focusedTextColor;
    private boolean hasPasswordToggleTintList;
    private boolean hasPasswordToggleTintMode;
    private boolean hasReconstructedEditTextBackground;
    private CharSequence hint;
    private boolean hintAnimationEnabled;
    private boolean hintEnabled;
    private boolean hintExpanded;
    private final int hoveredStrokeColor;
    private boolean inDrawableStateChanged;
    private final IndicatorViewController indicatorViewController;
    private final FrameLayout inputFrame;
    private boolean isProvidingHint;
    private Drawable originalEditTextEndDrawable;
    private CharSequence originalHint;
    private CharSequence passwordToggleContentDesc;
    private Drawable passwordToggleDrawable;
    private Drawable passwordToggleDummyDrawable;
    private boolean passwordToggleEnabled;
    private ColorStateList passwordToggleTintList;
    private Mode passwordToggleTintMode;
    private CheckableImageButton passwordToggleView;
    private boolean passwordToggledVisible;
    /* access modifiers changed from: private */
    public boolean restoringSavedState;
    private final Rect tmpRect;
    private final RectF tmpRectF;
    private Typeface typeface;

    public static class AccessibilityDelegate extends AccessibilityDelegateCompat {
        private final TextInputLayout layout;

        public AccessibilityDelegate(TextInputLayout layout2) {
            this.layout = layout2;
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            EditText editText = this.layout.getEditText();
            CharSequence text = editText != null ? editText.getText() : null;
            CharSequence hintText = this.layout.getHint();
            CharSequence errorText = this.layout.getError();
            CharSequence counterDesc = this.layout.getCounterOverflowDescription();
            boolean showingText = !TextUtils.isEmpty(text);
            boolean hasHint = !TextUtils.isEmpty(hintText);
            boolean showingError = !TextUtils.isEmpty(errorText);
            boolean z = false;
            boolean contentInvalid = showingError || !TextUtils.isEmpty(counterDesc);
            if (showingText) {
                info.setText(text);
            } else if (hasHint) {
                info.setText(hintText);
            }
            if (hasHint) {
                info.setHintText(hintText);
                if (!showingText && hasHint) {
                    z = true;
                }
                info.setShowingHintText(z);
            }
            if (contentInvalid) {
                info.setError(showingError ? errorText : counterDesc);
                info.setContentInvalid(true);
            }
        }

        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onPopulateAccessibilityEvent(host, event);
            EditText editText = this.layout.getEditText();
            CharSequence text = editText != null ? editText.getText() : null;
            CharSequence eventText = TextUtils.isEmpty(text) ? this.layout.getHint() : text;
            if (!TextUtils.isEmpty(eventText)) {
                event.getText().add(eventText);
            }
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface BoxBackgroundMode {
    }

    static class SavedState extends AbsSavedState {
        public static final Creator<SavedState> CREATOR = new ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        CharSequence error;
        boolean isPasswordToggledVisible;

        SavedState(Parcelable superState) {
            super(superState);
        }

        SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            this.error = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(source);
            boolean z = true;
            if (source.readInt() != 1) {
                z = false;
            }
            this.isPasswordToggledVisible = z;
        }

        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            TextUtils.writeToParcel(this.error, dest, flags);
            dest.writeInt(this.isPasswordToggledVisible ? 1 : 0);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("TextInputLayout.SavedState{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" error=");
            sb.append(this.error);
            sb.append("}");
            return sb.toString();
        }
    }

    public TextInputLayout(Context context) {
        this(context, null);
    }

    public TextInputLayout(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.textInputStyle);
    }

    public TextInputLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        Context context2 = context;
        super(context, attrs, defStyleAttr);
        this.indicatorViewController = new IndicatorViewController(this);
        this.tmpRect = new Rect();
        this.tmpRectF = new RectF();
        this.collapsingTextHelper = new CollapsingTextHelper(this);
        setOrientation(1);
        setWillNotDraw(false);
        setAddStatesFromChildren(true);
        FrameLayout frameLayout = new FrameLayout(context2);
        this.inputFrame = frameLayout;
        frameLayout.setAddStatesFromChildren(true);
        addView(this.inputFrame);
        this.collapsingTextHelper.setTextSizeInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        this.collapsingTextHelper.setPositionInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        this.collapsingTextHelper.setCollapsedTextGravity(8388659);
        TintTypedArray a = ThemeEnforcement.obtainTintedStyledAttributes(context, attrs, C0078R.styleable.TextInputLayout, defStyleAttr, C0078R.style.Widget_Design_TextInputLayout, new int[0]);
        this.hintEnabled = a.getBoolean(C0078R.styleable.TextInputLayout_hintEnabled, true);
        setHint(a.getText(C0078R.styleable.TextInputLayout_android_hint));
        this.hintAnimationEnabled = a.getBoolean(C0078R.styleable.TextInputLayout_hintAnimationEnabled, true);
        this.boxBottomOffsetPx = context.getResources().getDimensionPixelOffset(C0078R.dimen.mtrl_textinput_box_bottom_offset);
        this.boxLabelCutoutPaddingPx = context.getResources().getDimensionPixelOffset(C0078R.dimen.mtrl_textinput_box_label_cutout_padding);
        this.boxCollapsedPaddingTopPx = a.getDimensionPixelOffset(C0078R.styleable.TextInputLayout_boxCollapsedPaddingTop, 0);
        this.boxCornerRadiusTopStart = a.getDimension(C0078R.styleable.TextInputLayout_boxCornerRadiusTopStart, 0.0f);
        this.boxCornerRadiusTopEnd = a.getDimension(C0078R.styleable.TextInputLayout_boxCornerRadiusTopEnd, 0.0f);
        this.boxCornerRadiusBottomEnd = a.getDimension(C0078R.styleable.TextInputLayout_boxCornerRadiusBottomEnd, 0.0f);
        this.boxCornerRadiusBottomStart = a.getDimension(C0078R.styleable.TextInputLayout_boxCornerRadiusBottomStart, 0.0f);
        this.boxBackgroundColor = a.getColor(C0078R.styleable.TextInputLayout_boxBackgroundColor, 0);
        this.focusedStrokeColor = a.getColor(C0078R.styleable.TextInputLayout_boxStrokeColor, 0);
        this.boxStrokeWidthDefaultPx = context.getResources().getDimensionPixelSize(C0078R.dimen.mtrl_textinput_box_stroke_width_default);
        this.boxStrokeWidthFocusedPx = context.getResources().getDimensionPixelSize(C0078R.dimen.mtrl_textinput_box_stroke_width_focused);
        this.boxStrokeWidthPx = this.boxStrokeWidthDefaultPx;
        setBoxBackgroundMode(a.getInt(C0078R.styleable.TextInputLayout_boxBackgroundMode, 0));
        if (a.hasValue(C0078R.styleable.TextInputLayout_android_textColorHint)) {
            ColorStateList colorStateList = a.getColorStateList(C0078R.styleable.TextInputLayout_android_textColorHint);
            this.focusedTextColor = colorStateList;
            this.defaultHintTextColor = colorStateList;
        }
        this.defaultStrokeColor = ContextCompat.getColor(context2, C0078R.color.mtrl_textinput_default_box_stroke_color);
        this.disabledColor = ContextCompat.getColor(context2, C0078R.color.mtrl_textinput_disabled_color);
        this.hoveredStrokeColor = ContextCompat.getColor(context2, C0078R.color.mtrl_textinput_hovered_box_stroke_color);
        if (a.getResourceId(C0078R.styleable.TextInputLayout_hintTextAppearance, -1) != -1) {
            setHintTextAppearance(a.getResourceId(C0078R.styleable.TextInputLayout_hintTextAppearance, 0));
        }
        int errorTextAppearance = a.getResourceId(C0078R.styleable.TextInputLayout_errorTextAppearance, 0);
        boolean errorEnabled = a.getBoolean(C0078R.styleable.TextInputLayout_errorEnabled, false);
        int helperTextTextAppearance = a.getResourceId(C0078R.styleable.TextInputLayout_helperTextTextAppearance, 0);
        boolean helperTextEnabled = a.getBoolean(C0078R.styleable.TextInputLayout_helperTextEnabled, false);
        CharSequence helperText = a.getText(C0078R.styleable.TextInputLayout_helperText);
        boolean counterEnabled2 = a.getBoolean(C0078R.styleable.TextInputLayout_counterEnabled, false);
        setCounterMaxLength(a.getInt(C0078R.styleable.TextInputLayout_counterMaxLength, -1));
        this.counterTextAppearance = a.getResourceId(C0078R.styleable.TextInputLayout_counterTextAppearance, 0);
        this.counterOverflowTextAppearance = a.getResourceId(C0078R.styleable.TextInputLayout_counterOverflowTextAppearance, 0);
        this.passwordToggleEnabled = a.getBoolean(C0078R.styleable.TextInputLayout_passwordToggleEnabled, false);
        this.passwordToggleDrawable = a.getDrawable(C0078R.styleable.TextInputLayout_passwordToggleDrawable);
        this.passwordToggleContentDesc = a.getText(C0078R.styleable.TextInputLayout_passwordToggleContentDescription);
        if (a.hasValue(C0078R.styleable.TextInputLayout_passwordToggleTint)) {
            this.hasPasswordToggleTintList = true;
            this.passwordToggleTintList = a.getColorStateList(C0078R.styleable.TextInputLayout_passwordToggleTint);
        }
        if (a.hasValue(C0078R.styleable.TextInputLayout_passwordToggleTintMode)) {
            this.hasPasswordToggleTintMode = true;
            this.passwordToggleTintMode = ViewUtils.parseTintMode(a.getInt(C0078R.styleable.TextInputLayout_passwordToggleTintMode, -1), null);
        }
        a.recycle();
        setHelperTextEnabled(helperTextEnabled);
        setHelperText(helperText);
        setHelperTextTextAppearance(helperTextTextAppearance);
        setErrorEnabled(errorEnabled);
        setErrorTextAppearance(errorTextAppearance);
        setCounterEnabled(counterEnabled2);
        applyPasswordToggleTint();
        ViewCompat.setImportantForAccessibility(this, 2);
    }

    public void addView(View child, int index, LayoutParams params) {
        if (child instanceof EditText) {
            FrameLayout.LayoutParams flp = new FrameLayout.LayoutParams(params);
            flp.gravity = (flp.gravity & -113) | 16;
            this.inputFrame.addView(child, flp);
            this.inputFrame.setLayoutParams(params);
            updateInputLayoutMargins();
            setEditText((EditText) child);
            return;
        }
        super.addView(child, index, params);
    }

    private Drawable getBoxBackground() {
        int i = this.boxBackgroundMode;
        if (i == 1 || i == 2) {
            return this.boxBackground;
        }
        throw new IllegalStateException();
    }

    public void setBoxBackgroundMode(int boxBackgroundMode2) {
        if (boxBackgroundMode2 != this.boxBackgroundMode) {
            this.boxBackgroundMode = boxBackgroundMode2;
            onApplyBoxBackgroundMode();
        }
    }

    private void onApplyBoxBackgroundMode() {
        assignBoxBackgroundByMode();
        if (this.boxBackgroundMode != 0) {
            updateInputLayoutMargins();
        }
        updateTextInputBoxBounds();
    }

    private void assignBoxBackgroundByMode() {
        int i = this.boxBackgroundMode;
        if (i == 0) {
            this.boxBackground = null;
        } else if (i == 2 && this.hintEnabled && !(this.boxBackground instanceof CutoutDrawable)) {
            this.boxBackground = new CutoutDrawable();
        } else if (!(this.boxBackground instanceof GradientDrawable)) {
            this.boxBackground = new GradientDrawable();
        }
    }

    public void setBoxStrokeColor(int boxStrokeColor2) {
        if (this.focusedStrokeColor != boxStrokeColor2) {
            this.focusedStrokeColor = boxStrokeColor2;
            updateTextInputBoxState();
        }
    }

    public int getBoxStrokeColor() {
        return this.focusedStrokeColor;
    }

    public void setBoxBackgroundColorResource(int boxBackgroundColorId) {
        setBoxBackgroundColor(ContextCompat.getColor(getContext(), boxBackgroundColorId));
    }

    public void setBoxBackgroundColor(int boxBackgroundColor2) {
        if (this.boxBackgroundColor != boxBackgroundColor2) {
            this.boxBackgroundColor = boxBackgroundColor2;
            applyBoxAttributes();
        }
    }

    public int getBoxBackgroundColor() {
        return this.boxBackgroundColor;
    }

    public void setBoxCornerRadiiResources(int boxCornerRadiusTopStartId, int boxCornerRadiusTopEndId, int boxCornerRadiusBottomEndId, int boxCornerRadiusBottomStartId) {
        setBoxCornerRadii(getContext().getResources().getDimension(boxCornerRadiusTopStartId), getContext().getResources().getDimension(boxCornerRadiusTopEndId), getContext().getResources().getDimension(boxCornerRadiusBottomEndId), getContext().getResources().getDimension(boxCornerRadiusBottomStartId));
    }

    public void setBoxCornerRadii(float boxCornerRadiusTopStart2, float boxCornerRadiusTopEnd2, float boxCornerRadiusBottomStart2, float boxCornerRadiusBottomEnd2) {
        if (this.boxCornerRadiusTopStart != boxCornerRadiusTopStart2 || this.boxCornerRadiusTopEnd != boxCornerRadiusTopEnd2 || this.boxCornerRadiusBottomEnd != boxCornerRadiusBottomEnd2 || this.boxCornerRadiusBottomStart != boxCornerRadiusBottomStart2) {
            this.boxCornerRadiusTopStart = boxCornerRadiusTopStart2;
            this.boxCornerRadiusTopEnd = boxCornerRadiusTopEnd2;
            this.boxCornerRadiusBottomEnd = boxCornerRadiusBottomEnd2;
            this.boxCornerRadiusBottomStart = boxCornerRadiusBottomStart2;
            applyBoxAttributes();
        }
    }

    public float getBoxCornerRadiusTopStart() {
        return this.boxCornerRadiusTopStart;
    }

    public float getBoxCornerRadiusTopEnd() {
        return this.boxCornerRadiusTopEnd;
    }

    public float getBoxCornerRadiusBottomEnd() {
        return this.boxCornerRadiusBottomEnd;
    }

    public float getBoxCornerRadiusBottomStart() {
        return this.boxCornerRadiusBottomStart;
    }

    private float[] getCornerRadiiAsArray() {
        if (!ViewUtils.isLayoutRtl(this)) {
            float f = this.boxCornerRadiusTopStart;
            float f2 = this.boxCornerRadiusTopEnd;
            float f3 = this.boxCornerRadiusBottomEnd;
            float f4 = this.boxCornerRadiusBottomStart;
            return new float[]{f, f, f2, f2, f3, f3, f4, f4};
        }
        float f5 = this.boxCornerRadiusTopEnd;
        float f6 = this.boxCornerRadiusTopStart;
        float f7 = this.boxCornerRadiusBottomStart;
        float f8 = this.boxCornerRadiusBottomEnd;
        return new float[]{f5, f5, f6, f6, f7, f7, f8, f8};
    }

    public void setTypeface(Typeface typeface2) {
        if (typeface2 != this.typeface) {
            this.typeface = typeface2;
            this.collapsingTextHelper.setTypefaces(typeface2);
            this.indicatorViewController.setTypefaces(typeface2);
            TextView textView = this.counterView;
            if (textView != null) {
                textView.setTypeface(typeface2);
            }
        }
    }

    public Typeface getTypeface() {
        return this.typeface;
    }

    public void dispatchProvideAutofillStructure(ViewStructure structure, int flags) {
        if (this.originalHint != null) {
            EditText editText2 = this.editText;
            if (editText2 != null) {
                boolean wasProvidingHint = this.isProvidingHint;
                this.isProvidingHint = false;
                CharSequence hint2 = editText2.getHint();
                this.editText.setHint(this.originalHint);
                try {
                    super.dispatchProvideAutofillStructure(structure, flags);
                    return;
                } finally {
                    this.editText.setHint(hint2);
                    this.isProvidingHint = wasProvidingHint;
                }
            }
        }
        super.dispatchProvideAutofillStructure(structure, flags);
    }

    private void setEditText(EditText editText2) {
        if (this.editText == null) {
            if (!(editText2 instanceof TextInputEditText)) {
                Log.i(LOG_TAG, "EditText added is not a TextInputEditText. Please switch to using that class instead.");
            }
            this.editText = editText2;
            onApplyBoxBackgroundMode();
            setTextInputAccessibilityDelegate(new AccessibilityDelegate(this));
            if (!hasPasswordTransformation()) {
                this.collapsingTextHelper.setTypefaces(this.editText.getTypeface());
            }
            this.collapsingTextHelper.setExpandedTextSize(this.editText.getTextSize());
            int editTextGravity = this.editText.getGravity();
            this.collapsingTextHelper.setCollapsedTextGravity((editTextGravity & -113) | 48);
            this.collapsingTextHelper.setExpandedTextGravity(editTextGravity);
            this.editText.addTextChangedListener(new TextWatcher() {
                public void afterTextChanged(Editable s) {
                    TextInputLayout textInputLayout = TextInputLayout.this;
                    textInputLayout.updateLabelState(!textInputLayout.restoringSavedState);
                    if (TextInputLayout.this.counterEnabled) {
                        TextInputLayout.this.updateCounter(s.length());
                    }
                }

                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }
            });
            if (this.defaultHintTextColor == null) {
                this.defaultHintTextColor = this.editText.getHintTextColors();
            }
            if (this.hintEnabled) {
                if (TextUtils.isEmpty(this.hint)) {
                    CharSequence hint2 = this.editText.getHint();
                    this.originalHint = hint2;
                    setHint(hint2);
                    this.editText.setHint(null);
                }
                this.isProvidingHint = true;
            }
            if (this.counterView != null) {
                updateCounter(this.editText.getText().length());
            }
            this.indicatorViewController.adjustIndicatorPadding();
            updatePasswordToggleView();
            updateLabelState(false, true);
            return;
        }
        throw new IllegalArgumentException("We already have an EditText, can only have one");
    }

    private void updateInputLayoutMargins() {
        LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) this.inputFrame.getLayoutParams();
        int newTopMargin = calculateLabelMarginTop();
        if (newTopMargin != lp.topMargin) {
            lp.topMargin = newTopMargin;
            this.inputFrame.requestLayout();
        }
    }

    /* access modifiers changed from: 0000 */
    public void updateLabelState(boolean animate) {
        updateLabelState(animate, false);
    }

    private void updateLabelState(boolean animate, boolean force) {
        boolean isEnabled = isEnabled();
        EditText editText2 = this.editText;
        boolean hasFocus = true;
        boolean hasText = editText2 != null && !TextUtils.isEmpty(editText2.getText());
        EditText editText3 = this.editText;
        if (editText3 == null || !editText3.hasFocus()) {
            hasFocus = false;
        }
        boolean errorShouldBeShown = this.indicatorViewController.errorShouldBeShown();
        ColorStateList colorStateList = this.defaultHintTextColor;
        if (colorStateList != null) {
            this.collapsingTextHelper.setCollapsedTextColor(colorStateList);
            this.collapsingTextHelper.setExpandedTextColor(this.defaultHintTextColor);
        }
        if (!isEnabled) {
            this.collapsingTextHelper.setCollapsedTextColor(ColorStateList.valueOf(this.disabledColor));
            this.collapsingTextHelper.setExpandedTextColor(ColorStateList.valueOf(this.disabledColor));
        } else if (errorShouldBeShown) {
            this.collapsingTextHelper.setCollapsedTextColor(this.indicatorViewController.getErrorViewTextColors());
        } else {
            if (this.counterOverflowed) {
                TextView textView = this.counterView;
                if (textView != null) {
                    this.collapsingTextHelper.setCollapsedTextColor(textView.getTextColors());
                }
            }
            if (hasFocus) {
                ColorStateList colorStateList2 = this.focusedTextColor;
                if (colorStateList2 != null) {
                    this.collapsingTextHelper.setCollapsedTextColor(colorStateList2);
                }
            }
        }
        if (hasText || (isEnabled() && (hasFocus || errorShouldBeShown))) {
            if (force || this.hintExpanded) {
                collapseHint(animate);
            }
        } else if (force || !this.hintExpanded) {
            expandHint(animate);
        }
    }

    public EditText getEditText() {
        return this.editText;
    }

    public void setHint(CharSequence hint2) {
        if (this.hintEnabled) {
            setHintInternal(hint2);
            sendAccessibilityEvent(2048);
        }
    }

    private void setHintInternal(CharSequence hint2) {
        if (!TextUtils.equals(hint2, this.hint)) {
            this.hint = hint2;
            this.collapsingTextHelper.setText(hint2);
            if (!this.hintExpanded) {
                openCutout();
            }
        }
    }

    public CharSequence getHint() {
        if (this.hintEnabled) {
            return this.hint;
        }
        return null;
    }

    public void setHintEnabled(boolean enabled) {
        if (enabled != this.hintEnabled) {
            this.hintEnabled = enabled;
            if (!enabled) {
                this.isProvidingHint = false;
                if (!TextUtils.isEmpty(this.hint) && TextUtils.isEmpty(this.editText.getHint())) {
                    this.editText.setHint(this.hint);
                }
                setHintInternal(null);
            } else {
                CharSequence editTextHint = this.editText.getHint();
                if (!TextUtils.isEmpty(editTextHint)) {
                    if (TextUtils.isEmpty(this.hint)) {
                        setHint(editTextHint);
                    }
                    this.editText.setHint(null);
                }
                this.isProvidingHint = true;
            }
            if (this.editText != null) {
                updateInputLayoutMargins();
            }
        }
    }

    public boolean isHintEnabled() {
        return this.hintEnabled;
    }

    /* access modifiers changed from: 0000 */
    public boolean isProvidingHint() {
        return this.isProvidingHint;
    }

    public void setHintTextAppearance(int resId) {
        this.collapsingTextHelper.setCollapsedTextAppearance(resId);
        this.focusedTextColor = this.collapsingTextHelper.getCollapsedTextColor();
        if (this.editText != null) {
            updateLabelState(false);
            updateInputLayoutMargins();
        }
    }

    public void setDefaultHintTextColor(ColorStateList textColor) {
        this.defaultHintTextColor = textColor;
        this.focusedTextColor = textColor;
        if (this.editText != null) {
            updateLabelState(false);
        }
    }

    public ColorStateList getDefaultHintTextColor() {
        return this.defaultHintTextColor;
    }

    public void setErrorEnabled(boolean enabled) {
        this.indicatorViewController.setErrorEnabled(enabled);
    }

    public void setErrorTextAppearance(int resId) {
        this.indicatorViewController.setErrorTextAppearance(resId);
    }

    public void setErrorTextColor(ColorStateList textColors) {
        this.indicatorViewController.setErrorViewTextColor(textColors);
    }

    public int getErrorCurrentTextColors() {
        return this.indicatorViewController.getErrorViewCurrentTextColor();
    }

    public void setHelperTextTextAppearance(int resId) {
        this.indicatorViewController.setHelperTextAppearance(resId);
    }

    public boolean isErrorEnabled() {
        return this.indicatorViewController.isErrorEnabled();
    }

    public void setHelperTextEnabled(boolean enabled) {
        this.indicatorViewController.setHelperTextEnabled(enabled);
    }

    public void setHelperText(CharSequence helperText) {
        if (!TextUtils.isEmpty(helperText)) {
            if (!isHelperTextEnabled()) {
                setHelperTextEnabled(true);
            }
            this.indicatorViewController.showHelper(helperText);
        } else if (isHelperTextEnabled()) {
            setHelperTextEnabled(false);
        }
    }

    public boolean isHelperTextEnabled() {
        return this.indicatorViewController.isHelperTextEnabled();
    }

    public void setHelperTextColor(ColorStateList textColors) {
        this.indicatorViewController.setHelperTextViewTextColor(textColors);
    }

    public int getHelperTextCurrentTextColor() {
        return this.indicatorViewController.getHelperTextViewCurrentTextColor();
    }

    public void setError(CharSequence errorText) {
        if (!this.indicatorViewController.isErrorEnabled()) {
            if (!TextUtils.isEmpty(errorText)) {
                setErrorEnabled(true);
            } else {
                return;
            }
        }
        if (!TextUtils.isEmpty(errorText)) {
            this.indicatorViewController.showError(errorText);
        } else {
            this.indicatorViewController.hideError();
        }
    }

    public void setCounterEnabled(boolean enabled) {
        if (this.counterEnabled != enabled) {
            if (enabled) {
                AppCompatTextView appCompatTextView = new AppCompatTextView(getContext());
                this.counterView = appCompatTextView;
                appCompatTextView.setId(C0078R.C0080id.textinput_counter);
                Typeface typeface2 = this.typeface;
                if (typeface2 != null) {
                    this.counterView.setTypeface(typeface2);
                }
                this.counterView.setMaxLines(1);
                setTextAppearanceCompatWithErrorFallback(this.counterView, this.counterTextAppearance);
                this.indicatorViewController.addIndicator(this.counterView, 2);
                EditText editText2 = this.editText;
                if (editText2 == null) {
                    updateCounter(0);
                } else {
                    updateCounter(editText2.getText().length());
                }
            } else {
                this.indicatorViewController.removeIndicator(this.counterView, 2);
                this.counterView = null;
            }
            this.counterEnabled = enabled;
        }
    }

    public boolean isCounterEnabled() {
        return this.counterEnabled;
    }

    public void setCounterMaxLength(int maxLength) {
        if (this.counterMaxLength != maxLength) {
            if (maxLength > 0) {
                this.counterMaxLength = maxLength;
            } else {
                this.counterMaxLength = -1;
            }
            if (this.counterEnabled) {
                EditText editText2 = this.editText;
                updateCounter(editText2 == null ? 0 : editText2.getText().length());
            }
        }
    }

    public void setEnabled(boolean enabled) {
        recursiveSetEnabled(this, enabled);
        super.setEnabled(enabled);
    }

    private static void recursiveSetEnabled(ViewGroup vg, boolean enabled) {
        int count = vg.getChildCount();
        for (int i = 0; i < count; i++) {
            View child = vg.getChildAt(i);
            child.setEnabled(enabled);
            if (child instanceof ViewGroup) {
                recursiveSetEnabled((ViewGroup) child, enabled);
            }
        }
    }

    public int getCounterMaxLength() {
        return this.counterMaxLength;
    }

    /* access modifiers changed from: 0000 */
    public CharSequence getCounterOverflowDescription() {
        if (this.counterEnabled && this.counterOverflowed) {
            TextView textView = this.counterView;
            if (textView != null) {
                return textView.getContentDescription();
            }
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void updateCounter(int length) {
        boolean wasCounterOverflowed = this.counterOverflowed;
        if (this.counterMaxLength == -1) {
            this.counterView.setText(String.valueOf(length));
            this.counterView.setContentDescription(null);
            this.counterOverflowed = false;
        } else {
            if (ViewCompat.getAccessibilityLiveRegion(this.counterView) == 1) {
                ViewCompat.setAccessibilityLiveRegion(this.counterView, 0);
            }
            boolean z = length > this.counterMaxLength;
            this.counterOverflowed = z;
            if (wasCounterOverflowed != z) {
                setTextAppearanceCompatWithErrorFallback(this.counterView, z ? this.counterOverflowTextAppearance : this.counterTextAppearance);
                if (this.counterOverflowed) {
                    ViewCompat.setAccessibilityLiveRegion(this.counterView, 1);
                }
            }
            this.counterView.setText(getContext().getString(C0078R.string.character_counter_pattern, new Object[]{Integer.valueOf(length), Integer.valueOf(this.counterMaxLength)}));
            this.counterView.setContentDescription(getContext().getString(C0078R.string.character_counter_content_description, new Object[]{Integer.valueOf(length), Integer.valueOf(this.counterMaxLength)}));
        }
        if (this.editText != null && wasCounterOverflowed != this.counterOverflowed) {
            updateLabelState(false);
            updateTextInputBoxState();
            updateEditTextBackground();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setTextAppearanceCompatWithErrorFallback(TextView textView, int textAppearance) {
        boolean useDefaultColor = false;
        try {
            TextViewCompat.setTextAppearance(textView, textAppearance);
            if (VERSION.SDK_INT >= 23 && textView.getTextColors().getDefaultColor() == -65281) {
                useDefaultColor = true;
            }
        } catch (Exception e) {
            useDefaultColor = true;
        }
        if (useDefaultColor) {
            TextViewCompat.setTextAppearance(textView, C0078R.style.TextAppearance_AppCompat_Caption);
            textView.setTextColor(ContextCompat.getColor(getContext(), C0078R.color.design_error));
        }
    }

    private void updateTextInputBoxBounds() {
        if (this.boxBackgroundMode != 0 && this.boxBackground != null && this.editText != null && getRight() != 0) {
            int left = this.editText.getLeft();
            int top = calculateBoxBackgroundTop();
            int right = this.editText.getRight();
            int bottom = this.editText.getBottom() + this.boxBottomOffsetPx;
            if (this.boxBackgroundMode == 2) {
                int i = this.boxStrokeWidthFocusedPx;
                left += i / 2;
                top -= i / 2;
                right -= i / 2;
                bottom += i / 2;
            }
            this.boxBackground.setBounds(left, top, right, bottom);
            applyBoxAttributes();
            updateEditTextBackgroundBounds();
        }
    }

    private int calculateBoxBackgroundTop() {
        EditText editText2 = this.editText;
        if (editText2 == null) {
            return 0;
        }
        int i = this.boxBackgroundMode;
        if (i == 1) {
            return editText2.getTop();
        }
        if (i != 2) {
            return 0;
        }
        return editText2.getTop() + calculateLabelMarginTop();
    }

    private int calculateLabelMarginTop() {
        if (!this.hintEnabled) {
            return 0;
        }
        int i = this.boxBackgroundMode;
        if (i == 0 || i == 1) {
            return (int) this.collapsingTextHelper.getCollapsedTextHeight();
        }
        if (i != 2) {
            return 0;
        }
        return (int) (this.collapsingTextHelper.getCollapsedTextHeight() / 2.0f);
    }

    private int calculateCollapsedTextTopBounds() {
        int i = this.boxBackgroundMode;
        if (i == 1) {
            return getBoxBackground().getBounds().top + this.boxCollapsedPaddingTopPx;
        }
        if (i != 2) {
            return getPaddingTop();
        }
        return getBoxBackground().getBounds().top - calculateLabelMarginTop();
    }

    private void updateEditTextBackgroundBounds() {
        EditText editText2 = this.editText;
        if (editText2 != null) {
            Drawable editTextBackground = editText2.getBackground();
            if (editTextBackground != null) {
                if (DrawableUtils.canSafelyMutateDrawable(editTextBackground)) {
                    editTextBackground = editTextBackground.mutate();
                }
                DescendantOffsetUtils.getDescendantRect(this, this.editText, new Rect());
                Rect editTextBackgroundBounds = editTextBackground.getBounds();
                if (editTextBackgroundBounds.left != editTextBackgroundBounds.right) {
                    Rect editTextBackgroundPadding = new Rect();
                    editTextBackground.getPadding(editTextBackgroundPadding);
                    editTextBackground.setBounds(editTextBackgroundBounds.left - editTextBackgroundPadding.left, editTextBackgroundBounds.top, editTextBackgroundBounds.right + (editTextBackgroundPadding.right * 2), this.editText.getBottom());
                }
            }
        }
    }

    private void setBoxAttributes() {
        int i = this.boxBackgroundMode;
        if (i == 1) {
            this.boxStrokeWidthPx = 0;
        } else if (i == 2 && this.focusedStrokeColor == 0) {
            this.focusedStrokeColor = this.focusedTextColor.getColorForState(getDrawableState(), this.focusedTextColor.getDefaultColor());
        }
    }

    private void applyBoxAttributes() {
        if (this.boxBackground != null) {
            setBoxAttributes();
            EditText editText2 = this.editText;
            if (editText2 != null && this.boxBackgroundMode == 2) {
                if (editText2.getBackground() != null) {
                    this.editTextOriginalDrawable = this.editText.getBackground();
                }
                ViewCompat.setBackground(this.editText, null);
            }
            EditText editText3 = this.editText;
            if (editText3 != null && this.boxBackgroundMode == 1) {
                Drawable drawable = this.editTextOriginalDrawable;
                if (drawable != null) {
                    ViewCompat.setBackground(editText3, drawable);
                }
            }
            int i = this.boxStrokeWidthPx;
            if (i > -1) {
                int i2 = this.boxStrokeColor;
                if (i2 != 0) {
                    this.boxBackground.setStroke(i, i2);
                }
            }
            this.boxBackground.setCornerRadii(getCornerRadiiAsArray());
            this.boxBackground.setColor(this.boxBackgroundColor);
            invalidate();
        }
    }

    /* access modifiers changed from: 0000 */
    public void updateEditTextBackground() {
        EditText editText2 = this.editText;
        if (editText2 != null) {
            Drawable editTextBackground = editText2.getBackground();
            if (editTextBackground != null) {
                ensureBackgroundDrawableStateWorkaround();
                if (DrawableUtils.canSafelyMutateDrawable(editTextBackground)) {
                    editTextBackground = editTextBackground.mutate();
                }
                if (this.indicatorViewController.errorShouldBeShown()) {
                    editTextBackground.setColorFilter(AppCompatDrawableManager.getPorterDuffColorFilter(this.indicatorViewController.getErrorViewCurrentTextColor(), Mode.SRC_IN));
                } else {
                    if (this.counterOverflowed) {
                        TextView textView = this.counterView;
                        if (textView != null) {
                            editTextBackground.setColorFilter(AppCompatDrawableManager.getPorterDuffColorFilter(textView.getCurrentTextColor(), Mode.SRC_IN));
                        }
                    }
                    DrawableCompat.clearColorFilter(editTextBackground);
                    this.editText.refreshDrawableState();
                }
            }
        }
    }

    private void ensureBackgroundDrawableStateWorkaround() {
        int sdk = VERSION.SDK_INT;
        if (sdk == 21 || sdk == 22) {
            Drawable bg = this.editText.getBackground();
            if (bg != null && !this.hasReconstructedEditTextBackground) {
                Drawable newBg = bg.getConstantState().newDrawable();
                if (bg instanceof DrawableContainer) {
                    this.hasReconstructedEditTextBackground = com.google.android.material.internal.DrawableUtils.setContainerConstantState((DrawableContainer) bg, newBg.getConstantState());
                }
                if (!this.hasReconstructedEditTextBackground) {
                    ViewCompat.setBackground(this.editText, newBg);
                    this.hasReconstructedEditTextBackground = true;
                    onApplyBoxBackgroundMode();
                }
            }
        }
    }

    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        if (this.indicatorViewController.errorShouldBeShown()) {
            ss.error = getError();
        }
        ss.isPasswordToggledVisible = this.passwordToggledVisible;
        return ss;
    }

    /* access modifiers changed from: protected */
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        setError(ss.error);
        if (ss.isPasswordToggledVisible) {
            passwordVisibilityToggleRequested(true);
        }
        requestLayout();
    }

    /* access modifiers changed from: protected */
    public void dispatchRestoreInstanceState(SparseArray<Parcelable> container) {
        this.restoringSavedState = true;
        super.dispatchRestoreInstanceState(container);
        this.restoringSavedState = false;
    }

    public CharSequence getError() {
        if (this.indicatorViewController.isErrorEnabled()) {
            return this.indicatorViewController.getErrorText();
        }
        return null;
    }

    public CharSequence getHelperText() {
        if (this.indicatorViewController.isHelperTextEnabled()) {
            return this.indicatorViewController.getHelperText();
        }
        return null;
    }

    public boolean isHintAnimationEnabled() {
        return this.hintAnimationEnabled;
    }

    public void setHintAnimationEnabled(boolean enabled) {
        this.hintAnimationEnabled = enabled;
    }

    public void draw(Canvas canvas) {
        GradientDrawable gradientDrawable = this.boxBackground;
        if (gradientDrawable != null) {
            gradientDrawable.draw(canvas);
        }
        super.draw(canvas);
        if (this.hintEnabled) {
            this.collapsingTextHelper.draw(canvas);
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        updatePasswordToggleView();
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    private void updatePasswordToggleView() {
        if (this.editText != null) {
            if (shouldShowPasswordIcon()) {
                if (this.passwordToggleView == null) {
                    CheckableImageButton checkableImageButton = (CheckableImageButton) LayoutInflater.from(getContext()).inflate(C0078R.layout.design_text_input_password_icon, this.inputFrame, false);
                    this.passwordToggleView = checkableImageButton;
                    checkableImageButton.setImageDrawable(this.passwordToggleDrawable);
                    this.passwordToggleView.setContentDescription(this.passwordToggleContentDesc);
                    this.inputFrame.addView(this.passwordToggleView);
                    this.passwordToggleView.setOnClickListener(new OnClickListener() {
                        public void onClick(View view) {
                            TextInputLayout.this.passwordVisibilityToggleRequested(false);
                        }
                    });
                }
                EditText editText2 = this.editText;
                if (editText2 != null && ViewCompat.getMinimumHeight(editText2) <= 0) {
                    this.editText.setMinimumHeight(ViewCompat.getMinimumHeight(this.passwordToggleView));
                }
                this.passwordToggleView.setVisibility(0);
                this.passwordToggleView.setChecked(this.passwordToggledVisible);
                if (this.passwordToggleDummyDrawable == null) {
                    this.passwordToggleDummyDrawable = new ColorDrawable();
                }
                this.passwordToggleDummyDrawable.setBounds(0, 0, this.passwordToggleView.getMeasuredWidth(), 1);
                Drawable[] compounds = TextViewCompat.getCompoundDrawablesRelative(this.editText);
                if (compounds[2] != this.passwordToggleDummyDrawable) {
                    this.originalEditTextEndDrawable = compounds[2];
                }
                TextViewCompat.setCompoundDrawablesRelative(this.editText, compounds[0], compounds[1], this.passwordToggleDummyDrawable, compounds[3]);
                this.passwordToggleView.setPadding(this.editText.getPaddingLeft(), this.editText.getPaddingTop(), this.editText.getPaddingRight(), this.editText.getPaddingBottom());
            } else {
                CheckableImageButton checkableImageButton2 = this.passwordToggleView;
                if (checkableImageButton2 != null && checkableImageButton2.getVisibility() == 0) {
                    this.passwordToggleView.setVisibility(8);
                }
                if (this.passwordToggleDummyDrawable != null) {
                    Drawable[] compounds2 = TextViewCompat.getCompoundDrawablesRelative(this.editText);
                    if (compounds2[2] == this.passwordToggleDummyDrawable) {
                        TextViewCompat.setCompoundDrawablesRelative(this.editText, compounds2[0], compounds2[1], this.originalEditTextEndDrawable, compounds2[3]);
                        this.passwordToggleDummyDrawable = null;
                    }
                }
            }
        }
    }

    public void setPasswordVisibilityToggleDrawable(int resId) {
        setPasswordVisibilityToggleDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    public void setPasswordVisibilityToggleDrawable(Drawable icon) {
        this.passwordToggleDrawable = icon;
        CheckableImageButton checkableImageButton = this.passwordToggleView;
        if (checkableImageButton != null) {
            checkableImageButton.setImageDrawable(icon);
        }
    }

    public void setPasswordVisibilityToggleContentDescription(int resId) {
        setPasswordVisibilityToggleContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    public void setPasswordVisibilityToggleContentDescription(CharSequence description) {
        this.passwordToggleContentDesc = description;
        CheckableImageButton checkableImageButton = this.passwordToggleView;
        if (checkableImageButton != null) {
            checkableImageButton.setContentDescription(description);
        }
    }

    public Drawable getPasswordVisibilityToggleDrawable() {
        return this.passwordToggleDrawable;
    }

    public CharSequence getPasswordVisibilityToggleContentDescription() {
        return this.passwordToggleContentDesc;
    }

    public boolean isPasswordVisibilityToggleEnabled() {
        return this.passwordToggleEnabled;
    }

    public void setPasswordVisibilityToggleEnabled(boolean enabled) {
        if (this.passwordToggleEnabled != enabled) {
            this.passwordToggleEnabled = enabled;
            if (!enabled && this.passwordToggledVisible) {
                EditText editText2 = this.editText;
                if (editText2 != null) {
                    editText2.setTransformationMethod(PasswordTransformationMethod.getInstance());
                }
            }
            this.passwordToggledVisible = false;
            updatePasswordToggleView();
        }
    }

    public void setPasswordVisibilityToggleTintList(ColorStateList tintList) {
        this.passwordToggleTintList = tintList;
        this.hasPasswordToggleTintList = true;
        applyPasswordToggleTint();
    }

    public void setPasswordVisibilityToggleTintMode(Mode mode) {
        this.passwordToggleTintMode = mode;
        this.hasPasswordToggleTintMode = true;
        applyPasswordToggleTint();
    }

    public void passwordVisibilityToggleRequested(boolean shouldSkipAnimations) {
        if (this.passwordToggleEnabled) {
            int selection = this.editText.getSelectionEnd();
            if (hasPasswordTransformation()) {
                this.editText.setTransformationMethod(null);
                this.passwordToggledVisible = true;
            } else {
                this.editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
                this.passwordToggledVisible = false;
            }
            this.passwordToggleView.setChecked(this.passwordToggledVisible);
            if (shouldSkipAnimations) {
                this.passwordToggleView.jumpDrawablesToCurrentState();
            }
            this.editText.setSelection(selection);
        }
    }

    public void setTextInputAccessibilityDelegate(AccessibilityDelegate delegate) {
        EditText editText2 = this.editText;
        if (editText2 != null) {
            ViewCompat.setAccessibilityDelegate(editText2, delegate);
        }
    }

    private boolean hasPasswordTransformation() {
        EditText editText2 = this.editText;
        return editText2 != null && (editText2.getTransformationMethod() instanceof PasswordTransformationMethod);
    }

    private boolean shouldShowPasswordIcon() {
        return this.passwordToggleEnabled && (hasPasswordTransformation() || this.passwordToggledVisible);
    }

    private void applyPasswordToggleTint() {
        if (this.passwordToggleDrawable == null) {
            return;
        }
        if (this.hasPasswordToggleTintList || this.hasPasswordToggleTintMode) {
            Drawable mutate = DrawableCompat.wrap(this.passwordToggleDrawable).mutate();
            this.passwordToggleDrawable = mutate;
            if (this.hasPasswordToggleTintList) {
                DrawableCompat.setTintList(mutate, this.passwordToggleTintList);
            }
            if (this.hasPasswordToggleTintMode) {
                DrawableCompat.setTintMode(this.passwordToggleDrawable, this.passwordToggleTintMode);
            }
            CheckableImageButton checkableImageButton = this.passwordToggleView;
            if (checkableImageButton != null) {
                Drawable drawable = checkableImageButton.getDrawable();
                Drawable drawable2 = this.passwordToggleDrawable;
                if (drawable != drawable2) {
                    this.passwordToggleView.setImageDrawable(drawable2);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        if (this.boxBackground != null) {
            updateTextInputBoxBounds();
        }
        if (this.hintEnabled) {
            EditText editText2 = this.editText;
            if (editText2 != null) {
                Rect rect = this.tmpRect;
                DescendantOffsetUtils.getDescendantRect(this, editText2, rect);
                int l = rect.left + this.editText.getCompoundPaddingLeft();
                int r = rect.right - this.editText.getCompoundPaddingRight();
                int t = calculateCollapsedTextTopBounds();
                this.collapsingTextHelper.setExpandedBounds(l, rect.top + this.editText.getCompoundPaddingTop(), r, rect.bottom - this.editText.getCompoundPaddingBottom());
                this.collapsingTextHelper.setCollapsedBounds(l, t, r, (bottom - top) - getPaddingBottom());
                this.collapsingTextHelper.recalculate();
                if (cutoutEnabled() && !this.hintExpanded) {
                    openCutout();
                }
            }
        }
    }

    private void collapseHint(boolean animate) {
        ValueAnimator valueAnimator = this.animator;
        if (valueAnimator != null && valueAnimator.isRunning()) {
            this.animator.cancel();
        }
        if (!animate || !this.hintAnimationEnabled) {
            this.collapsingTextHelper.setExpansionFraction(1.0f);
        } else {
            animateToExpansionFraction(1.0f);
        }
        this.hintExpanded = false;
        if (cutoutEnabled()) {
            openCutout();
        }
    }

    private boolean cutoutEnabled() {
        return this.hintEnabled && !TextUtils.isEmpty(this.hint) && (this.boxBackground instanceof CutoutDrawable);
    }

    private void openCutout() {
        if (cutoutEnabled()) {
            RectF cutoutBounds = this.tmpRectF;
            this.collapsingTextHelper.getCollapsedTextActualBounds(cutoutBounds);
            applyCutoutPadding(cutoutBounds);
            ((CutoutDrawable) this.boxBackground).setCutout(cutoutBounds);
        }
    }

    private void closeCutout() {
        if (cutoutEnabled()) {
            ((CutoutDrawable) this.boxBackground).removeCutout();
        }
    }

    private void applyCutoutPadding(RectF cutoutBounds) {
        cutoutBounds.left -= (float) this.boxLabelCutoutPaddingPx;
        cutoutBounds.top -= (float) this.boxLabelCutoutPaddingPx;
        cutoutBounds.right += (float) this.boxLabelCutoutPaddingPx;
        cutoutBounds.bottom += (float) this.boxLabelCutoutPaddingPx;
    }

    /* access modifiers changed from: 0000 */
    public boolean cutoutIsOpen() {
        return cutoutEnabled() && ((CutoutDrawable) this.boxBackground).hasCutout();
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        if (!this.inDrawableStateChanged) {
            boolean z = true;
            this.inDrawableStateChanged = true;
            super.drawableStateChanged();
            int[] state = getDrawableState();
            boolean changed = false;
            if (!ViewCompat.isLaidOut(this) || !isEnabled()) {
                z = false;
            }
            updateLabelState(z);
            updateEditTextBackground();
            updateTextInputBoxBounds();
            updateTextInputBoxState();
            CollapsingTextHelper collapsingTextHelper2 = this.collapsingTextHelper;
            if (collapsingTextHelper2 != null) {
                changed = false | collapsingTextHelper2.setState(state);
            }
            if (changed) {
                invalidate();
            }
            this.inDrawableStateChanged = false;
        }
    }

    /* access modifiers changed from: 0000 */
    public void updateTextInputBoxState() {
        if (this.boxBackground != null && this.boxBackgroundMode != 0) {
            EditText editText2 = this.editText;
            boolean isHovered = true;
            boolean hasFocus = editText2 != null && editText2.hasFocus();
            EditText editText3 = this.editText;
            if (editText3 == null || !editText3.isHovered()) {
                isHovered = false;
            }
            if (this.boxBackgroundMode == 2) {
                if (!isEnabled()) {
                    this.boxStrokeColor = this.disabledColor;
                } else if (this.indicatorViewController.errorShouldBeShown()) {
                    this.boxStrokeColor = this.indicatorViewController.getErrorViewCurrentTextColor();
                } else {
                    if (this.counterOverflowed) {
                        TextView textView = this.counterView;
                        if (textView != null) {
                            this.boxStrokeColor = textView.getCurrentTextColor();
                        }
                    }
                    if (hasFocus) {
                        this.boxStrokeColor = this.focusedStrokeColor;
                    } else if (isHovered) {
                        this.boxStrokeColor = this.hoveredStrokeColor;
                    } else {
                        this.boxStrokeColor = this.defaultStrokeColor;
                    }
                }
                if ((isHovered || hasFocus) && isEnabled()) {
                    this.boxStrokeWidthPx = this.boxStrokeWidthFocusedPx;
                } else {
                    this.boxStrokeWidthPx = this.boxStrokeWidthDefaultPx;
                }
                applyBoxAttributes();
            }
        }
    }

    private void expandHint(boolean animate) {
        ValueAnimator valueAnimator = this.animator;
        if (valueAnimator != null && valueAnimator.isRunning()) {
            this.animator.cancel();
        }
        if (!animate || !this.hintAnimationEnabled) {
            this.collapsingTextHelper.setExpansionFraction(0.0f);
        } else {
            animateToExpansionFraction(0.0f);
        }
        if (cutoutEnabled() && ((CutoutDrawable) this.boxBackground).hasCutout()) {
            closeCutout();
        }
        this.hintExpanded = true;
    }

    /* access modifiers changed from: 0000 */
    public void animateToExpansionFraction(float target) {
        if (this.collapsingTextHelper.getExpansionFraction() != target) {
            if (this.animator == null) {
                ValueAnimator valueAnimator = new ValueAnimator();
                this.animator = valueAnimator;
                valueAnimator.setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
                this.animator.setDuration(167);
                this.animator.addUpdateListener(new AnimatorUpdateListener() {
                    public void onAnimationUpdate(ValueAnimator animator) {
                        TextInputLayout.this.collapsingTextHelper.setExpansionFraction(((Float) animator.getAnimatedValue()).floatValue());
                    }
                });
            }
            this.animator.setFloatValues(new float[]{this.collapsingTextHelper.getExpansionFraction(), target});
            this.animator.start();
        }
    }

    /* access modifiers changed from: 0000 */
    public final boolean isHintExpanded() {
        return this.hintExpanded;
    }

    /* access modifiers changed from: 0000 */
    public final boolean isHelperTextDisplayed() {
        return this.indicatorViewController.helperTextIsDisplayed();
    }

    /* access modifiers changed from: 0000 */
    public final int getHintCurrentCollapsedTextColor() {
        return this.collapsingTextHelper.getCurrentCollapsedTextColor();
    }

    /* access modifiers changed from: 0000 */
    public final float getHintCollapsedTextHeight() {
        return this.collapsingTextHelper.getCollapsedTextHeight();
    }

    /* access modifiers changed from: 0000 */
    public final int getErrorTextCurrentColor() {
        return this.indicatorViewController.getErrorViewCurrentTextColor();
    }
}
