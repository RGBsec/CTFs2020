package com.google.android.material.textfield;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.core.view.ViewCompat;
import androidx.core.widget.TextViewCompat;
import androidx.legacy.widget.Space;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.animation.AnimatorSetCompat;
import java.util.ArrayList;
import java.util.List;

final class IndicatorViewController {
    private static final int CAPTION_OPACITY_FADE_ANIMATION_DURATION = 167;
    private static final int CAPTION_STATE_ERROR = 1;
    private static final int CAPTION_STATE_HELPER_TEXT = 2;
    private static final int CAPTION_STATE_NONE = 0;
    private static final int CAPTION_TRANSLATE_Y_ANIMATION_DURATION = 217;
    static final int COUNTER_INDEX = 2;
    static final int ERROR_INDEX = 0;
    static final int HELPER_INDEX = 1;
    /* access modifiers changed from: private */
    public Animator captionAnimator;
    private FrameLayout captionArea;
    /* access modifiers changed from: private */
    public int captionDisplayed;
    private int captionToShow;
    private final float captionTranslationYPx;
    private int captionViewsAdded;
    private final Context context;
    private boolean errorEnabled;
    private CharSequence errorText;
    private int errorTextAppearance;
    /* access modifiers changed from: private */
    public TextView errorView;
    private CharSequence helperText;
    private boolean helperTextEnabled;
    private int helperTextTextAppearance;
    private TextView helperTextView;
    private LinearLayout indicatorArea;
    private int indicatorsAdded;
    private final TextInputLayout textInputView;
    private Typeface typeface;

    public IndicatorViewController(TextInputLayout textInputView2) {
        Context context2 = textInputView2.getContext();
        this.context = context2;
        this.textInputView = textInputView2;
        this.captionTranslationYPx = (float) context2.getResources().getDimensionPixelSize(C0078R.dimen.design_textinput_caption_translate_y);
    }

    /* access modifiers changed from: 0000 */
    public void showHelper(CharSequence helperText2) {
        cancelCaptionAnimator();
        this.helperText = helperText2;
        this.helperTextView.setText(helperText2);
        if (this.captionDisplayed != 2) {
            this.captionToShow = 2;
        }
        updateCaptionViewsVisibility(this.captionDisplayed, this.captionToShow, shouldAnimateCaptionView(this.helperTextView, helperText2));
    }

    /* access modifiers changed from: 0000 */
    public void hideHelperText() {
        cancelCaptionAnimator();
        if (this.captionDisplayed == 2) {
            this.captionToShow = 0;
        }
        updateCaptionViewsVisibility(this.captionDisplayed, this.captionToShow, shouldAnimateCaptionView(this.helperTextView, null));
    }

    /* access modifiers changed from: 0000 */
    public void showError(CharSequence errorText2) {
        cancelCaptionAnimator();
        this.errorText = errorText2;
        this.errorView.setText(errorText2);
        if (this.captionDisplayed != 1) {
            this.captionToShow = 1;
        }
        updateCaptionViewsVisibility(this.captionDisplayed, this.captionToShow, shouldAnimateCaptionView(this.errorView, errorText2));
    }

    /* access modifiers changed from: 0000 */
    public void hideError() {
        this.errorText = null;
        cancelCaptionAnimator();
        if (this.captionDisplayed == 1) {
            if (!this.helperTextEnabled || TextUtils.isEmpty(this.helperText)) {
                this.captionToShow = 0;
            } else {
                this.captionToShow = 2;
            }
        }
        updateCaptionViewsVisibility(this.captionDisplayed, this.captionToShow, shouldAnimateCaptionView(this.errorView, null));
    }

    private boolean shouldAnimateCaptionView(TextView captionView, CharSequence captionText) {
        return ViewCompat.isLaidOut(this.textInputView) && this.textInputView.isEnabled() && (this.captionToShow != this.captionDisplayed || captionView == null || !TextUtils.equals(captionView.getText(), captionText));
    }

    private void updateCaptionViewsVisibility(int captionToHide, int captionToShow2, boolean animate) {
        boolean z = animate;
        if (z) {
            AnimatorSet captionAnimator2 = new AnimatorSet();
            this.captionAnimator = captionAnimator2;
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = arrayList;
            int i = captionToHide;
            int i2 = captionToShow2;
            createCaptionAnimators(arrayList2, this.helperTextEnabled, this.helperTextView, 2, i, i2);
            createCaptionAnimators(arrayList2, this.errorEnabled, this.errorView, 1, i, i2);
            AnimatorSetCompat.playTogether(captionAnimator2, arrayList);
            final int i3 = captionToShow2;
            final TextView captionViewFromDisplayState = getCaptionViewFromDisplayState(captionToHide);
            final int i4 = captionToHide;
            final TextView captionViewFromDisplayState2 = getCaptionViewFromDisplayState(captionToShow2);
            C04921 r0 = new AnimatorListenerAdapter() {
                public void onAnimationEnd(Animator animator) {
                    IndicatorViewController.this.captionDisplayed = i3;
                    IndicatorViewController.this.captionAnimator = null;
                    TextView textView = captionViewFromDisplayState;
                    if (textView != null) {
                        textView.setVisibility(4);
                        if (i4 == 1 && IndicatorViewController.this.errorView != null) {
                            IndicatorViewController.this.errorView.setText(null);
                        }
                    }
                }

                public void onAnimationStart(Animator animator) {
                    TextView textView = captionViewFromDisplayState2;
                    if (textView != null) {
                        textView.setVisibility(0);
                    }
                }
            };
            captionAnimator2.addListener(r0);
            captionAnimator2.start();
        } else {
            int i5 = captionToShow2;
            setCaptionViewVisibilities(captionToHide, captionToShow2);
        }
        this.textInputView.updateEditTextBackground();
        this.textInputView.updateLabelState(z);
        this.textInputView.updateTextInputBoxState();
    }

    private void setCaptionViewVisibilities(int captionToHide, int captionToShow2) {
        if (captionToHide != captionToShow2) {
            if (captionToShow2 != 0) {
                TextView captionViewToShow = getCaptionViewFromDisplayState(captionToShow2);
                if (captionViewToShow != null) {
                    captionViewToShow.setVisibility(0);
                    captionViewToShow.setAlpha(1.0f);
                }
            }
            if (captionToHide != 0) {
                TextView captionViewDisplayed = getCaptionViewFromDisplayState(captionToHide);
                if (captionViewDisplayed != null) {
                    captionViewDisplayed.setVisibility(4);
                    if (captionToHide == 1) {
                        captionViewDisplayed.setText(null);
                    }
                }
            }
            this.captionDisplayed = captionToShow2;
        }
    }

    private void createCaptionAnimators(List<Animator> captionAnimatorList, boolean captionEnabled, TextView captionView, int captionState, int captionToHide, int captionToShow2) {
        if (captionView != null && captionEnabled) {
            if (captionState == captionToShow2 || captionState == captionToHide) {
                captionAnimatorList.add(createCaptionOpacityAnimator(captionView, captionToShow2 == captionState));
                if (captionToShow2 == captionState) {
                    captionAnimatorList.add(createCaptionTranslationYAnimator(captionView));
                }
            }
        }
    }

    private ObjectAnimator createCaptionOpacityAnimator(TextView captionView, boolean display) {
        ObjectAnimator opacityAnimator = ObjectAnimator.ofFloat(captionView, View.ALPHA, new float[]{display ? 1.0f : 0.0f});
        opacityAnimator.setDuration(167);
        opacityAnimator.setInterpolator(AnimationUtils.LINEAR_INTERPOLATOR);
        return opacityAnimator;
    }

    private ObjectAnimator createCaptionTranslationYAnimator(TextView captionView) {
        ObjectAnimator translationYAnimator = ObjectAnimator.ofFloat(captionView, View.TRANSLATION_Y, new float[]{-this.captionTranslationYPx, 0.0f});
        translationYAnimator.setDuration(217);
        translationYAnimator.setInterpolator(AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR);
        return translationYAnimator;
    }

    /* access modifiers changed from: 0000 */
    public void cancelCaptionAnimator() {
        Animator animator = this.captionAnimator;
        if (animator != null) {
            animator.cancel();
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isCaptionView(int index) {
        return index == 0 || index == 1;
    }

    private TextView getCaptionViewFromDisplayState(int captionDisplayState) {
        if (captionDisplayState == 1) {
            return this.errorView;
        }
        if (captionDisplayState != 2) {
            return null;
        }
        return this.helperTextView;
    }

    /* access modifiers changed from: 0000 */
    public void adjustIndicatorPadding() {
        if (canAdjustIndicatorPadding()) {
            ViewCompat.setPaddingRelative(this.indicatorArea, ViewCompat.getPaddingStart(this.textInputView.getEditText()), 0, ViewCompat.getPaddingEnd(this.textInputView.getEditText()), 0);
        }
    }

    private boolean canAdjustIndicatorPadding() {
        return (this.indicatorArea == null || this.textInputView.getEditText() == null) ? false : true;
    }

    /* access modifiers changed from: 0000 */
    public void addIndicator(TextView indicator, int index) {
        if (this.indicatorArea == null && this.captionArea == null) {
            LinearLayout linearLayout = new LinearLayout(this.context);
            this.indicatorArea = linearLayout;
            linearLayout.setOrientation(0);
            this.textInputView.addView(this.indicatorArea, -1, -2);
            FrameLayout frameLayout = new FrameLayout(this.context);
            this.captionArea = frameLayout;
            this.indicatorArea.addView(frameLayout, -1, new LayoutParams(-2, -2));
            this.indicatorArea.addView(new Space(this.context), new LinearLayout.LayoutParams(0, 0, 1.0f));
            if (this.textInputView.getEditText() != null) {
                adjustIndicatorPadding();
            }
        }
        if (isCaptionView(index)) {
            this.captionArea.setVisibility(0);
            this.captionArea.addView(indicator);
            this.captionViewsAdded++;
        } else {
            this.indicatorArea.addView(indicator, index);
        }
        this.indicatorArea.setVisibility(0);
        this.indicatorsAdded++;
    }

    /* access modifiers changed from: 0000 */
    public void removeIndicator(TextView indicator, int index) {
        if (this.indicatorArea != null) {
            if (isCaptionView(index)) {
                FrameLayout frameLayout = this.captionArea;
                if (frameLayout != null) {
                    int i = this.captionViewsAdded - 1;
                    this.captionViewsAdded = i;
                    setViewGroupGoneIfEmpty(frameLayout, i);
                    this.captionArea.removeView(indicator);
                    int i2 = this.indicatorsAdded - 1;
                    this.indicatorsAdded = i2;
                    setViewGroupGoneIfEmpty(this.indicatorArea, i2);
                }
            }
            this.indicatorArea.removeView(indicator);
            int i22 = this.indicatorsAdded - 1;
            this.indicatorsAdded = i22;
            setViewGroupGoneIfEmpty(this.indicatorArea, i22);
        }
    }

    private void setViewGroupGoneIfEmpty(ViewGroup viewGroup, int indicatorsAdded2) {
        if (indicatorsAdded2 == 0) {
            viewGroup.setVisibility(8);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setErrorEnabled(boolean enabled) {
        if (this.errorEnabled != enabled) {
            cancelCaptionAnimator();
            if (enabled) {
                AppCompatTextView appCompatTextView = new AppCompatTextView(this.context);
                this.errorView = appCompatTextView;
                appCompatTextView.setId(C0078R.C0080id.textinput_error);
                Typeface typeface2 = this.typeface;
                if (typeface2 != null) {
                    this.errorView.setTypeface(typeface2);
                }
                setErrorTextAppearance(this.errorTextAppearance);
                this.errorView.setVisibility(4);
                ViewCompat.setAccessibilityLiveRegion(this.errorView, 1);
                addIndicator(this.errorView, 0);
            } else {
                hideError();
                removeIndicator(this.errorView, 0);
                this.errorView = null;
                this.textInputView.updateEditTextBackground();
                this.textInputView.updateTextInputBoxState();
            }
            this.errorEnabled = enabled;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isErrorEnabled() {
        return this.errorEnabled;
    }

    /* access modifiers changed from: 0000 */
    public boolean isHelperTextEnabled() {
        return this.helperTextEnabled;
    }

    /* access modifiers changed from: 0000 */
    public void setHelperTextEnabled(boolean enabled) {
        if (this.helperTextEnabled != enabled) {
            cancelCaptionAnimator();
            if (enabled) {
                AppCompatTextView appCompatTextView = new AppCompatTextView(this.context);
                this.helperTextView = appCompatTextView;
                appCompatTextView.setId(C0078R.C0080id.textinput_helper_text);
                Typeface typeface2 = this.typeface;
                if (typeface2 != null) {
                    this.helperTextView.setTypeface(typeface2);
                }
                this.helperTextView.setVisibility(4);
                ViewCompat.setAccessibilityLiveRegion(this.helperTextView, 1);
                setHelperTextAppearance(this.helperTextTextAppearance);
                addIndicator(this.helperTextView, 1);
            } else {
                hideHelperText();
                removeIndicator(this.helperTextView, 1);
                this.helperTextView = null;
                this.textInputView.updateEditTextBackground();
                this.textInputView.updateTextInputBoxState();
            }
            this.helperTextEnabled = enabled;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean errorIsDisplayed() {
        return isCaptionStateError(this.captionDisplayed);
    }

    /* access modifiers changed from: 0000 */
    public boolean errorShouldBeShown() {
        return isCaptionStateError(this.captionToShow);
    }

    private boolean isCaptionStateError(int captionState) {
        if (captionState != 1 || this.errorView == null || TextUtils.isEmpty(this.errorText)) {
            return false;
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    public boolean helperTextIsDisplayed() {
        return isCaptionStateHelperText(this.captionDisplayed);
    }

    /* access modifiers changed from: 0000 */
    public boolean helperTextShouldBeShown() {
        return isCaptionStateHelperText(this.captionToShow);
    }

    private boolean isCaptionStateHelperText(int captionState) {
        return captionState == 2 && this.helperTextView != null && !TextUtils.isEmpty(this.helperText);
    }

    /* access modifiers changed from: 0000 */
    public CharSequence getErrorText() {
        return this.errorText;
    }

    /* access modifiers changed from: 0000 */
    public CharSequence getHelperText() {
        return this.helperText;
    }

    /* access modifiers changed from: 0000 */
    public void setTypefaces(Typeface typeface2) {
        if (typeface2 != this.typeface) {
            this.typeface = typeface2;
            setTextViewTypeface(this.errorView, typeface2);
            setTextViewTypeface(this.helperTextView, typeface2);
        }
    }

    private void setTextViewTypeface(TextView captionView, Typeface typeface2) {
        if (captionView != null) {
            captionView.setTypeface(typeface2);
        }
    }

    /* access modifiers changed from: 0000 */
    public int getErrorViewCurrentTextColor() {
        TextView textView = this.errorView;
        if (textView != null) {
            return textView.getCurrentTextColor();
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getErrorViewTextColors() {
        TextView textView = this.errorView;
        if (textView != null) {
            return textView.getTextColors();
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void setErrorViewTextColor(ColorStateList textColors) {
        TextView textView = this.errorView;
        if (textView != null) {
            textView.setTextColor(textColors);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setErrorTextAppearance(int resId) {
        this.errorTextAppearance = resId;
        TextView textView = this.errorView;
        if (textView != null) {
            this.textInputView.setTextAppearanceCompatWithErrorFallback(textView, resId);
        }
    }

    /* access modifiers changed from: 0000 */
    public int getHelperTextViewCurrentTextColor() {
        TextView textView = this.helperTextView;
        if (textView != null) {
            return textView.getCurrentTextColor();
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getHelperTextViewColors() {
        TextView textView = this.helperTextView;
        if (textView != null) {
            return textView.getTextColors();
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void setHelperTextViewTextColor(ColorStateList textColors) {
        TextView textView = this.helperTextView;
        if (textView != null) {
            textView.setTextColor(textColors);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setHelperTextAppearance(int resId) {
        this.helperTextTextAppearance = resId;
        TextView textView = this.helperTextView;
        if (textView != null) {
            TextViewCompat.setTextAppearance(textView, resId);
        }
    }
}
