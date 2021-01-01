package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build.VERSION;
import android.view.View;
import androidx.core.graphics.drawable.DrawableCompat;
import com.google.android.material.internal.CircularBorderDrawable;
import com.google.android.material.internal.CircularBorderDrawableLollipop;
import com.google.android.material.internal.VisibilityAwareImageButton;
import com.google.android.material.ripple.RippleUtils;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.google.android.material.shadow.ShadowViewDelegate;
import java.util.ArrayList;
import java.util.List;

class FloatingActionButtonImplLollipop extends FloatingActionButtonImpl {
    private InsetDrawable insetDrawable;

    static class AlwaysStatefulGradientDrawable extends GradientDrawable {
        AlwaysStatefulGradientDrawable() {
        }

        public boolean isStateful() {
            return true;
        }
    }

    FloatingActionButtonImplLollipop(VisibilityAwareImageButton view, ShadowViewDelegate shadowViewDelegate) {
        super(view, shadowViewDelegate);
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundDrawable(ColorStateList backgroundTint, Mode backgroundTintMode, ColorStateList rippleColor, int borderWidth) {
        Drawable rippleContent;
        this.shapeDrawable = DrawableCompat.wrap(createShapeDrawable());
        DrawableCompat.setTintList(this.shapeDrawable, backgroundTint);
        if (backgroundTintMode != null) {
            DrawableCompat.setTintMode(this.shapeDrawable, backgroundTintMode);
        }
        if (borderWidth > 0) {
            this.borderDrawable = createBorderDrawable(borderWidth, backgroundTint);
            rippleContent = new LayerDrawable(new Drawable[]{this.borderDrawable, this.shapeDrawable});
        } else {
            this.borderDrawable = null;
            rippleContent = this.shapeDrawable;
        }
        this.rippleDrawable = new RippleDrawable(RippleUtils.convertToRippleDrawableColor(rippleColor), rippleContent, null);
        this.contentBackground = this.rippleDrawable;
        this.shadowViewDelegate.setBackgroundDrawable(this.rippleDrawable);
    }

    /* access modifiers changed from: 0000 */
    public void setRippleColor(ColorStateList rippleColor) {
        if (this.rippleDrawable instanceof RippleDrawable) {
            ((RippleDrawable) this.rippleDrawable).setColor(RippleUtils.convertToRippleDrawableColor(rippleColor));
        } else {
            super.setRippleColor(rippleColor);
        }
    }

    /* access modifiers changed from: 0000 */
    public void onElevationsChanged(float elevation, float hoveredFocusedTranslationZ, float pressedTranslationZ) {
        if (VERSION.SDK_INT == 21) {
            this.view.refreshDrawableState();
        } else {
            StateListAnimator stateListAnimator = new StateListAnimator();
            stateListAnimator.addState(PRESSED_ENABLED_STATE_SET, createElevationAnimator(elevation, pressedTranslationZ));
            stateListAnimator.addState(HOVERED_FOCUSED_ENABLED_STATE_SET, createElevationAnimator(elevation, hoveredFocusedTranslationZ));
            stateListAnimator.addState(FOCUSED_ENABLED_STATE_SET, createElevationAnimator(elevation, hoveredFocusedTranslationZ));
            stateListAnimator.addState(HOVERED_ENABLED_STATE_SET, createElevationAnimator(elevation, hoveredFocusedTranslationZ));
            AnimatorSet set = new AnimatorSet();
            List<Animator> animators = new ArrayList<>();
            animators.add(ObjectAnimator.ofFloat(this.view, "elevation", new float[]{elevation}).setDuration(0));
            if (VERSION.SDK_INT >= 22 && VERSION.SDK_INT <= 24) {
                animators.add(ObjectAnimator.ofFloat(this.view, View.TRANSLATION_Z, new float[]{this.view.getTranslationZ()}).setDuration(100));
            }
            animators.add(ObjectAnimator.ofFloat(this.view, View.TRANSLATION_Z, new float[]{0.0f}).setDuration(100));
            set.playSequentially((Animator[]) animators.toArray(new Animator[0]));
            set.setInterpolator(ELEVATION_ANIM_INTERPOLATOR);
            stateListAnimator.addState(ENABLED_STATE_SET, set);
            stateListAnimator.addState(EMPTY_STATE_SET, createElevationAnimator(0.0f, 0.0f));
            this.view.setStateListAnimator(stateListAnimator);
        }
        if (this.shadowViewDelegate.isCompatPaddingEnabled()) {
            updatePadding();
        }
    }

    private Animator createElevationAnimator(float elevation, float translationZ) {
        AnimatorSet set = new AnimatorSet();
        set.play(ObjectAnimator.ofFloat(this.view, "elevation", new float[]{elevation}).setDuration(0)).with(ObjectAnimator.ofFloat(this.view, View.TRANSLATION_Z, new float[]{translationZ}).setDuration(100));
        set.setInterpolator(ELEVATION_ANIM_INTERPOLATOR);
        return set;
    }

    public float getElevation() {
        return this.view.getElevation();
    }

    /* access modifiers changed from: 0000 */
    public void onCompatShadowChanged() {
        updatePadding();
    }

    /* access modifiers changed from: 0000 */
    public void onPaddingUpdated(Rect padding) {
        if (this.shadowViewDelegate.isCompatPaddingEnabled()) {
            InsetDrawable insetDrawable2 = new InsetDrawable(this.rippleDrawable, padding.left, padding.top, padding.right, padding.bottom);
            this.insetDrawable = insetDrawable2;
            this.shadowViewDelegate.setBackgroundDrawable(this.insetDrawable);
            return;
        }
        this.shadowViewDelegate.setBackgroundDrawable(this.rippleDrawable);
    }

    /* access modifiers changed from: 0000 */
    public void onDrawableStateChanged(int[] state) {
        if (VERSION.SDK_INT != 21) {
            return;
        }
        if (this.view.isEnabled()) {
            this.view.setElevation(this.elevation);
            if (this.view.isPressed()) {
                this.view.setTranslationZ(this.pressedTranslationZ);
            } else if (this.view.isFocused() || this.view.isHovered()) {
                this.view.setTranslationZ(this.hoveredFocusedTranslationZ);
            } else {
                this.view.setTranslationZ(0.0f);
            }
        } else {
            this.view.setElevation(0.0f);
            this.view.setTranslationZ(0.0f);
        }
    }

    /* access modifiers changed from: 0000 */
    public void jumpDrawableToCurrentState() {
    }

    /* access modifiers changed from: 0000 */
    public boolean requirePreDrawListener() {
        return false;
    }

    /* access modifiers changed from: 0000 */
    public CircularBorderDrawable newCircularDrawable() {
        return new CircularBorderDrawableLollipop();
    }

    /* access modifiers changed from: 0000 */
    public GradientDrawable newGradientDrawableForShape() {
        return new AlwaysStatefulGradientDrawable();
    }

    /* access modifiers changed from: 0000 */
    public void getPadding(Rect rect) {
        if (this.shadowViewDelegate.isCompatPaddingEnabled()) {
            float radius = this.shadowViewDelegate.getRadius();
            float maxShadowSize = getElevation() + this.pressedTranslationZ;
            int hPadding = (int) Math.ceil((double) ShadowDrawableWrapper.calculateHorizontalPadding(maxShadowSize, radius, false));
            int vPadding = (int) Math.ceil((double) ShadowDrawableWrapper.calculateVerticalPadding(maxShadowSize, radius, false));
            rect.set(hPadding, vPadding, hPadding, vPadding);
            return;
        }
        rect.set(0, 0, 0, 0);
    }
}
