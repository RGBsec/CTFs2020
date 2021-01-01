package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.Animator.AnimatorListener;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Matrix;
import android.graphics.Matrix.ScaleToFit;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.os.Build.VERSION;
import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.animation.AnimatorSetCompat;
import com.google.android.material.animation.ImageMatrixProperty;
import com.google.android.material.animation.MatrixEvaluator;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.internal.CircularBorderDrawable;
import com.google.android.material.internal.StateListAnimator;
import com.google.android.material.internal.VisibilityAwareImageButton;
import com.google.android.material.ripple.RippleUtils;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.google.android.material.shadow.ShadowViewDelegate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

class FloatingActionButtonImpl {
    static final int ANIM_STATE_HIDING = 1;
    static final int ANIM_STATE_NONE = 0;
    static final int ANIM_STATE_SHOWING = 2;
    static final long ELEVATION_ANIM_DELAY = 100;
    static final long ELEVATION_ANIM_DURATION = 100;
    static final TimeInterpolator ELEVATION_ANIM_INTERPOLATOR = AnimationUtils.FAST_OUT_LINEAR_IN_INTERPOLATOR;
    static final int[] EMPTY_STATE_SET = new int[0];
    static final int[] ENABLED_STATE_SET = {16842910};
    static final int[] FOCUSED_ENABLED_STATE_SET = {16842908, 16842910};
    private static final float HIDE_ICON_SCALE = 0.0f;
    private static final float HIDE_OPACITY = 0.0f;
    private static final float HIDE_SCALE = 0.0f;
    static final int[] HOVERED_ENABLED_STATE_SET = {16843623, 16842910};
    static final int[] HOVERED_FOCUSED_ENABLED_STATE_SET = {16843623, 16842908, 16842910};
    static final int[] PRESSED_ENABLED_STATE_SET = {16842919, 16842910};
    private static final float SHOW_ICON_SCALE = 1.0f;
    private static final float SHOW_OPACITY = 1.0f;
    private static final float SHOW_SCALE = 1.0f;
    int animState = 0;
    CircularBorderDrawable borderDrawable;
    Drawable contentBackground;
    Animator currentAnimator;
    private MotionSpec defaultHideMotionSpec;
    private MotionSpec defaultShowMotionSpec;
    float elevation;
    private ArrayList<AnimatorListener> hideListeners;
    MotionSpec hideMotionSpec;
    float hoveredFocusedTranslationZ;
    float imageMatrixScale = 1.0f;
    int maxImageSize;
    private OnPreDrawListener preDrawListener;
    float pressedTranslationZ;
    Drawable rippleDrawable;
    private float rotation;
    ShadowDrawableWrapper shadowDrawable;
    final ShadowViewDelegate shadowViewDelegate;
    Drawable shapeDrawable;
    private ArrayList<AnimatorListener> showListeners;
    MotionSpec showMotionSpec;
    private final StateListAnimator stateListAnimator;
    private final Matrix tmpMatrix = new Matrix();
    private final Rect tmpRect = new Rect();
    private final RectF tmpRectF1 = new RectF();
    private final RectF tmpRectF2 = new RectF();
    final VisibilityAwareImageButton view;

    private class DisabledElevationAnimation extends ShadowAnimatorImpl {
        DisabledElevationAnimation() {
            super();
        }

        /* access modifiers changed from: protected */
        public float getTargetShadowSize() {
            return 0.0f;
        }
    }

    private class ElevateToHoveredFocusedTranslationZAnimation extends ShadowAnimatorImpl {
        ElevateToHoveredFocusedTranslationZAnimation() {
            super();
        }

        /* access modifiers changed from: protected */
        public float getTargetShadowSize() {
            return FloatingActionButtonImpl.this.elevation + FloatingActionButtonImpl.this.hoveredFocusedTranslationZ;
        }
    }

    private class ElevateToPressedTranslationZAnimation extends ShadowAnimatorImpl {
        ElevateToPressedTranslationZAnimation() {
            super();
        }

        /* access modifiers changed from: protected */
        public float getTargetShadowSize() {
            return FloatingActionButtonImpl.this.elevation + FloatingActionButtonImpl.this.pressedTranslationZ;
        }
    }

    interface InternalVisibilityChangedListener {
        void onHidden();

        void onShown();
    }

    private class ResetElevationAnimation extends ShadowAnimatorImpl {
        ResetElevationAnimation() {
            super();
        }

        /* access modifiers changed from: protected */
        public float getTargetShadowSize() {
            return FloatingActionButtonImpl.this.elevation;
        }
    }

    private abstract class ShadowAnimatorImpl extends AnimatorListenerAdapter implements AnimatorUpdateListener {
        private float shadowSizeEnd;
        private float shadowSizeStart;
        private boolean validValues;

        /* access modifiers changed from: protected */
        public abstract float getTargetShadowSize();

        private ShadowAnimatorImpl() {
        }

        public void onAnimationUpdate(ValueAnimator animator) {
            if (!this.validValues) {
                this.shadowSizeStart = FloatingActionButtonImpl.this.shadowDrawable.getShadowSize();
                this.shadowSizeEnd = getTargetShadowSize();
                this.validValues = true;
            }
            ShadowDrawableWrapper shadowDrawableWrapper = FloatingActionButtonImpl.this.shadowDrawable;
            float f = this.shadowSizeStart;
            shadowDrawableWrapper.setShadowSize(f + ((this.shadowSizeEnd - f) * animator.getAnimatedFraction()));
        }

        public void onAnimationEnd(Animator animator) {
            FloatingActionButtonImpl.this.shadowDrawable.setShadowSize(this.shadowSizeEnd);
            this.validValues = false;
        }
    }

    FloatingActionButtonImpl(VisibilityAwareImageButton view2, ShadowViewDelegate shadowViewDelegate2) {
        this.view = view2;
        this.shadowViewDelegate = shadowViewDelegate2;
        StateListAnimator stateListAnimator2 = new StateListAnimator();
        this.stateListAnimator = stateListAnimator2;
        stateListAnimator2.addState(PRESSED_ENABLED_STATE_SET, createElevationAnimator(new ElevateToPressedTranslationZAnimation()));
        this.stateListAnimator.addState(HOVERED_FOCUSED_ENABLED_STATE_SET, createElevationAnimator(new ElevateToHoveredFocusedTranslationZAnimation()));
        this.stateListAnimator.addState(FOCUSED_ENABLED_STATE_SET, createElevationAnimator(new ElevateToHoveredFocusedTranslationZAnimation()));
        this.stateListAnimator.addState(HOVERED_ENABLED_STATE_SET, createElevationAnimator(new ElevateToHoveredFocusedTranslationZAnimation()));
        this.stateListAnimator.addState(ENABLED_STATE_SET, createElevationAnimator(new ResetElevationAnimation()));
        this.stateListAnimator.addState(EMPTY_STATE_SET, createElevationAnimator(new DisabledElevationAnimation()));
        this.rotation = this.view.getRotation();
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundDrawable(ColorStateList backgroundTint, Mode backgroundTintMode, ColorStateList rippleColor, int borderWidth) {
        Drawable[] layers;
        Drawable wrap = DrawableCompat.wrap(createShapeDrawable());
        this.shapeDrawable = wrap;
        DrawableCompat.setTintList(wrap, backgroundTint);
        if (backgroundTintMode != null) {
            DrawableCompat.setTintMode(this.shapeDrawable, backgroundTintMode);
        }
        Drawable wrap2 = DrawableCompat.wrap(createShapeDrawable());
        this.rippleDrawable = wrap2;
        DrawableCompat.setTintList(wrap2, RippleUtils.convertToRippleDrawableColor(rippleColor));
        if (borderWidth > 0) {
            CircularBorderDrawable createBorderDrawable = createBorderDrawable(borderWidth, backgroundTint);
            this.borderDrawable = createBorderDrawable;
            layers = new Drawable[]{createBorderDrawable, this.shapeDrawable, this.rippleDrawable};
        } else {
            this.borderDrawable = null;
            layers = new Drawable[]{this.shapeDrawable, this.rippleDrawable};
        }
        this.contentBackground = new LayerDrawable(layers);
        Context context = this.view.getContext();
        Drawable drawable = this.contentBackground;
        float radius = this.shadowViewDelegate.getRadius();
        float f = this.elevation;
        ShadowDrawableWrapper shadowDrawableWrapper = new ShadowDrawableWrapper(context, drawable, radius, f, f + this.pressedTranslationZ);
        this.shadowDrawable = shadowDrawableWrapper;
        shadowDrawableWrapper.setAddPaddingForCorners(false);
        this.shadowViewDelegate.setBackgroundDrawable(this.shadowDrawable);
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundTintList(ColorStateList tint) {
        Drawable drawable = this.shapeDrawable;
        if (drawable != null) {
            DrawableCompat.setTintList(drawable, tint);
        }
        CircularBorderDrawable circularBorderDrawable = this.borderDrawable;
        if (circularBorderDrawable != null) {
            circularBorderDrawable.setBorderTint(tint);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setBackgroundTintMode(Mode tintMode) {
        Drawable drawable = this.shapeDrawable;
        if (drawable != null) {
            DrawableCompat.setTintMode(drawable, tintMode);
        }
    }

    /* access modifiers changed from: 0000 */
    public void setRippleColor(ColorStateList rippleColor) {
        Drawable drawable = this.rippleDrawable;
        if (drawable != null) {
            DrawableCompat.setTintList(drawable, RippleUtils.convertToRippleDrawableColor(rippleColor));
        }
    }

    /* access modifiers changed from: 0000 */
    public final void setElevation(float elevation2) {
        if (this.elevation != elevation2) {
            this.elevation = elevation2;
            onElevationsChanged(elevation2, this.hoveredFocusedTranslationZ, this.pressedTranslationZ);
        }
    }

    /* access modifiers changed from: 0000 */
    public float getElevation() {
        return this.elevation;
    }

    /* access modifiers changed from: 0000 */
    public float getHoveredFocusedTranslationZ() {
        return this.hoveredFocusedTranslationZ;
    }

    /* access modifiers changed from: 0000 */
    public float getPressedTranslationZ() {
        return this.pressedTranslationZ;
    }

    /* access modifiers changed from: 0000 */
    public final void setHoveredFocusedTranslationZ(float translationZ) {
        if (this.hoveredFocusedTranslationZ != translationZ) {
            this.hoveredFocusedTranslationZ = translationZ;
            onElevationsChanged(this.elevation, translationZ, this.pressedTranslationZ);
        }
    }

    /* access modifiers changed from: 0000 */
    public final void setPressedTranslationZ(float translationZ) {
        if (this.pressedTranslationZ != translationZ) {
            this.pressedTranslationZ = translationZ;
            onElevationsChanged(this.elevation, this.hoveredFocusedTranslationZ, translationZ);
        }
    }

    /* access modifiers changed from: 0000 */
    public final void setMaxImageSize(int maxImageSize2) {
        if (this.maxImageSize != maxImageSize2) {
            this.maxImageSize = maxImageSize2;
            updateImageMatrixScale();
        }
    }

    /* access modifiers changed from: 0000 */
    public final void updateImageMatrixScale() {
        setImageMatrixScale(this.imageMatrixScale);
    }

    /* access modifiers changed from: 0000 */
    public final void setImageMatrixScale(float scale) {
        this.imageMatrixScale = scale;
        Matrix matrix = this.tmpMatrix;
        calculateImageMatrixFromScale(scale, matrix);
        this.view.setImageMatrix(matrix);
    }

    private void calculateImageMatrixFromScale(float scale, Matrix matrix) {
        matrix.reset();
        Drawable drawable = this.view.getDrawable();
        if (drawable != null && this.maxImageSize != 0) {
            RectF drawableBounds = this.tmpRectF1;
            RectF imageBounds = this.tmpRectF2;
            drawableBounds.set(0.0f, 0.0f, (float) drawable.getIntrinsicWidth(), (float) drawable.getIntrinsicHeight());
            int i = this.maxImageSize;
            imageBounds.set(0.0f, 0.0f, (float) i, (float) i);
            matrix.setRectToRect(drawableBounds, imageBounds, ScaleToFit.CENTER);
            int i2 = this.maxImageSize;
            matrix.postScale(scale, scale, ((float) i2) / 2.0f, ((float) i2) / 2.0f);
        }
    }

    /* access modifiers changed from: 0000 */
    public final MotionSpec getShowMotionSpec() {
        return this.showMotionSpec;
    }

    /* access modifiers changed from: 0000 */
    public final void setShowMotionSpec(MotionSpec spec) {
        this.showMotionSpec = spec;
    }

    /* access modifiers changed from: 0000 */
    public final MotionSpec getHideMotionSpec() {
        return this.hideMotionSpec;
    }

    /* access modifiers changed from: 0000 */
    public final void setHideMotionSpec(MotionSpec spec) {
        this.hideMotionSpec = spec;
    }

    /* access modifiers changed from: 0000 */
    public void onElevationsChanged(float elevation2, float hoveredFocusedTranslationZ2, float pressedTranslationZ2) {
        ShadowDrawableWrapper shadowDrawableWrapper = this.shadowDrawable;
        if (shadowDrawableWrapper != null) {
            shadowDrawableWrapper.setShadowSize(elevation2, this.pressedTranslationZ + elevation2);
            updatePadding();
        }
    }

    /* access modifiers changed from: 0000 */
    public void onDrawableStateChanged(int[] state) {
        this.stateListAnimator.setState(state);
    }

    /* access modifiers changed from: 0000 */
    public void jumpDrawableToCurrentState() {
        this.stateListAnimator.jumpToCurrentState();
    }

    /* access modifiers changed from: 0000 */
    public void addOnShowAnimationListener(AnimatorListener listener) {
        if (this.showListeners == null) {
            this.showListeners = new ArrayList<>();
        }
        this.showListeners.add(listener);
    }

    /* access modifiers changed from: 0000 */
    public void removeOnShowAnimationListener(AnimatorListener listener) {
        ArrayList<AnimatorListener> arrayList = this.showListeners;
        if (arrayList != null) {
            arrayList.remove(listener);
        }
    }

    public void addOnHideAnimationListener(AnimatorListener listener) {
        if (this.hideListeners == null) {
            this.hideListeners = new ArrayList<>();
        }
        this.hideListeners.add(listener);
    }

    public void removeOnHideAnimationListener(AnimatorListener listener) {
        ArrayList<AnimatorListener> arrayList = this.hideListeners;
        if (arrayList != null) {
            arrayList.remove(listener);
        }
    }

    /* access modifiers changed from: 0000 */
    public void hide(final InternalVisibilityChangedListener listener, final boolean fromUser) {
        if (!isOrWillBeHidden()) {
            Animator animator = this.currentAnimator;
            if (animator != null) {
                animator.cancel();
            }
            if (shouldAnimateVisibilityChange()) {
                MotionSpec motionSpec = this.hideMotionSpec;
                if (motionSpec == null) {
                    motionSpec = getDefaultHideMotionSpec();
                }
                AnimatorSet set = createAnimator(motionSpec, 0.0f, 0.0f, 0.0f);
                set.addListener(new AnimatorListenerAdapter() {
                    private boolean cancelled;

                    public void onAnimationStart(Animator animation) {
                        FloatingActionButtonImpl.this.view.internalSetVisibility(0, fromUser);
                        FloatingActionButtonImpl.this.animState = 1;
                        FloatingActionButtonImpl.this.currentAnimator = animation;
                        this.cancelled = false;
                    }

                    public void onAnimationCancel(Animator animation) {
                        this.cancelled = true;
                    }

                    public void onAnimationEnd(Animator animation) {
                        FloatingActionButtonImpl.this.animState = 0;
                        FloatingActionButtonImpl.this.currentAnimator = null;
                        if (!this.cancelled) {
                            FloatingActionButtonImpl.this.view.internalSetVisibility(fromUser ? 8 : 4, fromUser);
                            InternalVisibilityChangedListener internalVisibilityChangedListener = listener;
                            if (internalVisibilityChangedListener != null) {
                                internalVisibilityChangedListener.onHidden();
                            }
                        }
                    }
                });
                ArrayList<AnimatorListener> arrayList = this.hideListeners;
                if (arrayList != null) {
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        set.addListener((AnimatorListener) it.next());
                    }
                }
                set.start();
            } else {
                this.view.internalSetVisibility(fromUser ? 8 : 4, fromUser);
                if (listener != null) {
                    listener.onHidden();
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void show(final InternalVisibilityChangedListener listener, final boolean fromUser) {
        if (!isOrWillBeShown()) {
            Animator animator = this.currentAnimator;
            if (animator != null) {
                animator.cancel();
            }
            if (shouldAnimateVisibilityChange()) {
                if (this.view.getVisibility() != 0) {
                    this.view.setAlpha(0.0f);
                    this.view.setScaleY(0.0f);
                    this.view.setScaleX(0.0f);
                    setImageMatrixScale(0.0f);
                }
                MotionSpec motionSpec = this.showMotionSpec;
                if (motionSpec == null) {
                    motionSpec = getDefaultShowMotionSpec();
                }
                AnimatorSet set = createAnimator(motionSpec, 1.0f, 1.0f, 1.0f);
                set.addListener(new AnimatorListenerAdapter() {
                    public void onAnimationStart(Animator animation) {
                        FloatingActionButtonImpl.this.view.internalSetVisibility(0, fromUser);
                        FloatingActionButtonImpl.this.animState = 2;
                        FloatingActionButtonImpl.this.currentAnimator = animation;
                    }

                    public void onAnimationEnd(Animator animation) {
                        FloatingActionButtonImpl.this.animState = 0;
                        FloatingActionButtonImpl.this.currentAnimator = null;
                        InternalVisibilityChangedListener internalVisibilityChangedListener = listener;
                        if (internalVisibilityChangedListener != null) {
                            internalVisibilityChangedListener.onShown();
                        }
                    }
                });
                ArrayList<AnimatorListener> arrayList = this.showListeners;
                if (arrayList != null) {
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        set.addListener((AnimatorListener) it.next());
                    }
                }
                set.start();
            } else {
                this.view.internalSetVisibility(0, fromUser);
                this.view.setAlpha(1.0f);
                this.view.setScaleY(1.0f);
                this.view.setScaleX(1.0f);
                setImageMatrixScale(1.0f);
                if (listener != null) {
                    listener.onShown();
                }
            }
        }
    }

    private MotionSpec getDefaultShowMotionSpec() {
        if (this.defaultShowMotionSpec == null) {
            this.defaultShowMotionSpec = MotionSpec.createFromResource(this.view.getContext(), C0078R.animator.design_fab_show_motion_spec);
        }
        return this.defaultShowMotionSpec;
    }

    private MotionSpec getDefaultHideMotionSpec() {
        if (this.defaultHideMotionSpec == null) {
            this.defaultHideMotionSpec = MotionSpec.createFromResource(this.view.getContext(), C0078R.animator.design_fab_hide_motion_spec);
        }
        return this.defaultHideMotionSpec;
    }

    private AnimatorSet createAnimator(MotionSpec spec, float opacity, float scale, float iconScale) {
        List<Animator> animators = new ArrayList<>();
        Animator animator = ObjectAnimator.ofFloat(this.view, View.ALPHA, new float[]{opacity});
        spec.getTiming("opacity").apply(animator);
        animators.add(animator);
        Animator animator2 = ObjectAnimator.ofFloat(this.view, View.SCALE_X, new float[]{scale});
        String str = "scale";
        spec.getTiming(str).apply(animator2);
        animators.add(animator2);
        Animator animator3 = ObjectAnimator.ofFloat(this.view, View.SCALE_Y, new float[]{scale});
        spec.getTiming(str).apply(animator3);
        animators.add(animator3);
        calculateImageMatrixFromScale(iconScale, this.tmpMatrix);
        Animator animator4 = ObjectAnimator.ofObject(this.view, new ImageMatrixProperty(), new MatrixEvaluator(), new Matrix[]{new Matrix(this.tmpMatrix)});
        spec.getTiming("iconScale").apply(animator4);
        animators.add(animator4);
        AnimatorSet set = new AnimatorSet();
        AnimatorSetCompat.playTogether(set, animators);
        return set;
    }

    /* access modifiers changed from: 0000 */
    public final Drawable getContentBackground() {
        return this.contentBackground;
    }

    /* access modifiers changed from: 0000 */
    public void onCompatShadowChanged() {
    }

    /* access modifiers changed from: 0000 */
    public final void updatePadding() {
        Rect rect = this.tmpRect;
        getPadding(rect);
        onPaddingUpdated(rect);
        this.shadowViewDelegate.setShadowPadding(rect.left, rect.top, rect.right, rect.bottom);
    }

    /* access modifiers changed from: 0000 */
    public void getPadding(Rect rect) {
        this.shadowDrawable.getPadding(rect);
    }

    /* access modifiers changed from: 0000 */
    public void onPaddingUpdated(Rect padding) {
    }

    /* access modifiers changed from: 0000 */
    public void onAttachedToWindow() {
        if (requirePreDrawListener()) {
            ensurePreDrawListener();
            this.view.getViewTreeObserver().addOnPreDrawListener(this.preDrawListener);
        }
    }

    /* access modifiers changed from: 0000 */
    public void onDetachedFromWindow() {
        if (this.preDrawListener != null) {
            this.view.getViewTreeObserver().removeOnPreDrawListener(this.preDrawListener);
            this.preDrawListener = null;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean requirePreDrawListener() {
        return true;
    }

    /* access modifiers changed from: 0000 */
    public CircularBorderDrawable createBorderDrawable(int borderWidth, ColorStateList backgroundTint) {
        Context context = this.view.getContext();
        CircularBorderDrawable borderDrawable2 = newCircularDrawable();
        borderDrawable2.setGradientColors(ContextCompat.getColor(context, C0078R.color.design_fab_stroke_top_outer_color), ContextCompat.getColor(context, C0078R.color.design_fab_stroke_top_inner_color), ContextCompat.getColor(context, C0078R.color.design_fab_stroke_end_inner_color), ContextCompat.getColor(context, C0078R.color.design_fab_stroke_end_outer_color));
        borderDrawable2.setBorderWidth((float) borderWidth);
        borderDrawable2.setBorderTint(backgroundTint);
        return borderDrawable2;
    }

    /* access modifiers changed from: 0000 */
    public CircularBorderDrawable newCircularDrawable() {
        return new CircularBorderDrawable();
    }

    /* access modifiers changed from: 0000 */
    public void onPreDraw() {
        float rotation2 = this.view.getRotation();
        if (this.rotation != rotation2) {
            this.rotation = rotation2;
            updateFromViewRotation();
        }
    }

    private void ensurePreDrawListener() {
        if (this.preDrawListener == null) {
            this.preDrawListener = new OnPreDrawListener() {
                public boolean onPreDraw() {
                    FloatingActionButtonImpl.this.onPreDraw();
                    return true;
                }
            };
        }
    }

    /* access modifiers changed from: 0000 */
    public GradientDrawable createShapeDrawable() {
        GradientDrawable d = newGradientDrawableForShape();
        d.setShape(1);
        d.setColor(-1);
        return d;
    }

    /* access modifiers changed from: 0000 */
    public GradientDrawable newGradientDrawableForShape() {
        return new GradientDrawable();
    }

    /* access modifiers changed from: 0000 */
    public boolean isOrWillBeShown() {
        boolean z = false;
        if (this.view.getVisibility() != 0) {
            if (this.animState == 2) {
                z = true;
            }
            return z;
        }
        if (this.animState != 1) {
            z = true;
        }
        return z;
    }

    /* access modifiers changed from: 0000 */
    public boolean isOrWillBeHidden() {
        boolean z = false;
        if (this.view.getVisibility() == 0) {
            if (this.animState == 1) {
                z = true;
            }
            return z;
        }
        if (this.animState != 2) {
            z = true;
        }
        return z;
    }

    private ValueAnimator createElevationAnimator(ShadowAnimatorImpl impl) {
        ValueAnimator animator = new ValueAnimator();
        animator.setInterpolator(ELEVATION_ANIM_INTERPOLATOR);
        animator.setDuration(100);
        animator.addListener(impl);
        animator.addUpdateListener(impl);
        animator.setFloatValues(new float[]{0.0f, 1.0f});
        return animator;
    }

    private boolean shouldAnimateVisibilityChange() {
        return ViewCompat.isLaidOut(this.view) && !this.view.isInEditMode();
    }

    private void updateFromViewRotation() {
        if (VERSION.SDK_INT == 19) {
            if (this.rotation % 90.0f != 0.0f) {
                if (this.view.getLayerType() != 1) {
                    this.view.setLayerType(1, null);
                }
            } else if (this.view.getLayerType() != 0) {
                this.view.setLayerType(0, null);
            }
        }
        ShadowDrawableWrapper shadowDrawableWrapper = this.shadowDrawable;
        if (shadowDrawableWrapper != null) {
            shadowDrawableWrapper.setRotation(-this.rotation);
        }
        CircularBorderDrawable circularBorderDrawable = this.borderDrawable;
        if (circularBorderDrawable != null) {
            circularBorderDrawable.setRotation(-this.rotation);
        }
    }
}
