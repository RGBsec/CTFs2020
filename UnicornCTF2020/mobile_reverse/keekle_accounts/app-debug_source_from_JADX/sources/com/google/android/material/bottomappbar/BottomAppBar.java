package com.google.android.material.bottomappbar;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Paint.Style;
import android.graphics.Rect;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.view.View;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.AttachedBehavior;
import androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.customview.view.AbsSavedState;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapePathModel;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.List;

public class BottomAppBar extends Toolbar implements AttachedBehavior {
    private static final long ANIMATION_DURATION = 300;
    public static final int FAB_ALIGNMENT_MODE_CENTER = 0;
    public static final int FAB_ALIGNMENT_MODE_END = 1;
    /* access modifiers changed from: private */
    public Animator attachAnimator;
    /* access modifiers changed from: private */
    public int fabAlignmentMode;
    AnimatorListenerAdapter fabAnimationListener;
    /* access modifiers changed from: private */
    public boolean fabAttached;
    private final int fabOffsetEndMode;
    private boolean hideOnScroll;
    /* access modifiers changed from: private */
    public final MaterialShapeDrawable materialShapeDrawable;
    /* access modifiers changed from: private */
    public Animator menuAnimator;
    /* access modifiers changed from: private */
    public Animator modeAnimator;
    /* access modifiers changed from: private */
    public final BottomAppBarTopEdgeTreatment topEdgeTreatment;

    public static class Behavior extends HideBottomViewOnScrollBehavior<BottomAppBar> {
        private final Rect fabContentRect = new Rect();

        public Behavior() {
        }

        public Behavior(Context context, AttributeSet attrs) {
            super(context, attrs);
        }

        private boolean updateFabPositionAndVisibility(FloatingActionButton fab, BottomAppBar child) {
            ((LayoutParams) fab.getLayoutParams()).anchorGravity = 17;
            child.addFabAnimationListeners(fab);
            return true;
        }

        public boolean onLayoutChild(CoordinatorLayout parent, BottomAppBar child, int layoutDirection) {
            FloatingActionButton fab = child.findDependentFab();
            if (fab != null) {
                updateFabPositionAndVisibility(fab, child);
                fab.getMeasuredContentRect(this.fabContentRect);
                child.setFabDiameter(this.fabContentRect.height());
            }
            if (!child.isAnimationRunning()) {
                child.setCutoutState();
            }
            parent.onLayoutChild(child, layoutDirection);
            return super.onLayoutChild(parent, child, layoutDirection);
        }

        public boolean onStartNestedScroll(CoordinatorLayout coordinatorLayout, BottomAppBar child, View directTargetChild, View target, int axes, int type) {
            return child.getHideOnScroll() && super.onStartNestedScroll(coordinatorLayout, child, directTargetChild, target, axes, type);
        }

        /* access modifiers changed from: protected */
        public void slideUp(BottomAppBar child) {
            super.slideUp(child);
            FloatingActionButton fab = child.findDependentFab();
            if (fab != null) {
                fab.clearAnimation();
                fab.animate().translationY(child.getFabTranslationY()).setInterpolator(AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR).setDuration(225);
            }
        }

        /* access modifiers changed from: protected */
        public void slideDown(BottomAppBar child) {
            super.slideDown(child);
            FloatingActionButton fab = child.findDependentFab();
            if (fab != null) {
                fab.getContentRect(this.fabContentRect);
                float fabShadowPadding = (float) (fab.getMeasuredHeight() - this.fabContentRect.height());
                fab.clearAnimation();
                fab.animate().translationY(((float) (-fab.getPaddingBottom())) + fabShadowPadding).setInterpolator(AnimationUtils.FAST_OUT_LINEAR_IN_INTERPOLATOR).setDuration(175);
            }
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface FabAlignmentMode {
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
        int fabAlignmentMode;
        boolean fabAttached;

        public SavedState(Parcelable superState) {
            super(superState);
        }

        public SavedState(Parcel in, ClassLoader loader) {
            super(in, loader);
            this.fabAlignmentMode = in.readInt();
            this.fabAttached = in.readInt() != 0;
        }

        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.fabAlignmentMode);
            out.writeInt(this.fabAttached ? 1 : 0);
        }
    }

    public BottomAppBar(Context context) {
        this(context, null, 0);
    }

    public BottomAppBar(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.bottomAppBarStyle);
    }

    public BottomAppBar(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.fabAttached = true;
        this.fabAnimationListener = new AnimatorListenerAdapter() {
            public void onAnimationStart(Animator animation) {
                BottomAppBar bottomAppBar = BottomAppBar.this;
                bottomAppBar.maybeAnimateAttachChange(bottomAppBar.fabAttached);
                BottomAppBar bottomAppBar2 = BottomAppBar.this;
                bottomAppBar2.maybeAnimateMenuView(bottomAppBar2.fabAlignmentMode, BottomAppBar.this.fabAttached);
            }
        };
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(context, attrs, C0078R.styleable.BottomAppBar, defStyleAttr, C0078R.style.Widget_MaterialComponents_BottomAppBar, new int[0]);
        ColorStateList backgroundTint = MaterialResources.getColorStateList(context, a, C0078R.styleable.BottomAppBar_backgroundTint);
        float fabCradleMargin = (float) a.getDimensionPixelOffset(C0078R.styleable.BottomAppBar_fabCradleMargin, 0);
        float fabCornerRadius = (float) a.getDimensionPixelOffset(C0078R.styleable.BottomAppBar_fabCradleRoundedCornerRadius, 0);
        float fabVerticalOffset = (float) a.getDimensionPixelOffset(C0078R.styleable.BottomAppBar_fabCradleVerticalOffset, 0);
        this.fabAlignmentMode = a.getInt(C0078R.styleable.BottomAppBar_fabAlignmentMode, 0);
        this.hideOnScroll = a.getBoolean(C0078R.styleable.BottomAppBar_hideOnScroll, false);
        a.recycle();
        this.fabOffsetEndMode = getResources().getDimensionPixelOffset(C0078R.dimen.mtrl_bottomappbar_fabOffsetEndMode);
        this.topEdgeTreatment = new BottomAppBarTopEdgeTreatment(fabCradleMargin, fabCornerRadius, fabVerticalOffset);
        ShapePathModel appBarModel = new ShapePathModel();
        appBarModel.setTopEdge(this.topEdgeTreatment);
        MaterialShapeDrawable materialShapeDrawable2 = new MaterialShapeDrawable(appBarModel);
        this.materialShapeDrawable = materialShapeDrawable2;
        materialShapeDrawable2.setShadowEnabled(true);
        this.materialShapeDrawable.setPaintStyle(Style.FILL);
        DrawableCompat.setTintList(this.materialShapeDrawable, backgroundTint);
        ViewCompat.setBackground(this, this.materialShapeDrawable);
    }

    public int getFabAlignmentMode() {
        return this.fabAlignmentMode;
    }

    public void setFabAlignmentMode(int fabAlignmentMode2) {
        maybeAnimateModeChange(fabAlignmentMode2);
        maybeAnimateMenuView(fabAlignmentMode2, this.fabAttached);
        this.fabAlignmentMode = fabAlignmentMode2;
    }

    public void setBackgroundTint(ColorStateList backgroundTint) {
        DrawableCompat.setTintList(this.materialShapeDrawable, backgroundTint);
    }

    public ColorStateList getBackgroundTint() {
        return this.materialShapeDrawable.getTintList();
    }

    public float getFabCradleMargin() {
        return this.topEdgeTreatment.getFabCradleMargin();
    }

    public void setFabCradleMargin(float cradleMargin) {
        if (cradleMargin != getFabCradleMargin()) {
            this.topEdgeTreatment.setFabCradleMargin(cradleMargin);
            this.materialShapeDrawable.invalidateSelf();
        }
    }

    public float getFabCradleRoundedCornerRadius() {
        return this.topEdgeTreatment.getFabCradleRoundedCornerRadius();
    }

    public void setFabCradleRoundedCornerRadius(float roundedCornerRadius) {
        if (roundedCornerRadius != getFabCradleRoundedCornerRadius()) {
            this.topEdgeTreatment.setFabCradleRoundedCornerRadius(roundedCornerRadius);
            this.materialShapeDrawable.invalidateSelf();
        }
    }

    public float getCradleVerticalOffset() {
        return this.topEdgeTreatment.getCradleVerticalOffset();
    }

    public void setCradleVerticalOffset(float verticalOffset) {
        if (verticalOffset != getCradleVerticalOffset()) {
            this.topEdgeTreatment.setCradleVerticalOffset(verticalOffset);
            this.materialShapeDrawable.invalidateSelf();
        }
    }

    public boolean getHideOnScroll() {
        return this.hideOnScroll;
    }

    public void setHideOnScroll(boolean hide) {
        this.hideOnScroll = hide;
    }

    public void replaceMenu(int newMenu) {
        getMenu().clear();
        inflateMenu(newMenu);
    }

    /* access modifiers changed from: 0000 */
    public void setFabDiameter(int diameter) {
        if (((float) diameter) != this.topEdgeTreatment.getFabDiameter()) {
            this.topEdgeTreatment.setFabDiameter((float) diameter);
            this.materialShapeDrawable.invalidateSelf();
        }
    }

    private void maybeAnimateModeChange(int targetMode) {
        if (this.fabAlignmentMode != targetMode && ViewCompat.isLaidOut(this)) {
            Animator animator = this.modeAnimator;
            if (animator != null) {
                animator.cancel();
            }
            List<Animator> animators = new ArrayList<>();
            createCradleTranslationAnimation(targetMode, animators);
            createFabTranslationXAnimation(targetMode, animators);
            AnimatorSet set = new AnimatorSet();
            set.playTogether(animators);
            this.modeAnimator = set;
            set.addListener(new AnimatorListenerAdapter() {
                public void onAnimationEnd(Animator animation) {
                    BottomAppBar.this.modeAnimator = null;
                }
            });
            this.modeAnimator.start();
        }
    }

    private void createCradleTranslationAnimation(int targetMode, List<Animator> animators) {
        if (this.fabAttached) {
            ValueAnimator animator = ValueAnimator.ofFloat(new float[]{this.topEdgeTreatment.getHorizontalOffset(), (float) getFabTranslationX(targetMode)});
            animator.addUpdateListener(new AnimatorUpdateListener() {
                public void onAnimationUpdate(ValueAnimator animation) {
                    BottomAppBar.this.topEdgeTreatment.setHorizontalOffset(((Float) animation.getAnimatedValue()).floatValue());
                    BottomAppBar.this.materialShapeDrawable.invalidateSelf();
                }
            });
            animator.setDuration(ANIMATION_DURATION);
            animators.add(animator);
        }
    }

    /* access modifiers changed from: private */
    public FloatingActionButton findDependentFab() {
        if (!(getParent() instanceof CoordinatorLayout)) {
            return null;
        }
        for (View v : ((CoordinatorLayout) getParent()).getDependents(this)) {
            if (v instanceof FloatingActionButton) {
                return (FloatingActionButton) v;
            }
        }
        return null;
    }

    private boolean isVisibleFab() {
        FloatingActionButton fab = findDependentFab();
        return fab != null && fab.isOrWillBeShown();
    }

    private void createFabTranslationXAnimation(int targetMode, List<Animator> animators) {
        ObjectAnimator animator = ObjectAnimator.ofFloat(findDependentFab(), "translationX", new float[]{(float) getFabTranslationX(targetMode)});
        animator.setDuration(ANIMATION_DURATION);
        animators.add(animator);
    }

    /* access modifiers changed from: private */
    public void maybeAnimateMenuView(int targetMode, boolean newFabAttached) {
        if (ViewCompat.isLaidOut(this)) {
            Animator animator = this.menuAnimator;
            if (animator != null) {
                animator.cancel();
            }
            List<Animator> animators = new ArrayList<>();
            if (!isVisibleFab()) {
                targetMode = 0;
                newFabAttached = false;
            }
            createMenuViewTranslationAnimation(targetMode, newFabAttached, animators);
            AnimatorSet set = new AnimatorSet();
            set.playTogether(animators);
            this.menuAnimator = set;
            set.addListener(new AnimatorListenerAdapter() {
                public void onAnimationEnd(Animator animation) {
                    BottomAppBar.this.menuAnimator = null;
                }
            });
            this.menuAnimator.start();
        }
    }

    private void createMenuViewTranslationAnimation(final int targetMode, final boolean targetAttached, List<Animator> animators) {
        final ActionMenuView actionMenuView = getActionMenuView();
        if (actionMenuView != null) {
            String str = "alpha";
            Animator fadeIn = ObjectAnimator.ofFloat(actionMenuView, str, new float[]{1.0f});
            if ((this.fabAttached || (targetAttached && isVisibleFab())) && (this.fabAlignmentMode == 1 || targetMode == 1)) {
                Animator fadeOut = ObjectAnimator.ofFloat(actionMenuView, str, new float[]{0.0f});
                fadeOut.addListener(new AnimatorListenerAdapter() {
                    public boolean cancelled;

                    public void onAnimationCancel(Animator animation) {
                        this.cancelled = true;
                    }

                    public void onAnimationEnd(Animator animation) {
                        if (!this.cancelled) {
                            BottomAppBar.this.translateActionMenuView(actionMenuView, targetMode, targetAttached);
                        }
                    }
                });
                AnimatorSet set = new AnimatorSet();
                set.setDuration(150);
                set.playSequentially(new Animator[]{fadeOut, fadeIn});
                animators.add(set);
            } else if (actionMenuView.getAlpha() < 1.0f) {
                animators.add(fadeIn);
            }
        }
    }

    /* access modifiers changed from: private */
    public void maybeAnimateAttachChange(boolean targetAttached) {
        if (ViewCompat.isLaidOut(this)) {
            Animator animator = this.attachAnimator;
            if (animator != null) {
                animator.cancel();
            }
            List<Animator> animators = new ArrayList<>();
            createCradleShapeAnimation(targetAttached && isVisibleFab(), animators);
            createFabTranslationYAnimation(targetAttached, animators);
            AnimatorSet set = new AnimatorSet();
            set.playTogether(animators);
            this.attachAnimator = set;
            set.addListener(new AnimatorListenerAdapter() {
                public void onAnimationEnd(Animator animation) {
                    BottomAppBar.this.attachAnimator = null;
                }
            });
            this.attachAnimator.start();
        }
    }

    private void createCradleShapeAnimation(boolean showCradle, List<Animator> animators) {
        if (showCradle) {
            this.topEdgeTreatment.setHorizontalOffset(getFabTranslationX());
        }
        float[] fArr = new float[2];
        fArr[0] = this.materialShapeDrawable.getInterpolation();
        fArr[1] = showCradle ? 1.0f : 0.0f;
        ValueAnimator animator = ValueAnimator.ofFloat(fArr);
        animator.addUpdateListener(new AnimatorUpdateListener() {
            public void onAnimationUpdate(ValueAnimator animation) {
                BottomAppBar.this.materialShapeDrawable.setInterpolation(((Float) animation.getAnimatedValue()).floatValue());
            }
        });
        animator.setDuration(ANIMATION_DURATION);
        animators.add(animator);
    }

    private void createFabTranslationYAnimation(boolean targetAttached, List<Animator> animators) {
        FloatingActionButton fab = findDependentFab();
        if (fab != null) {
            ObjectAnimator animator = ObjectAnimator.ofFloat(fab, "translationY", new float[]{getFabTranslationY(targetAttached)});
            animator.setDuration(ANIMATION_DURATION);
            animators.add(animator);
        }
    }

    private float getFabTranslationY(boolean targetAttached) {
        FloatingActionButton fab = findDependentFab();
        if (fab == null) {
            return 0.0f;
        }
        Rect fabContentRect = new Rect();
        fab.getContentRect(fabContentRect);
        float fabHeight = (float) fabContentRect.height();
        if (fabHeight == 0.0f) {
            fabHeight = (float) fab.getMeasuredHeight();
        }
        return ((float) (-getMeasuredHeight())) + (targetAttached ? (-getCradleVerticalOffset()) + (fabHeight / 2.0f) + ((float) (fab.getHeight() - fabContentRect.bottom)) : ((float) (fab.getHeight() - fabContentRect.height())) - ((float) fab.getPaddingBottom()));
    }

    /* access modifiers changed from: private */
    public float getFabTranslationY() {
        return getFabTranslationY(this.fabAttached);
    }

    private int getFabTranslationX(int fabAlignmentMode2) {
        int i = 1;
        boolean isRtl = ViewCompat.getLayoutDirection(this) == 1;
        if (fabAlignmentMode2 != 1) {
            return 0;
        }
        int measuredWidth = (getMeasuredWidth() / 2) - this.fabOffsetEndMode;
        if (isRtl) {
            i = -1;
        }
        return measuredWidth * i;
    }

    private float getFabTranslationX() {
        return (float) getFabTranslationX(this.fabAlignmentMode);
    }

    private ActionMenuView getActionMenuView() {
        for (int i = 0; i < getChildCount(); i++) {
            View view = getChildAt(i);
            if (view instanceof ActionMenuView) {
                return (ActionMenuView) view;
            }
        }
        return null;
    }

    /* access modifiers changed from: private */
    public void translateActionMenuView(ActionMenuView actionMenuView, int fabAlignmentMode2, boolean fabAttached2) {
        int i;
        int toolbarLeftContentEnd = 0;
        boolean isRtl = ViewCompat.getLayoutDirection(this) == 1;
        for (int i2 = 0; i2 < getChildCount(); i2++) {
            View view = getChildAt(i2);
            if ((view.getLayoutParams() instanceof Toolbar.LayoutParams) && (((Toolbar.LayoutParams) view.getLayoutParams()).gravity & GravityCompat.RELATIVE_HORIZONTAL_GRAVITY_MASK) == 8388611) {
                if (isRtl) {
                    i = view.getLeft();
                } else {
                    i = view.getRight();
                }
                toolbarLeftContentEnd = Math.max(toolbarLeftContentEnd, i);
            }
        }
        actionMenuView.setTranslationX((fabAlignmentMode2 != 1 || !fabAttached2) ? 0.0f : (float) (toolbarLeftContentEnd - (isRtl ? actionMenuView.getRight() : actionMenuView.getLeft())));
    }

    private void cancelAnimations() {
        Animator animator = this.attachAnimator;
        if (animator != null) {
            animator.cancel();
        }
        Animator animator2 = this.menuAnimator;
        if (animator2 != null) {
            animator2.cancel();
        }
        Animator animator3 = this.modeAnimator;
        if (animator3 != null) {
            animator3.cancel();
        }
    }

    /* access modifiers changed from: private */
    public boolean isAnimationRunning() {
        Animator animator = this.attachAnimator;
        if (animator == null || !animator.isRunning()) {
            Animator animator2 = this.menuAnimator;
            if (animator2 == null || !animator2.isRunning()) {
                Animator animator3 = this.modeAnimator;
                if (animator3 == null || !animator3.isRunning()) {
                    return false;
                }
            }
        }
        return true;
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        cancelAnimations();
        setCutoutState();
    }

    /* access modifiers changed from: private */
    public void setCutoutState() {
        this.topEdgeTreatment.setHorizontalOffset(getFabTranslationX());
        FloatingActionButton fab = findDependentFab();
        this.materialShapeDrawable.setInterpolation((!this.fabAttached || !isVisibleFab()) ? 0.0f : 1.0f);
        if (fab != null) {
            fab.setTranslationY(getFabTranslationY());
            fab.setTranslationX(getFabTranslationX());
        }
        ActionMenuView actionMenuView = getActionMenuView();
        if (actionMenuView != null) {
            actionMenuView.setAlpha(1.0f);
            if (!isVisibleFab()) {
                translateActionMenuView(actionMenuView, 0, false);
            } else {
                translateActionMenuView(actionMenuView, this.fabAlignmentMode, this.fabAttached);
            }
        }
    }

    /* access modifiers changed from: private */
    public void addFabAnimationListeners(FloatingActionButton fab) {
        removeFabAnimationListeners(fab);
        fab.addOnHideAnimationListener(this.fabAnimationListener);
        fab.addOnShowAnimationListener(this.fabAnimationListener);
    }

    private void removeFabAnimationListeners(FloatingActionButton fab) {
        fab.removeOnHideAnimationListener(this.fabAnimationListener);
        fab.removeOnShowAnimationListener(this.fabAnimationListener);
    }

    public void setTitle(CharSequence title) {
    }

    public void setSubtitle(CharSequence subtitle) {
    }

    public androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior<BottomAppBar> getBehavior() {
        return new Behavior();
    }

    /* access modifiers changed from: protected */
    public Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.fabAlignmentMode = this.fabAlignmentMode;
        savedState.fabAttached = this.fabAttached;
        return savedState;
    }

    /* access modifiers changed from: protected */
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState savedState = (SavedState) state;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.fabAlignmentMode = savedState.fabAlignmentMode;
        this.fabAttached = savedState.fabAttached;
    }
}
