package com.google.android.material.appbar;

import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.appcompat.C0003R;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.math.MathUtils;
import androidx.core.util.ObjectsCompat;
import androidx.core.view.OnApplyWindowInsetsListener;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener;
import com.google.android.material.internal.CollapsingTextHelper;
import com.google.android.material.internal.DescendantOffsetUtils;
import com.google.android.material.internal.ThemeEnforcement;

public class CollapsingToolbarLayout extends FrameLayout {
    private static final int DEFAULT_SCRIM_ANIMATION_DURATION = 600;
    final CollapsingTextHelper collapsingTextHelper;
    private boolean collapsingTitleEnabled;
    private Drawable contentScrim;
    int currentOffset;
    private boolean drawCollapsingTitle;
    private View dummyView;
    private int expandedMarginBottom;
    private int expandedMarginEnd;
    private int expandedMarginStart;
    private int expandedMarginTop;
    WindowInsetsCompat lastInsets;
    private OnOffsetChangedListener onOffsetChangedListener;
    private boolean refreshToolbar;
    private int scrimAlpha;
    private long scrimAnimationDuration;
    private ValueAnimator scrimAnimator;
    private int scrimVisibleHeightTrigger;
    private boolean scrimsAreShown;
    Drawable statusBarScrim;
    private final Rect tmpRect;
    private Toolbar toolbar;
    private View toolbarDirectChild;
    private int toolbarId;

    public static class LayoutParams extends android.widget.FrameLayout.LayoutParams {
        public static final int COLLAPSE_MODE_OFF = 0;
        public static final int COLLAPSE_MODE_PARALLAX = 2;
        public static final int COLLAPSE_MODE_PIN = 1;
        private static final float DEFAULT_PARALLAX_MULTIPLIER = 0.5f;
        int collapseMode = 0;
        float parallaxMult = DEFAULT_PARALLAX_MULTIPLIER;

        public LayoutParams(Context c, AttributeSet attrs) {
            super(c, attrs);
            TypedArray a = c.obtainStyledAttributes(attrs, C0078R.styleable.CollapsingToolbarLayout_Layout);
            this.collapseMode = a.getInt(C0078R.styleable.CollapsingToolbarLayout_Layout_layout_collapseMode, 0);
            setParallaxMultiplier(a.getFloat(C0078R.styleable.CollapsingToolbarLayout_Layout_layout_collapseParallaxMultiplier, DEFAULT_PARALLAX_MULTIPLIER));
            a.recycle();
        }

        public LayoutParams(int width, int height) {
            super(width, height);
        }

        public LayoutParams(int width, int height, int gravity) {
            super(width, height, gravity);
        }

        public LayoutParams(android.view.ViewGroup.LayoutParams p) {
            super(p);
        }

        public LayoutParams(MarginLayoutParams source) {
            super(source);
        }

        public LayoutParams(android.widget.FrameLayout.LayoutParams source) {
            super(source);
        }

        public void setCollapseMode(int collapseMode2) {
            this.collapseMode = collapseMode2;
        }

        public int getCollapseMode() {
            return this.collapseMode;
        }

        public void setParallaxMultiplier(float multiplier) {
            this.parallaxMult = multiplier;
        }

        public float getParallaxMultiplier() {
            return this.parallaxMult;
        }
    }

    private class OffsetUpdateListener implements OnOffsetChangedListener {
        OffsetUpdateListener() {
        }

        public void onOffsetChanged(AppBarLayout layout, int verticalOffset) {
            CollapsingToolbarLayout.this.currentOffset = verticalOffset;
            int insetTop = CollapsingToolbarLayout.this.lastInsets != null ? CollapsingToolbarLayout.this.lastInsets.getSystemWindowInsetTop() : 0;
            int z = CollapsingToolbarLayout.this.getChildCount();
            for (int i = 0; i < z; i++) {
                View child = CollapsingToolbarLayout.this.getChildAt(i);
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                ViewOffsetHelper offsetHelper = CollapsingToolbarLayout.getViewOffsetHelper(child);
                int i2 = lp.collapseMode;
                if (i2 == 1) {
                    offsetHelper.setTopAndBottomOffset(MathUtils.clamp(-verticalOffset, 0, CollapsingToolbarLayout.this.getMaxOffsetForPinChild(child)));
                } else if (i2 == 2) {
                    offsetHelper.setTopAndBottomOffset(Math.round(((float) (-verticalOffset)) * lp.parallaxMult));
                }
            }
            CollapsingToolbarLayout.this.updateScrimVisibility();
            if (CollapsingToolbarLayout.this.statusBarScrim != null && insetTop > 0) {
                ViewCompat.postInvalidateOnAnimation(CollapsingToolbarLayout.this);
            }
            CollapsingToolbarLayout.this.collapsingTextHelper.setExpansionFraction(((float) Math.abs(verticalOffset)) / ((float) ((CollapsingToolbarLayout.this.getHeight() - ViewCompat.getMinimumHeight(CollapsingToolbarLayout.this)) - insetTop)));
        }
    }

    public CollapsingToolbarLayout(Context context) {
        this(context, null);
    }

    public CollapsingToolbarLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public CollapsingToolbarLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.refreshToolbar = true;
        this.tmpRect = new Rect();
        this.scrimVisibleHeightTrigger = -1;
        CollapsingTextHelper collapsingTextHelper2 = new CollapsingTextHelper(this);
        this.collapsingTextHelper = collapsingTextHelper2;
        collapsingTextHelper2.setTextSizeInterpolator(AnimationUtils.DECELERATE_INTERPOLATOR);
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(context, attrs, C0078R.styleable.CollapsingToolbarLayout, defStyleAttr, C0078R.style.Widget_Design_CollapsingToolbar, new int[0]);
        this.collapsingTextHelper.setExpandedTextGravity(a.getInt(C0078R.styleable.CollapsingToolbarLayout_expandedTitleGravity, 8388691));
        this.collapsingTextHelper.setCollapsedTextGravity(a.getInt(C0078R.styleable.CollapsingToolbarLayout_collapsedTitleGravity, 8388627));
        int dimensionPixelSize = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMargin, 0);
        this.expandedMarginBottom = dimensionPixelSize;
        this.expandedMarginEnd = dimensionPixelSize;
        this.expandedMarginTop = dimensionPixelSize;
        this.expandedMarginStart = dimensionPixelSize;
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginStart)) {
            this.expandedMarginStart = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginStart, 0);
        }
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginEnd)) {
            this.expandedMarginEnd = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginEnd, 0);
        }
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginTop)) {
            this.expandedMarginTop = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginTop, 0);
        }
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginBottom)) {
            this.expandedMarginBottom = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_expandedTitleMarginBottom, 0);
        }
        this.collapsingTitleEnabled = a.getBoolean(C0078R.styleable.CollapsingToolbarLayout_titleEnabled, true);
        setTitle(a.getText(C0078R.styleable.CollapsingToolbarLayout_title));
        this.collapsingTextHelper.setExpandedTextAppearance(C0078R.style.TextAppearance_Design_CollapsingToolbar_Expanded);
        this.collapsingTextHelper.setCollapsedTextAppearance(C0003R.style.TextAppearance_AppCompat_Widget_ActionBar_Title);
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_expandedTitleTextAppearance)) {
            this.collapsingTextHelper.setExpandedTextAppearance(a.getResourceId(C0078R.styleable.CollapsingToolbarLayout_expandedTitleTextAppearance, 0));
        }
        if (a.hasValue(C0078R.styleable.CollapsingToolbarLayout_collapsedTitleTextAppearance)) {
            this.collapsingTextHelper.setCollapsedTextAppearance(a.getResourceId(C0078R.styleable.CollapsingToolbarLayout_collapsedTitleTextAppearance, 0));
        }
        this.scrimVisibleHeightTrigger = a.getDimensionPixelSize(C0078R.styleable.CollapsingToolbarLayout_scrimVisibleHeightTrigger, -1);
        this.scrimAnimationDuration = (long) a.getInt(C0078R.styleable.CollapsingToolbarLayout_scrimAnimationDuration, DEFAULT_SCRIM_ANIMATION_DURATION);
        setContentScrim(a.getDrawable(C0078R.styleable.CollapsingToolbarLayout_contentScrim));
        setStatusBarScrim(a.getDrawable(C0078R.styleable.CollapsingToolbarLayout_statusBarScrim));
        this.toolbarId = a.getResourceId(C0078R.styleable.CollapsingToolbarLayout_toolbarId, -1);
        a.recycle();
        setWillNotDraw(false);
        ViewCompat.setOnApplyWindowInsetsListener(this, new OnApplyWindowInsetsListener() {
            public WindowInsetsCompat onApplyWindowInsets(View v, WindowInsetsCompat insets) {
                return CollapsingToolbarLayout.this.onWindowInsetChanged(insets);
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        ViewParent parent = getParent();
        if (parent instanceof AppBarLayout) {
            ViewCompat.setFitsSystemWindows(this, ViewCompat.getFitsSystemWindows((View) parent));
            if (this.onOffsetChangedListener == null) {
                this.onOffsetChangedListener = new OffsetUpdateListener();
            }
            ((AppBarLayout) parent).addOnOffsetChangedListener(this.onOffsetChangedListener);
            ViewCompat.requestApplyInsets(this);
        }
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        ViewParent parent = getParent();
        OnOffsetChangedListener onOffsetChangedListener2 = this.onOffsetChangedListener;
        if (onOffsetChangedListener2 != null && (parent instanceof AppBarLayout)) {
            ((AppBarLayout) parent).removeOnOffsetChangedListener(onOffsetChangedListener2);
        }
        super.onDetachedFromWindow();
    }

    /* access modifiers changed from: 0000 */
    public WindowInsetsCompat onWindowInsetChanged(WindowInsetsCompat insets) {
        WindowInsetsCompat newInsets = null;
        if (ViewCompat.getFitsSystemWindows(this)) {
            newInsets = insets;
        }
        if (!ObjectsCompat.equals(this.lastInsets, newInsets)) {
            this.lastInsets = newInsets;
            requestLayout();
        }
        return insets.consumeSystemWindowInsets();
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        ensureToolbar();
        if (this.toolbar == null) {
            Drawable drawable = this.contentScrim;
            if (drawable != null && this.scrimAlpha > 0) {
                drawable.mutate().setAlpha(this.scrimAlpha);
                this.contentScrim.draw(canvas);
            }
        }
        if (this.collapsingTitleEnabled && this.drawCollapsingTitle) {
            this.collapsingTextHelper.draw(canvas);
        }
        if (this.statusBarScrim != null && this.scrimAlpha > 0) {
            WindowInsetsCompat windowInsetsCompat = this.lastInsets;
            int topInset = windowInsetsCompat != null ? windowInsetsCompat.getSystemWindowInsetTop() : 0;
            if (topInset > 0) {
                this.statusBarScrim.setBounds(0, -this.currentOffset, getWidth(), topInset - this.currentOffset);
                this.statusBarScrim.mutate().setAlpha(this.scrimAlpha);
                this.statusBarScrim.draw(canvas);
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean drawChild(Canvas canvas, View child, long drawingTime) {
        boolean invalidated = false;
        if (this.contentScrim != null && this.scrimAlpha > 0 && isToolbarChild(child)) {
            this.contentScrim.mutate().setAlpha(this.scrimAlpha);
            this.contentScrim.draw(canvas);
            invalidated = true;
        }
        return super.drawChild(canvas, child, drawingTime) || invalidated;
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        Drawable drawable = this.contentScrim;
        if (drawable != null) {
            drawable.setBounds(0, 0, w, h);
        }
    }

    private void ensureToolbar() {
        if (this.refreshToolbar) {
            this.toolbar = null;
            this.toolbarDirectChild = null;
            int i = this.toolbarId;
            if (i != -1) {
                Toolbar toolbar2 = (Toolbar) findViewById(i);
                this.toolbar = toolbar2;
                if (toolbar2 != null) {
                    this.toolbarDirectChild = findDirectChild(toolbar2);
                }
            }
            if (this.toolbar == null) {
                Toolbar toolbar3 = null;
                int i2 = 0;
                int count = getChildCount();
                while (true) {
                    if (i2 >= count) {
                        break;
                    }
                    View child = getChildAt(i2);
                    if (child instanceof Toolbar) {
                        toolbar3 = (Toolbar) child;
                        break;
                    }
                    i2++;
                }
                this.toolbar = toolbar3;
            }
            updateDummyView();
            this.refreshToolbar = false;
        }
    }

    private boolean isToolbarChild(View child) {
        View view = this.toolbarDirectChild;
        if (view == null || view == this) {
            if (child == this.toolbar) {
                return true;
            }
        } else if (child == view) {
            return true;
        }
        return false;
    }

    private View findDirectChild(View descendant) {
        View directChild = descendant;
        ViewParent p = descendant.getParent();
        while (p != this && p != null) {
            if (p instanceof View) {
                directChild = (View) p;
            }
            p = p.getParent();
        }
        return directChild;
    }

    private void updateDummyView() {
        if (!this.collapsingTitleEnabled) {
            View view = this.dummyView;
            if (view != null) {
                ViewParent parent = view.getParent();
                if (parent instanceof ViewGroup) {
                    ((ViewGroup) parent).removeView(this.dummyView);
                }
            }
        }
        if (this.collapsingTitleEnabled && this.toolbar != null) {
            if (this.dummyView == null) {
                this.dummyView = new View(getContext());
            }
            if (this.dummyView.getParent() == null) {
                this.toolbar.addView(this.dummyView, -1, -1);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        ensureToolbar();
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        int mode = MeasureSpec.getMode(heightMeasureSpec);
        WindowInsetsCompat windowInsetsCompat = this.lastInsets;
        int topInset = windowInsetsCompat != null ? windowInsetsCompat.getSystemWindowInsetTop() : 0;
        if (mode == 0 && topInset > 0) {
            super.onMeasure(widthMeasureSpec, MeasureSpec.makeMeasureSpec(getMeasuredHeight() + topInset, 1073741824));
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        WindowInsetsCompat windowInsetsCompat = this.lastInsets;
        if (windowInsetsCompat != null) {
            int insetTop = windowInsetsCompat.getSystemWindowInsetTop();
            int z = getChildCount();
            for (int i = 0; i < z; i++) {
                View child = getChildAt(i);
                if (!ViewCompat.getFitsSystemWindows(child) && child.getTop() < insetTop) {
                    ViewCompat.offsetTopAndBottom(child, insetTop);
                }
            }
        }
        if (this.collapsingTitleEnabled != 0) {
            View view = this.dummyView;
            if (view != null) {
                boolean z2 = false;
                boolean z3 = ViewCompat.isAttachedToWindow(view) && this.dummyView.getVisibility() == 0;
                this.drawCollapsingTitle = z3;
                if (z3) {
                    if (ViewCompat.getLayoutDirection(this) == 1) {
                        z2 = true;
                    }
                    boolean isRtl = z2;
                    View view2 = this.toolbarDirectChild;
                    if (view2 == null) {
                        view2 = this.toolbar;
                    }
                    int maxOffset = getMaxOffsetForPinChild(view2);
                    DescendantOffsetUtils.getDescendantRect(this, this.dummyView, this.tmpRect);
                    this.collapsingTextHelper.setCollapsedBounds(this.tmpRect.left + (isRtl ? this.toolbar.getTitleMarginEnd() : this.toolbar.getTitleMarginStart()), this.tmpRect.top + maxOffset + this.toolbar.getTitleMarginTop(), this.tmpRect.right + (isRtl ? this.toolbar.getTitleMarginStart() : this.toolbar.getTitleMarginEnd()), (this.tmpRect.bottom + maxOffset) - this.toolbar.getTitleMarginBottom());
                    this.collapsingTextHelper.setExpandedBounds(isRtl ? this.expandedMarginEnd : this.expandedMarginStart, this.tmpRect.top + this.expandedMarginTop, (right - left) - (isRtl ? this.expandedMarginStart : this.expandedMarginEnd), (bottom - top) - this.expandedMarginBottom);
                    this.collapsingTextHelper.recalculate();
                }
            }
        }
        int z4 = getChildCount();
        for (int i2 = 0; i2 < z4; i2++) {
            getViewOffsetHelper(getChildAt(i2)).onViewLayout();
        }
        if (this.toolbar != null) {
            if (this.collapsingTitleEnabled && TextUtils.isEmpty(this.collapsingTextHelper.getText())) {
                setTitle(this.toolbar.getTitle());
            }
            View view3 = this.toolbarDirectChild;
            if (view3 == null || view3 == this) {
                setMinimumHeight(getHeightWithMargins(this.toolbar));
            } else {
                setMinimumHeight(getHeightWithMargins(view3));
            }
        }
        updateScrimVisibility();
    }

    private static int getHeightWithMargins(View view) {
        android.view.ViewGroup.LayoutParams lp = view.getLayoutParams();
        if (!(lp instanceof MarginLayoutParams)) {
            return view.getHeight();
        }
        MarginLayoutParams mlp = (MarginLayoutParams) lp;
        return view.getHeight() + mlp.topMargin + mlp.bottomMargin;
    }

    static ViewOffsetHelper getViewOffsetHelper(View view) {
        ViewOffsetHelper offsetHelper = (ViewOffsetHelper) view.getTag(C0078R.C0080id.view_offset_helper);
        if (offsetHelper != null) {
            return offsetHelper;
        }
        ViewOffsetHelper offsetHelper2 = new ViewOffsetHelper(view);
        view.setTag(C0078R.C0080id.view_offset_helper, offsetHelper2);
        return offsetHelper2;
    }

    public void setTitle(CharSequence title) {
        this.collapsingTextHelper.setText(title);
        updateContentDescriptionFromTitle();
    }

    public CharSequence getTitle() {
        if (this.collapsingTitleEnabled) {
            return this.collapsingTextHelper.getText();
        }
        return null;
    }

    public void setTitleEnabled(boolean enabled) {
        if (enabled != this.collapsingTitleEnabled) {
            this.collapsingTitleEnabled = enabled;
            updateContentDescriptionFromTitle();
            updateDummyView();
            requestLayout();
        }
    }

    public boolean isTitleEnabled() {
        return this.collapsingTitleEnabled;
    }

    public void setScrimsShown(boolean shown) {
        setScrimsShown(shown, ViewCompat.isLaidOut(this) && !isInEditMode());
    }

    public void setScrimsShown(boolean shown, boolean animate) {
        if (this.scrimsAreShown != shown) {
            int i = 255;
            if (animate) {
                if (!shown) {
                    i = 0;
                }
                animateScrim(i);
            } else {
                if (!shown) {
                    i = 0;
                }
                setScrimAlpha(i);
            }
            this.scrimsAreShown = shown;
        }
    }

    private void animateScrim(int targetAlpha) {
        ensureToolbar();
        ValueAnimator valueAnimator = this.scrimAnimator;
        if (valueAnimator == null) {
            ValueAnimator valueAnimator2 = new ValueAnimator();
            this.scrimAnimator = valueAnimator2;
            valueAnimator2.setDuration(this.scrimAnimationDuration);
            this.scrimAnimator.setInterpolator(targetAlpha > this.scrimAlpha ? AnimationUtils.FAST_OUT_LINEAR_IN_INTERPOLATOR : AnimationUtils.LINEAR_OUT_SLOW_IN_INTERPOLATOR);
            this.scrimAnimator.addUpdateListener(new AnimatorUpdateListener() {
                public void onAnimationUpdate(ValueAnimator animator) {
                    CollapsingToolbarLayout.this.setScrimAlpha(((Integer) animator.getAnimatedValue()).intValue());
                }
            });
        } else if (valueAnimator.isRunning()) {
            this.scrimAnimator.cancel();
        }
        this.scrimAnimator.setIntValues(new int[]{this.scrimAlpha, targetAlpha});
        this.scrimAnimator.start();
    }

    /* access modifiers changed from: 0000 */
    public void setScrimAlpha(int alpha) {
        if (alpha != this.scrimAlpha) {
            if (this.contentScrim != null) {
                Toolbar toolbar2 = this.toolbar;
                if (toolbar2 != null) {
                    ViewCompat.postInvalidateOnAnimation(toolbar2);
                }
            }
            this.scrimAlpha = alpha;
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    /* access modifiers changed from: 0000 */
    public int getScrimAlpha() {
        return this.scrimAlpha;
    }

    public void setContentScrim(Drawable drawable) {
        Drawable drawable2 = this.contentScrim;
        if (drawable2 != drawable) {
            Drawable drawable3 = null;
            if (drawable2 != null) {
                drawable2.setCallback(null);
            }
            if (drawable != null) {
                drawable3 = drawable.mutate();
            }
            this.contentScrim = drawable3;
            if (drawable3 != null) {
                drawable3.setBounds(0, 0, getWidth(), getHeight());
                this.contentScrim.setCallback(this);
                this.contentScrim.setAlpha(this.scrimAlpha);
            }
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    public void setContentScrimColor(int color) {
        setContentScrim(new ColorDrawable(color));
    }

    public void setContentScrimResource(int resId) {
        setContentScrim(ContextCompat.getDrawable(getContext(), resId));
    }

    public Drawable getContentScrim() {
        return this.contentScrim;
    }

    public void setStatusBarScrim(Drawable drawable) {
        Drawable drawable2 = this.statusBarScrim;
        if (drawable2 != drawable) {
            Drawable drawable3 = null;
            if (drawable2 != null) {
                drawable2.setCallback(null);
            }
            if (drawable != null) {
                drawable3 = drawable.mutate();
            }
            this.statusBarScrim = drawable3;
            if (drawable3 != null) {
                if (drawable3.isStateful()) {
                    this.statusBarScrim.setState(getDrawableState());
                }
                DrawableCompat.setLayoutDirection(this.statusBarScrim, ViewCompat.getLayoutDirection(this));
                this.statusBarScrim.setVisible(getVisibility() == 0, false);
                this.statusBarScrim.setCallback(this);
                this.statusBarScrim.setAlpha(this.scrimAlpha);
            }
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        super.drawableStateChanged();
        int[] state = getDrawableState();
        boolean changed = false;
        Drawable d = this.statusBarScrim;
        if (d != null && d.isStateful()) {
            changed = false | d.setState(state);
        }
        Drawable d2 = this.contentScrim;
        if (d2 != null && d2.isStateful()) {
            changed |= d2.setState(state);
        }
        CollapsingTextHelper collapsingTextHelper2 = this.collapsingTextHelper;
        if (collapsingTextHelper2 != null) {
            changed |= collapsingTextHelper2.setState(state);
        }
        if (changed) {
            invalidate();
        }
    }

    /* access modifiers changed from: protected */
    public boolean verifyDrawable(Drawable who) {
        return super.verifyDrawable(who) || who == this.contentScrim || who == this.statusBarScrim;
    }

    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        boolean visible = visibility == 0;
        Drawable drawable = this.statusBarScrim;
        if (!(drawable == null || drawable.isVisible() == visible)) {
            this.statusBarScrim.setVisible(visible, false);
        }
        Drawable drawable2 = this.contentScrim;
        if (drawable2 != null && drawable2.isVisible() != visible) {
            this.contentScrim.setVisible(visible, false);
        }
    }

    public void setStatusBarScrimColor(int color) {
        setStatusBarScrim(new ColorDrawable(color));
    }

    public void setStatusBarScrimResource(int resId) {
        setStatusBarScrim(ContextCompat.getDrawable(getContext(), resId));
    }

    public Drawable getStatusBarScrim() {
        return this.statusBarScrim;
    }

    public void setCollapsedTitleTextAppearance(int resId) {
        this.collapsingTextHelper.setCollapsedTextAppearance(resId);
    }

    public void setCollapsedTitleTextColor(int color) {
        setCollapsedTitleTextColor(ColorStateList.valueOf(color));
    }

    public void setCollapsedTitleTextColor(ColorStateList colors) {
        this.collapsingTextHelper.setCollapsedTextColor(colors);
    }

    public void setCollapsedTitleGravity(int gravity) {
        this.collapsingTextHelper.setCollapsedTextGravity(gravity);
    }

    public int getCollapsedTitleGravity() {
        return this.collapsingTextHelper.getCollapsedTextGravity();
    }

    public void setExpandedTitleTextAppearance(int resId) {
        this.collapsingTextHelper.setExpandedTextAppearance(resId);
    }

    public void setExpandedTitleColor(int color) {
        setExpandedTitleTextColor(ColorStateList.valueOf(color));
    }

    public void setExpandedTitleTextColor(ColorStateList colors) {
        this.collapsingTextHelper.setExpandedTextColor(colors);
    }

    public void setExpandedTitleGravity(int gravity) {
        this.collapsingTextHelper.setExpandedTextGravity(gravity);
    }

    public int getExpandedTitleGravity() {
        return this.collapsingTextHelper.getExpandedTextGravity();
    }

    public void setCollapsedTitleTypeface(Typeface typeface) {
        this.collapsingTextHelper.setCollapsedTypeface(typeface);
    }

    public Typeface getCollapsedTitleTypeface() {
        return this.collapsingTextHelper.getCollapsedTypeface();
    }

    public void setExpandedTitleTypeface(Typeface typeface) {
        this.collapsingTextHelper.setExpandedTypeface(typeface);
    }

    public Typeface getExpandedTitleTypeface() {
        return this.collapsingTextHelper.getExpandedTypeface();
    }

    public void setExpandedTitleMargin(int start, int top, int end, int bottom) {
        this.expandedMarginStart = start;
        this.expandedMarginTop = top;
        this.expandedMarginEnd = end;
        this.expandedMarginBottom = bottom;
        requestLayout();
    }

    public int getExpandedTitleMarginStart() {
        return this.expandedMarginStart;
    }

    public void setExpandedTitleMarginStart(int margin) {
        this.expandedMarginStart = margin;
        requestLayout();
    }

    public int getExpandedTitleMarginTop() {
        return this.expandedMarginTop;
    }

    public void setExpandedTitleMarginTop(int margin) {
        this.expandedMarginTop = margin;
        requestLayout();
    }

    public int getExpandedTitleMarginEnd() {
        return this.expandedMarginEnd;
    }

    public void setExpandedTitleMarginEnd(int margin) {
        this.expandedMarginEnd = margin;
        requestLayout();
    }

    public int getExpandedTitleMarginBottom() {
        return this.expandedMarginBottom;
    }

    public void setExpandedTitleMarginBottom(int margin) {
        this.expandedMarginBottom = margin;
        requestLayout();
    }

    public void setScrimVisibleHeightTrigger(int height) {
        if (this.scrimVisibleHeightTrigger != height) {
            this.scrimVisibleHeightTrigger = height;
            updateScrimVisibility();
        }
    }

    public int getScrimVisibleHeightTrigger() {
        int i = this.scrimVisibleHeightTrigger;
        if (i >= 0) {
            return i;
        }
        WindowInsetsCompat windowInsetsCompat = this.lastInsets;
        int insetTop = windowInsetsCompat != null ? windowInsetsCompat.getSystemWindowInsetTop() : 0;
        int minHeight = ViewCompat.getMinimumHeight(this);
        if (minHeight > 0) {
            return Math.min((minHeight * 2) + insetTop, getHeight());
        }
        return getHeight() / 3;
    }

    public void setScrimAnimationDuration(long duration) {
        this.scrimAnimationDuration = duration;
    }

    public long getScrimAnimationDuration() {
        return this.scrimAnimationDuration;
    }

    /* access modifiers changed from: protected */
    public boolean checkLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return p instanceof LayoutParams;
    }

    /* access modifiers changed from: protected */
    public LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(-1, -1);
    }

    public android.widget.FrameLayout.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    /* access modifiers changed from: protected */
    public android.widget.FrameLayout.LayoutParams generateLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return new LayoutParams(p);
    }

    /* access modifiers changed from: 0000 */
    public final void updateScrimVisibility() {
        if (this.contentScrim != null || this.statusBarScrim != null) {
            setScrimsShown(getHeight() + this.currentOffset < getScrimVisibleHeightTrigger());
        }
    }

    /* access modifiers changed from: 0000 */
    public final int getMaxOffsetForPinChild(View child) {
        return ((getHeight() - getViewOffsetHelper(child).getLayoutTop()) - child.getHeight()) - ((LayoutParams) child.getLayoutParams()).bottomMargin;
    }

    private void updateContentDescriptionFromTitle() {
        setContentDescription(getTitle());
    }
}
