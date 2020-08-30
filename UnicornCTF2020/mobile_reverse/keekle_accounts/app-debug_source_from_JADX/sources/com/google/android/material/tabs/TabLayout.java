package com.google.android.material.tabs;

import android.animation.Animator;
import android.animation.Animator.AnimatorListener;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.database.DataSetObserver;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build.VERSION;
import android.text.Layout;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import androidx.appcompat.C0003R;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.TooltipCompat;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.util.Pools.Pool;
import androidx.core.util.Pools.SimplePool;
import androidx.core.util.Pools.SynchronizedPool;
import androidx.core.view.GravityCompat;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.PointerIconCompat;
import androidx.core.view.ViewCompat;
import androidx.core.widget.TextViewCompat;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import androidx.viewpager.widget.ViewPager.DecorView;
import androidx.viewpager.widget.ViewPager.OnAdapterChangeListener;
import androidx.viewpager.widget.ViewPager.OnPageChangeListener;
import com.google.android.material.C0078R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.ripple.RippleUtils;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;

@DecorView
public class TabLayout extends HorizontalScrollView {
    private static final int ANIMATION_DURATION = 300;
    static final int DEFAULT_GAP_TEXT_ICON = 8;
    private static final int DEFAULT_HEIGHT = 48;
    private static final int DEFAULT_HEIGHT_WITH_TEXT_ICON = 72;
    static final int FIXED_WRAP_GUTTER_MIN = 16;
    public static final int GRAVITY_CENTER = 1;
    public static final int GRAVITY_FILL = 0;
    public static final int INDICATOR_GRAVITY_BOTTOM = 0;
    public static final int INDICATOR_GRAVITY_CENTER = 1;
    public static final int INDICATOR_GRAVITY_STRETCH = 3;
    public static final int INDICATOR_GRAVITY_TOP = 2;
    private static final int INVALID_WIDTH = -1;
    private static final int MIN_INDICATOR_WIDTH = 24;
    public static final int MODE_FIXED = 1;
    public static final int MODE_SCROLLABLE = 0;
    private static final int TAB_MIN_WIDTH_MARGIN = 56;
    private static final Pool<Tab> tabPool = new SynchronizedPool(16);
    private AdapterChangeListener adapterChangeListener;
    private int contentInsetStart;
    private BaseOnTabSelectedListener currentVpSelectedListener;
    boolean inlineLabel;
    int mode;
    private TabLayoutOnPageChangeListener pageChangeListener;
    private PagerAdapter pagerAdapter;
    private DataSetObserver pagerAdapterObserver;
    private final int requestedTabMaxWidth;
    private final int requestedTabMinWidth;
    private ValueAnimator scrollAnimator;
    private final int scrollableTabMinWidth;
    private BaseOnTabSelectedListener selectedListener;
    private final ArrayList<BaseOnTabSelectedListener> selectedListeners;
    private Tab selectedTab;
    private boolean setupViewPagerImplicitly;
    private final SlidingTabIndicator slidingTabIndicator;
    final int tabBackgroundResId;
    int tabGravity;
    ColorStateList tabIconTint;
    android.graphics.PorterDuff.Mode tabIconTintMode;
    int tabIndicatorAnimationDuration;
    boolean tabIndicatorFullWidth;
    int tabIndicatorGravity;
    int tabMaxWidth;
    int tabPaddingBottom;
    int tabPaddingEnd;
    int tabPaddingStart;
    int tabPaddingTop;
    ColorStateList tabRippleColorStateList;
    Drawable tabSelectedIndicator;
    int tabTextAppearance;
    ColorStateList tabTextColors;
    float tabTextMultiLineSize;
    float tabTextSize;
    /* access modifiers changed from: private */
    public final RectF tabViewContentBounds;
    private final Pool<TabView> tabViewPool;
    private final ArrayList<Tab> tabs;
    boolean unboundedRipple;
    ViewPager viewPager;

    private class AdapterChangeListener implements OnAdapterChangeListener {
        private boolean autoRefresh;

        AdapterChangeListener() {
        }

        public void onAdapterChanged(ViewPager viewPager, PagerAdapter oldAdapter, PagerAdapter newAdapter) {
            if (TabLayout.this.viewPager == viewPager) {
                TabLayout.this.setPagerAdapter(newAdapter, this.autoRefresh);
            }
        }

        /* access modifiers changed from: 0000 */
        public void setAutoRefresh(boolean autoRefresh2) {
            this.autoRefresh = autoRefresh2;
        }
    }

    public interface BaseOnTabSelectedListener<T extends Tab> {
        void onTabReselected(T t);

        void onTabSelected(T t);

        void onTabUnselected(T t);
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface Mode {
    }

    public interface OnTabSelectedListener extends BaseOnTabSelectedListener<Tab> {
    }

    private class PagerAdapterObserver extends DataSetObserver {
        PagerAdapterObserver() {
        }

        public void onChanged() {
            TabLayout.this.populateFromPagerAdapter();
        }

        public void onInvalidated() {
            TabLayout.this.populateFromPagerAdapter();
        }
    }

    private class SlidingTabIndicator extends LinearLayout {
        private final GradientDrawable defaultSelectionIndicator;
        private ValueAnimator indicatorAnimator;
        private int indicatorLeft = -1;
        private int indicatorRight = -1;
        private int layoutDirection = -1;
        private int selectedIndicatorHeight;
        private final Paint selectedIndicatorPaint;
        int selectedPosition = -1;
        float selectionOffset;

        SlidingTabIndicator(Context context) {
            super(context);
            setWillNotDraw(false);
            this.selectedIndicatorPaint = new Paint();
            this.defaultSelectionIndicator = new GradientDrawable();
        }

        /* access modifiers changed from: 0000 */
        public void setSelectedIndicatorColor(int color) {
            if (this.selectedIndicatorPaint.getColor() != color) {
                this.selectedIndicatorPaint.setColor(color);
                ViewCompat.postInvalidateOnAnimation(this);
            }
        }

        /* access modifiers changed from: 0000 */
        public void setSelectedIndicatorHeight(int height) {
            if (this.selectedIndicatorHeight != height) {
                this.selectedIndicatorHeight = height;
                ViewCompat.postInvalidateOnAnimation(this);
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean childrenNeedLayout() {
            int z = getChildCount();
            for (int i = 0; i < z; i++) {
                if (getChildAt(i).getWidth() <= 0) {
                    return true;
                }
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public void setIndicatorPositionFromTabPosition(int position, float positionOffset) {
            ValueAnimator valueAnimator = this.indicatorAnimator;
            if (valueAnimator != null && valueAnimator.isRunning()) {
                this.indicatorAnimator.cancel();
            }
            this.selectedPosition = position;
            this.selectionOffset = positionOffset;
            updateIndicatorPosition();
        }

        /* access modifiers changed from: 0000 */
        public float getIndicatorPosition() {
            return ((float) this.selectedPosition) + this.selectionOffset;
        }

        public void onRtlPropertiesChanged(int layoutDirection2) {
            super.onRtlPropertiesChanged(layoutDirection2);
            if (VERSION.SDK_INT < 23 && this.layoutDirection != layoutDirection2) {
                requestLayout();
                this.layoutDirection = layoutDirection2;
            }
        }

        /* access modifiers changed from: protected */
        public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            if (MeasureSpec.getMode(widthMeasureSpec) == 1073741824 && TabLayout.this.mode == 1 && TabLayout.this.tabGravity == 1) {
                int count = getChildCount();
                int largestTabWidth = 0;
                int z = count;
                for (int i = 0; i < z; i++) {
                    View child = getChildAt(i);
                    if (child.getVisibility() == 0) {
                        largestTabWidth = Math.max(largestTabWidth, child.getMeasuredWidth());
                    }
                }
                if (largestTabWidth > 0) {
                    boolean remeasure = false;
                    if (largestTabWidth * count <= getMeasuredWidth() - (TabLayout.this.dpToPx(16) * 2)) {
                        for (int i2 = 0; i2 < count; i2++) {
                            LayoutParams lp = (LayoutParams) getChildAt(i2).getLayoutParams();
                            if (lp.width != largestTabWidth || lp.weight != 0.0f) {
                                lp.width = largestTabWidth;
                                lp.weight = 0.0f;
                                remeasure = true;
                            }
                        }
                    } else {
                        TabLayout.this.tabGravity = 0;
                        TabLayout.this.updateTabViews(false);
                        remeasure = true;
                    }
                    if (remeasure) {
                        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                    }
                }
            }
        }

        /* access modifiers changed from: protected */
        public void onLayout(boolean changed, int l, int t, int r, int b) {
            super.onLayout(changed, l, t, r, b);
            ValueAnimator valueAnimator = this.indicatorAnimator;
            if (valueAnimator == null || !valueAnimator.isRunning()) {
                updateIndicatorPosition();
                return;
            }
            this.indicatorAnimator.cancel();
            animateIndicatorToPosition(this.selectedPosition, Math.round((1.0f - this.indicatorAnimator.getAnimatedFraction()) * ((float) this.indicatorAnimator.getDuration())));
        }

        private void updateIndicatorPosition() {
            int right;
            int left;
            View selectedTitle = getChildAt(this.selectedPosition);
            if (selectedTitle == null || selectedTitle.getWidth() <= 0) {
                left = -1;
                right = -1;
            } else {
                left = selectedTitle.getLeft();
                right = selectedTitle.getRight();
                if (!TabLayout.this.tabIndicatorFullWidth && (selectedTitle instanceof TabView)) {
                    calculateTabViewContentBounds((TabView) selectedTitle, TabLayout.this.tabViewContentBounds);
                    left = (int) TabLayout.this.tabViewContentBounds.left;
                    right = (int) TabLayout.this.tabViewContentBounds.right;
                }
                if (this.selectionOffset > 0.0f && this.selectedPosition < getChildCount() - 1) {
                    View nextTitle = getChildAt(this.selectedPosition + 1);
                    int nextTitleLeft = nextTitle.getLeft();
                    int nextTitleRight = nextTitle.getRight();
                    if (!TabLayout.this.tabIndicatorFullWidth && (nextTitle instanceof TabView)) {
                        calculateTabViewContentBounds((TabView) nextTitle, TabLayout.this.tabViewContentBounds);
                        nextTitleLeft = (int) TabLayout.this.tabViewContentBounds.left;
                        nextTitleRight = (int) TabLayout.this.tabViewContentBounds.right;
                    }
                    float f = this.selectionOffset;
                    left = (int) ((((float) nextTitleLeft) * f) + ((1.0f - f) * ((float) left)));
                    right = (int) ((((float) nextTitleRight) * f) + ((1.0f - f) * ((float) right)));
                }
            }
            setIndicatorPosition(left, right);
        }

        /* access modifiers changed from: 0000 */
        public void setIndicatorPosition(int left, int right) {
            if (left != this.indicatorLeft || right != this.indicatorRight) {
                this.indicatorLeft = left;
                this.indicatorRight = right;
                ViewCompat.postInvalidateOnAnimation(this);
            }
        }

        /* access modifiers changed from: 0000 */
        public void animateIndicatorToPosition(int position, int duration) {
            int targetRight;
            int targetLeft;
            ValueAnimator valueAnimator = this.indicatorAnimator;
            if (valueAnimator != null && valueAnimator.isRunning()) {
                this.indicatorAnimator.cancel();
            }
            View targetView = getChildAt(position);
            if (targetView == null) {
                updateIndicatorPosition();
                return;
            }
            int targetLeft2 = targetView.getLeft();
            int targetRight2 = targetView.getRight();
            if (TabLayout.this.tabIndicatorFullWidth || !(targetView instanceof TabView)) {
                targetLeft = targetLeft2;
                targetRight = targetRight2;
            } else {
                calculateTabViewContentBounds((TabView) targetView, TabLayout.this.tabViewContentBounds);
                targetLeft = (int) TabLayout.this.tabViewContentBounds.left;
                targetRight = (int) TabLayout.this.tabViewContentBounds.right;
            }
            int finalTargetLeft = targetLeft;
            int finalTargetRight = targetRight;
            int startLeft = this.indicatorLeft;
            int startRight = this.indicatorRight;
            if (startLeft == finalTargetLeft && startRight == finalTargetRight) {
                int i = position;
                int i2 = duration;
                View view = targetView;
            } else {
                ValueAnimator valueAnimator2 = new ValueAnimator();
                this.indicatorAnimator = valueAnimator2;
                ValueAnimator animator = valueAnimator2;
                animator.setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
                animator.setDuration((long) duration);
                animator.setFloatValues(new float[]{0.0f, 1.0f});
                final int i3 = startLeft;
                final int i4 = finalTargetLeft;
                final int i5 = startRight;
                View view2 = targetView;
                C04901 r7 = r0;
                final int i6 = finalTargetRight;
                C04901 r0 = new AnimatorUpdateListener() {
                    public void onAnimationUpdate(ValueAnimator animator) {
                        float fraction = animator.getAnimatedFraction();
                        SlidingTabIndicator.this.setIndicatorPosition(AnimationUtils.lerp(i3, i4, fraction), AnimationUtils.lerp(i5, i6, fraction));
                    }
                };
                animator.addUpdateListener(r7);
                final int i7 = position;
                animator.addListener(new AnimatorListenerAdapter() {
                    public void onAnimationEnd(Animator animator) {
                        SlidingTabIndicator.this.selectedPosition = i7;
                        SlidingTabIndicator.this.selectionOffset = 0.0f;
                    }
                });
                animator.start();
            }
        }

        private void calculateTabViewContentBounds(TabView tabView, RectF contentBounds) {
            int tabViewContentWidth = tabView.getContentWidth();
            if (tabViewContentWidth < TabLayout.this.dpToPx(24)) {
                tabViewContentWidth = TabLayout.this.dpToPx(24);
            }
            int tabViewCenter = (tabView.getLeft() + tabView.getRight()) / 2;
            contentBounds.set((float) (tabViewCenter - (tabViewContentWidth / 2)), 0.0f, (float) ((tabViewContentWidth / 2) + tabViewCenter), 0.0f);
        }

        public void draw(Canvas canvas) {
            int indicatorHeight = 0;
            if (TabLayout.this.tabSelectedIndicator != null) {
                indicatorHeight = TabLayout.this.tabSelectedIndicator.getIntrinsicHeight();
            }
            if (this.selectedIndicatorHeight >= 0) {
                indicatorHeight = this.selectedIndicatorHeight;
            }
            int indicatorTop = 0;
            int indicatorBottom = 0;
            int i = TabLayout.this.tabIndicatorGravity;
            if (i == 0) {
                indicatorTop = getHeight() - indicatorHeight;
                indicatorBottom = getHeight();
            } else if (i == 1) {
                indicatorTop = (getHeight() - indicatorHeight) / 2;
                indicatorBottom = (getHeight() + indicatorHeight) / 2;
            } else if (i == 2) {
                indicatorTop = 0;
                indicatorBottom = indicatorHeight;
            } else if (i == 3) {
                indicatorTop = 0;
                indicatorBottom = getHeight();
            }
            int i2 = this.indicatorLeft;
            if (i2 >= 0 && this.indicatorRight > i2) {
                Drawable selectedIndicator = DrawableCompat.wrap(TabLayout.this.tabSelectedIndicator != null ? TabLayout.this.tabSelectedIndicator : this.defaultSelectionIndicator);
                selectedIndicator.setBounds(this.indicatorLeft, indicatorTop, this.indicatorRight, indicatorBottom);
                if (this.selectedIndicatorPaint != null) {
                    if (VERSION.SDK_INT == 21) {
                        selectedIndicator.setColorFilter(this.selectedIndicatorPaint.getColor(), android.graphics.PorterDuff.Mode.SRC_IN);
                    } else {
                        DrawableCompat.setTint(selectedIndicator, this.selectedIndicatorPaint.getColor());
                    }
                }
                selectedIndicator.draw(canvas);
            }
            super.draw(canvas);
        }
    }

    public static class Tab {
        public static final int INVALID_POSITION = -1;
        /* access modifiers changed from: private */
        public CharSequence contentDesc;
        private View customView;
        private Drawable icon;
        public TabLayout parent;
        private int position = -1;
        private Object tag;
        /* access modifiers changed from: private */
        public CharSequence text;
        public TabView view;

        public Object getTag() {
            return this.tag;
        }

        public Tab setTag(Object tag2) {
            this.tag = tag2;
            return this;
        }

        public View getCustomView() {
            return this.customView;
        }

        public Tab setCustomView(View view2) {
            this.customView = view2;
            updateView();
            return this;
        }

        public Tab setCustomView(int resId) {
            return setCustomView(LayoutInflater.from(this.view.getContext()).inflate(resId, this.view, false));
        }

        public Drawable getIcon() {
            return this.icon;
        }

        public int getPosition() {
            return this.position;
        }

        /* access modifiers changed from: 0000 */
        public void setPosition(int position2) {
            this.position = position2;
        }

        public CharSequence getText() {
            return this.text;
        }

        public Tab setIcon(Drawable icon2) {
            this.icon = icon2;
            updateView();
            return this;
        }

        public Tab setIcon(int resId) {
            TabLayout tabLayout = this.parent;
            if (tabLayout != null) {
                return setIcon(AppCompatResources.getDrawable(tabLayout.getContext(), resId));
            }
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }

        public Tab setText(CharSequence text2) {
            if (TextUtils.isEmpty(this.contentDesc) && !TextUtils.isEmpty(text2)) {
                this.view.setContentDescription(text2);
            }
            this.text = text2;
            updateView();
            return this;
        }

        public Tab setText(int resId) {
            TabLayout tabLayout = this.parent;
            if (tabLayout != null) {
                return setText(tabLayout.getResources().getText(resId));
            }
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }

        public void select() {
            TabLayout tabLayout = this.parent;
            if (tabLayout != null) {
                tabLayout.selectTab(this);
                return;
            }
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }

        public boolean isSelected() {
            TabLayout tabLayout = this.parent;
            if (tabLayout != null) {
                return tabLayout.getSelectedTabPosition() == this.position;
            }
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }

        public Tab setContentDescription(int resId) {
            TabLayout tabLayout = this.parent;
            if (tabLayout != null) {
                return setContentDescription(tabLayout.getResources().getText(resId));
            }
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }

        public Tab setContentDescription(CharSequence contentDesc2) {
            this.contentDesc = contentDesc2;
            updateView();
            return this;
        }

        public CharSequence getContentDescription() {
            TabView tabView = this.view;
            if (tabView == null) {
                return null;
            }
            return tabView.getContentDescription();
        }

        /* access modifiers changed from: 0000 */
        public void updateView() {
            TabView tabView = this.view;
            if (tabView != null) {
                tabView.update();
            }
        }

        /* access modifiers changed from: 0000 */
        public void reset() {
            this.parent = null;
            this.view = null;
            this.tag = null;
            this.icon = null;
            this.text = null;
            this.contentDesc = null;
            this.position = -1;
            this.customView = null;
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface TabGravity {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface TabIndicatorGravity {
    }

    public static class TabLayoutOnPageChangeListener implements OnPageChangeListener {
        private int previousScrollState;
        private int scrollState;
        private final WeakReference<TabLayout> tabLayoutRef;

        public TabLayoutOnPageChangeListener(TabLayout tabLayout) {
            this.tabLayoutRef = new WeakReference<>(tabLayout);
        }

        public void onPageScrollStateChanged(int state) {
            this.previousScrollState = this.scrollState;
            this.scrollState = state;
        }

        public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            TabLayout tabLayout = (TabLayout) this.tabLayoutRef.get();
            if (tabLayout != null) {
                boolean updateIndicator = false;
                boolean updateText = this.scrollState != 2 || this.previousScrollState == 1;
                if (!(this.scrollState == 2 && this.previousScrollState == 0)) {
                    updateIndicator = true;
                }
                tabLayout.setScrollPosition(position, positionOffset, updateText, updateIndicator);
            }
        }

        public void onPageSelected(int position) {
            TabLayout tabLayout = (TabLayout) this.tabLayoutRef.get();
            if (tabLayout != null && tabLayout.getSelectedTabPosition() != position && position < tabLayout.getTabCount()) {
                int i = this.scrollState;
                tabLayout.selectTab(tabLayout.getTabAt(position), i == 0 || (i == 2 && this.previousScrollState == 0));
            }
        }

        /* access modifiers changed from: 0000 */
        public void reset() {
            this.scrollState = 0;
            this.previousScrollState = 0;
        }
    }

    class TabView extends LinearLayout {
        private Drawable baseBackgroundDrawable;
        private ImageView customIconView;
        private TextView customTextView;
        private View customView;
        private int defaultMaxLines = 2;
        private ImageView iconView;
        private Tab tab;
        private TextView textView;

        public TabView(Context context) {
            super(context);
            updateBackgroundDrawable(context);
            ViewCompat.setPaddingRelative(this, TabLayout.this.tabPaddingStart, TabLayout.this.tabPaddingTop, TabLayout.this.tabPaddingEnd, TabLayout.this.tabPaddingBottom);
            setGravity(17);
            setOrientation(TabLayout.this.inlineLabel ^ true ? 1 : 0);
            setClickable(true);
            ViewCompat.setPointerIcon(this, PointerIconCompat.getSystemIcon(getContext(), PointerIconCompat.TYPE_HAND));
        }

        /* access modifiers changed from: private */
        public void updateBackgroundDrawable(Context context) {
            Drawable background;
            GradientDrawable gradientDrawable = null;
            if (TabLayout.this.tabBackgroundResId != 0) {
                Drawable drawable = AppCompatResources.getDrawable(context, TabLayout.this.tabBackgroundResId);
                this.baseBackgroundDrawable = drawable;
                if (drawable != null && drawable.isStateful()) {
                    this.baseBackgroundDrawable.setState(getDrawableState());
                }
            } else {
                this.baseBackgroundDrawable = null;
            }
            Drawable contentDrawable = new GradientDrawable();
            contentDrawable.setColor(0);
            if (TabLayout.this.tabRippleColorStateList != null) {
                GradientDrawable maskDrawable = new GradientDrawable();
                maskDrawable.setCornerRadius(1.0E-5f);
                maskDrawable.setColor(-1);
                ColorStateList rippleColor = RippleUtils.convertToRippleDrawableColor(TabLayout.this.tabRippleColorStateList);
                if (VERSION.SDK_INT >= 21) {
                    GradientDrawable gradientDrawable2 = TabLayout.this.unboundedRipple ? null : contentDrawable;
                    if (!TabLayout.this.unboundedRipple) {
                        gradientDrawable = maskDrawable;
                    }
                    background = new RippleDrawable(rippleColor, gradientDrawable2, gradientDrawable);
                } else {
                    Drawable rippleDrawable = DrawableCompat.wrap(maskDrawable);
                    DrawableCompat.setTintList(rippleDrawable, rippleColor);
                    background = new LayerDrawable(new Drawable[]{contentDrawable, rippleDrawable});
                }
            } else {
                background = contentDrawable;
            }
            ViewCompat.setBackground(this, background);
            TabLayout.this.invalidate();
        }

        /* access modifiers changed from: private */
        public void drawBackground(Canvas canvas) {
            Drawable drawable = this.baseBackgroundDrawable;
            if (drawable != null) {
                drawable.setBounds(getLeft(), getTop(), getRight(), getBottom());
                this.baseBackgroundDrawable.draw(canvas);
            }
        }

        /* access modifiers changed from: protected */
        public void drawableStateChanged() {
            super.drawableStateChanged();
            boolean changed = false;
            int[] state = getDrawableState();
            Drawable drawable = this.baseBackgroundDrawable;
            if (drawable != null && drawable.isStateful()) {
                changed = false | this.baseBackgroundDrawable.setState(state);
            }
            if (changed) {
                invalidate();
                TabLayout.this.invalidate();
            }
        }

        public boolean performClick() {
            boolean handled = super.performClick();
            if (this.tab == null) {
                return handled;
            }
            if (!handled) {
                playSoundEffect(0);
            }
            this.tab.select();
            return true;
        }

        public void setSelected(boolean selected) {
            boolean changed = isSelected() != selected;
            super.setSelected(selected);
            if (changed && selected && VERSION.SDK_INT < 16) {
                sendAccessibilityEvent(4);
            }
            TextView textView2 = this.textView;
            if (textView2 != null) {
                textView2.setSelected(selected);
            }
            ImageView imageView = this.iconView;
            if (imageView != null) {
                imageView.setSelected(selected);
            }
            View view = this.customView;
            if (view != null) {
                view.setSelected(selected);
            }
        }

        public void onInitializeAccessibilityEvent(AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(event);
            event.setClassName(androidx.appcompat.app.ActionBar.Tab.class.getName());
        }

        public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info);
            info.setClassName(androidx.appcompat.app.ActionBar.Tab.class.getName());
        }

        public void onMeasure(int origWidthMeasureSpec, int origHeightMeasureSpec) {
            int widthMeasureSpec;
            int specWidthSize = MeasureSpec.getSize(origWidthMeasureSpec);
            int specWidthMode = MeasureSpec.getMode(origWidthMeasureSpec);
            int maxWidth = TabLayout.this.getTabMaxWidth();
            int heightMeasureSpec = origHeightMeasureSpec;
            if (maxWidth <= 0 || (specWidthMode != 0 && specWidthSize <= maxWidth)) {
                widthMeasureSpec = origWidthMeasureSpec;
            } else {
                widthMeasureSpec = MeasureSpec.makeMeasureSpec(TabLayout.this.tabMaxWidth, Integer.MIN_VALUE);
            }
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            if (this.textView != null) {
                float textSize = TabLayout.this.tabTextSize;
                int maxLines = this.defaultMaxLines;
                ImageView imageView = this.iconView;
                if (imageView == null || imageView.getVisibility() != 0) {
                    TextView textView2 = this.textView;
                    if (textView2 != null && textView2.getLineCount() > 1) {
                        textSize = TabLayout.this.tabTextMultiLineSize;
                    }
                } else {
                    maxLines = 1;
                }
                float curTextSize = this.textView.getTextSize();
                int curLineCount = this.textView.getLineCount();
                int curMaxLines = TextViewCompat.getMaxLines(this.textView);
                if (textSize != curTextSize || (curMaxLines >= 0 && maxLines != curMaxLines)) {
                    boolean updateTextView = true;
                    if (TabLayout.this.mode == 1 && textSize > curTextSize && curLineCount == 1) {
                        Layout layout = this.textView.getLayout();
                        if (layout == null || approximateLineWidth(layout, 0, textSize) > ((float) ((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight()))) {
                            updateTextView = false;
                        }
                    }
                    if (updateTextView) {
                        this.textView.setTextSize(0, textSize);
                        this.textView.setMaxLines(maxLines);
                        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                    }
                }
            }
        }

        /* access modifiers changed from: 0000 */
        public void setTab(Tab tab2) {
            if (tab2 != this.tab) {
                this.tab = tab2;
                update();
            }
        }

        /* access modifiers changed from: 0000 */
        public void reset() {
            setTab(null);
            setSelected(false);
        }

        /* access modifiers changed from: 0000 */
        public final void update() {
            Tab tab2 = this.tab;
            Drawable icon = null;
            View custom = tab2 != null ? tab2.getCustomView() : null;
            if (custom != null) {
                ViewParent customParent = custom.getParent();
                if (customParent != this) {
                    if (customParent != null) {
                        ((ViewGroup) customParent).removeView(custom);
                    }
                    addView(custom);
                }
                this.customView = custom;
                TextView textView2 = this.textView;
                if (textView2 != null) {
                    textView2.setVisibility(8);
                }
                ImageView imageView = this.iconView;
                if (imageView != null) {
                    imageView.setVisibility(8);
                    this.iconView.setImageDrawable(null);
                }
                TextView textView3 = (TextView) custom.findViewById(16908308);
                this.customTextView = textView3;
                if (textView3 != null) {
                    this.defaultMaxLines = TextViewCompat.getMaxLines(textView3);
                }
                this.customIconView = (ImageView) custom.findViewById(16908294);
            } else {
                View view = this.customView;
                if (view != null) {
                    removeView(view);
                    this.customView = null;
                }
                this.customTextView = null;
                this.customIconView = null;
            }
            boolean z = false;
            if (this.customView == null) {
                if (this.iconView == null) {
                    ImageView iconView2 = (ImageView) LayoutInflater.from(getContext()).inflate(C0078R.layout.design_layout_tab_icon, this, false);
                    addView(iconView2, 0);
                    this.iconView = iconView2;
                }
                if (!(tab2 == null || tab2.getIcon() == null)) {
                    icon = DrawableCompat.wrap(tab2.getIcon()).mutate();
                }
                if (icon != null) {
                    DrawableCompat.setTintList(icon, TabLayout.this.tabIconTint);
                    if (TabLayout.this.tabIconTintMode != null) {
                        DrawableCompat.setTintMode(icon, TabLayout.this.tabIconTintMode);
                    }
                }
                if (this.textView == null) {
                    TextView textView4 = (TextView) LayoutInflater.from(getContext()).inflate(C0078R.layout.design_layout_tab_text, this, false);
                    addView(textView4);
                    this.textView = textView4;
                    this.defaultMaxLines = TextViewCompat.getMaxLines(textView4);
                }
                TextViewCompat.setTextAppearance(this.textView, TabLayout.this.tabTextAppearance);
                if (TabLayout.this.tabTextColors != null) {
                    this.textView.setTextColor(TabLayout.this.tabTextColors);
                }
                updateTextAndIcon(this.textView, this.iconView);
            } else if (!(this.customTextView == null && this.customIconView == null)) {
                updateTextAndIcon(this.customTextView, this.customIconView);
            }
            if (tab2 != null && !TextUtils.isEmpty(tab2.contentDesc)) {
                setContentDescription(tab2.contentDesc);
            }
            if (tab2 != null && tab2.isSelected()) {
                z = true;
            }
            setSelected(z);
        }

        /* access modifiers changed from: 0000 */
        public final void updateOrientation() {
            setOrientation(TabLayout.this.inlineLabel ^ true ? 1 : 0);
            if (this.customTextView == null && this.customIconView == null) {
                updateTextAndIcon(this.textView, this.iconView);
            } else {
                updateTextAndIcon(this.customTextView, this.customIconView);
            }
        }

        private void updateTextAndIcon(TextView textView2, ImageView iconView2) {
            Tab tab2 = this.tab;
            CharSequence charSequence = null;
            Drawable icon = (tab2 == null || tab2.getIcon() == null) ? null : DrawableCompat.wrap(this.tab.getIcon()).mutate();
            Tab tab3 = this.tab;
            CharSequence text = tab3 != null ? tab3.getText() : null;
            if (iconView2 != null) {
                if (icon != null) {
                    iconView2.setImageDrawable(icon);
                    iconView2.setVisibility(0);
                    setVisibility(0);
                } else {
                    iconView2.setVisibility(8);
                    iconView2.setImageDrawable(null);
                }
            }
            boolean hasText = !TextUtils.isEmpty(text);
            if (textView2 != null) {
                if (hasText) {
                    textView2.setText(text);
                    textView2.setVisibility(0);
                    setVisibility(0);
                } else {
                    textView2.setVisibility(8);
                    textView2.setText(null);
                }
            }
            if (iconView2 != null) {
                MarginLayoutParams lp = (MarginLayoutParams) iconView2.getLayoutParams();
                int iconMargin = 0;
                if (hasText && iconView2.getVisibility() == 0) {
                    iconMargin = TabLayout.this.dpToPx(8);
                }
                if (TabLayout.this.inlineLabel) {
                    if (iconMargin != MarginLayoutParamsCompat.getMarginEnd(lp)) {
                        MarginLayoutParamsCompat.setMarginEnd(lp, iconMargin);
                        lp.bottomMargin = 0;
                        iconView2.setLayoutParams(lp);
                        iconView2.requestLayout();
                    }
                } else if (iconMargin != lp.bottomMargin) {
                    lp.bottomMargin = iconMargin;
                    MarginLayoutParamsCompat.setMarginEnd(lp, 0);
                    iconView2.setLayoutParams(lp);
                    iconView2.requestLayout();
                }
            }
            Tab tab4 = this.tab;
            CharSequence contentDesc = tab4 != null ? tab4.contentDesc : null;
            if (!hasText) {
                charSequence = contentDesc;
            }
            TooltipCompat.setTooltipText(this, charSequence);
        }

        /* access modifiers changed from: private */
        public int getContentWidth() {
            boolean initialized = false;
            int left = 0;
            int right = 0;
            View[] viewArr = {this.textView, this.iconView, this.customView};
            for (int i = 0; i < 3; i++) {
                View view = viewArr[i];
                if (view != null && view.getVisibility() == 0) {
                    int left2 = view.getLeft();
                    if (initialized) {
                        left2 = Math.min(left, left2);
                    }
                    left = left2;
                    int right2 = view.getRight();
                    if (initialized) {
                        right2 = Math.max(right, right2);
                    }
                    right = right2;
                    initialized = true;
                }
            }
            return right - left;
        }

        public Tab getTab() {
            return this.tab;
        }

        private float approximateLineWidth(Layout layout, int line, float textSize) {
            return layout.getLineWidth(line) * (textSize / layout.getPaint().getTextSize());
        }
    }

    public static class ViewPagerOnTabSelectedListener implements OnTabSelectedListener {
        private final ViewPager viewPager;

        public ViewPagerOnTabSelectedListener(ViewPager viewPager2) {
            this.viewPager = viewPager2;
        }

        public void onTabSelected(Tab tab) {
            this.viewPager.setCurrentItem(tab.getPosition());
        }

        public void onTabUnselected(Tab tab) {
        }

        public void onTabReselected(Tab tab) {
        }
    }

    public TabLayout(Context context) {
        this(context, null);
    }

    public TabLayout(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.tabStyle);
    }

    /* JADX INFO: finally extract failed */
    public TabLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.tabs = new ArrayList<>();
        this.tabViewContentBounds = new RectF();
        this.tabMaxWidth = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        this.selectedListeners = new ArrayList<>();
        this.tabViewPool = new SimplePool(12);
        setHorizontalScrollBarEnabled(false);
        SlidingTabIndicator slidingTabIndicator2 = new SlidingTabIndicator(context);
        this.slidingTabIndicator = slidingTabIndicator2;
        super.addView(slidingTabIndicator2, 0, new FrameLayout.LayoutParams(-2, -1));
        TypedArray a = ThemeEnforcement.obtainStyledAttributes(context, attrs, C0078R.styleable.TabLayout, defStyleAttr, C0078R.style.Widget_Design_TabLayout, C0078R.styleable.TabLayout_tabTextAppearance);
        this.slidingTabIndicator.setSelectedIndicatorHeight(a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabIndicatorHeight, -1));
        this.slidingTabIndicator.setSelectedIndicatorColor(a.getColor(C0078R.styleable.TabLayout_tabIndicatorColor, 0));
        setSelectedTabIndicator(MaterialResources.getDrawable(context, a, C0078R.styleable.TabLayout_tabIndicator));
        setSelectedTabIndicatorGravity(a.getInt(C0078R.styleable.TabLayout_tabIndicatorGravity, 0));
        setTabIndicatorFullWidth(a.getBoolean(C0078R.styleable.TabLayout_tabIndicatorFullWidth, true));
        int dimensionPixelSize = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabPadding, 0);
        this.tabPaddingBottom = dimensionPixelSize;
        this.tabPaddingEnd = dimensionPixelSize;
        this.tabPaddingTop = dimensionPixelSize;
        this.tabPaddingStart = dimensionPixelSize;
        this.tabPaddingStart = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabPaddingStart, this.tabPaddingStart);
        this.tabPaddingTop = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabPaddingTop, this.tabPaddingTop);
        this.tabPaddingEnd = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabPaddingEnd, this.tabPaddingEnd);
        this.tabPaddingBottom = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabPaddingBottom, this.tabPaddingBottom);
        int resourceId = a.getResourceId(C0078R.styleable.TabLayout_tabTextAppearance, C0078R.style.TextAppearance_Design_Tab);
        this.tabTextAppearance = resourceId;
        TypedArray ta = context.obtainStyledAttributes(resourceId, C0003R.styleable.TextAppearance);
        try {
            this.tabTextSize = (float) ta.getDimensionPixelSize(C0003R.styleable.TextAppearance_android_textSize, 0);
            this.tabTextColors = MaterialResources.getColorStateList(context, ta, C0003R.styleable.TextAppearance_android_textColor);
            ta.recycle();
            if (a.hasValue(C0078R.styleable.TabLayout_tabTextColor)) {
                this.tabTextColors = MaterialResources.getColorStateList(context, a, C0078R.styleable.TabLayout_tabTextColor);
            }
            if (a.hasValue(C0078R.styleable.TabLayout_tabSelectedTextColor)) {
                this.tabTextColors = createColorStateList(this.tabTextColors.getDefaultColor(), a.getColor(C0078R.styleable.TabLayout_tabSelectedTextColor, 0));
            }
            this.tabIconTint = MaterialResources.getColorStateList(context, a, C0078R.styleable.TabLayout_tabIconTint);
            this.tabIconTintMode = ViewUtils.parseTintMode(a.getInt(C0078R.styleable.TabLayout_tabIconTintMode, -1), null);
            this.tabRippleColorStateList = MaterialResources.getColorStateList(context, a, C0078R.styleable.TabLayout_tabRippleColor);
            this.tabIndicatorAnimationDuration = a.getInt(C0078R.styleable.TabLayout_tabIndicatorAnimationDuration, ANIMATION_DURATION);
            this.requestedTabMinWidth = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabMinWidth, -1);
            this.requestedTabMaxWidth = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabMaxWidth, -1);
            this.tabBackgroundResId = a.getResourceId(C0078R.styleable.TabLayout_tabBackground, 0);
            this.contentInsetStart = a.getDimensionPixelSize(C0078R.styleable.TabLayout_tabContentStart, 0);
            this.mode = a.getInt(C0078R.styleable.TabLayout_tabMode, 1);
            this.tabGravity = a.getInt(C0078R.styleable.TabLayout_tabGravity, 0);
            this.inlineLabel = a.getBoolean(C0078R.styleable.TabLayout_tabInlineLabel, false);
            this.unboundedRipple = a.getBoolean(C0078R.styleable.TabLayout_tabUnboundedRipple, false);
            a.recycle();
            Resources res = getResources();
            this.tabTextMultiLineSize = (float) res.getDimensionPixelSize(C0078R.dimen.design_tab_text_size_2line);
            this.scrollableTabMinWidth = res.getDimensionPixelSize(C0078R.dimen.design_tab_scrollable_min_width);
            applyModeAndGravity();
        } catch (Throwable th) {
            ta.recycle();
            throw th;
        }
    }

    public void setSelectedTabIndicatorColor(int color) {
        this.slidingTabIndicator.setSelectedIndicatorColor(color);
    }

    @Deprecated
    public void setSelectedTabIndicatorHeight(int height) {
        this.slidingTabIndicator.setSelectedIndicatorHeight(height);
    }

    public void setScrollPosition(int position, float positionOffset, boolean updateSelectedText) {
        setScrollPosition(position, positionOffset, updateSelectedText, true);
    }

    /* access modifiers changed from: 0000 */
    public void setScrollPosition(int position, float positionOffset, boolean updateSelectedText, boolean updateIndicatorPosition) {
        int roundedPosition = Math.round(((float) position) + positionOffset);
        if (roundedPosition >= 0 && roundedPosition < this.slidingTabIndicator.getChildCount()) {
            if (updateIndicatorPosition) {
                this.slidingTabIndicator.setIndicatorPositionFromTabPosition(position, positionOffset);
            }
            ValueAnimator valueAnimator = this.scrollAnimator;
            if (valueAnimator != null && valueAnimator.isRunning()) {
                this.scrollAnimator.cancel();
            }
            scrollTo(calculateScrollXForTab(position, positionOffset), 0);
            if (updateSelectedText) {
                setSelectedTabView(roundedPosition);
            }
        }
    }

    public void addTab(Tab tab) {
        addTab(tab, this.tabs.isEmpty());
    }

    public void addTab(Tab tab, int position) {
        addTab(tab, position, this.tabs.isEmpty());
    }

    public void addTab(Tab tab, boolean setSelected) {
        addTab(tab, this.tabs.size(), setSelected);
    }

    public void addTab(Tab tab, int position, boolean setSelected) {
        if (tab.parent == this) {
            configureTab(tab, position);
            addTabView(tab);
            if (setSelected) {
                tab.select();
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Tab belongs to a different TabLayout.");
    }

    private void addTabFromItemView(TabItem item) {
        Tab tab = newTab();
        if (item.text != null) {
            tab.setText(item.text);
        }
        if (item.icon != null) {
            tab.setIcon(item.icon);
        }
        if (item.customLayout != 0) {
            tab.setCustomView(item.customLayout);
        }
        if (!TextUtils.isEmpty(item.getContentDescription())) {
            tab.setContentDescription(item.getContentDescription());
        }
        addTab(tab);
    }

    @Deprecated
    public void setOnTabSelectedListener(BaseOnTabSelectedListener listener) {
        BaseOnTabSelectedListener baseOnTabSelectedListener = this.selectedListener;
        if (baseOnTabSelectedListener != null) {
            removeOnTabSelectedListener(baseOnTabSelectedListener);
        }
        this.selectedListener = listener;
        if (listener != null) {
            addOnTabSelectedListener(listener);
        }
    }

    public void addOnTabSelectedListener(BaseOnTabSelectedListener listener) {
        if (!this.selectedListeners.contains(listener)) {
            this.selectedListeners.add(listener);
        }
    }

    public void removeOnTabSelectedListener(BaseOnTabSelectedListener listener) {
        this.selectedListeners.remove(listener);
    }

    public void clearOnTabSelectedListeners() {
        this.selectedListeners.clear();
    }

    public Tab newTab() {
        Tab tab = createTabFromPool();
        tab.parent = this;
        tab.view = createTabView(tab);
        return tab;
    }

    /* access modifiers changed from: protected */
    public Tab createTabFromPool() {
        Tab tab = (Tab) tabPool.acquire();
        if (tab == null) {
            return new Tab();
        }
        return tab;
    }

    /* access modifiers changed from: protected */
    public boolean releaseFromTabPool(Tab tab) {
        return tabPool.release(tab);
    }

    public int getTabCount() {
        return this.tabs.size();
    }

    public Tab getTabAt(int index) {
        if (index < 0 || index >= getTabCount()) {
            return null;
        }
        return (Tab) this.tabs.get(index);
    }

    public int getSelectedTabPosition() {
        Tab tab = this.selectedTab;
        if (tab != null) {
            return tab.getPosition();
        }
        return -1;
    }

    public void removeTab(Tab tab) {
        if (tab.parent == this) {
            removeTabAt(tab.getPosition());
            return;
        }
        throw new IllegalArgumentException("Tab does not belong to this TabLayout.");
    }

    public void removeTabAt(int position) {
        Tab tab = this.selectedTab;
        int selectedTabPosition = tab != null ? tab.getPosition() : 0;
        removeTabViewAt(position);
        Tab removedTab = (Tab) this.tabs.remove(position);
        if (removedTab != null) {
            removedTab.reset();
            releaseFromTabPool(removedTab);
        }
        int newTabCount = this.tabs.size();
        for (int i = position; i < newTabCount; i++) {
            ((Tab) this.tabs.get(i)).setPosition(i);
        }
        if (selectedTabPosition == position) {
            selectTab(this.tabs.isEmpty() ? null : (Tab) this.tabs.get(Math.max(0, position - 1)));
        }
    }

    public void removeAllTabs() {
        for (int i = this.slidingTabIndicator.getChildCount() - 1; i >= 0; i--) {
            removeTabViewAt(i);
        }
        Iterator<Tab> i2 = this.tabs.iterator();
        while (i2.hasNext()) {
            Tab tab = (Tab) i2.next();
            i2.remove();
            tab.reset();
            releaseFromTabPool(tab);
        }
        this.selectedTab = null;
    }

    public void setTabMode(int mode2) {
        if (mode2 != this.mode) {
            this.mode = mode2;
            applyModeAndGravity();
        }
    }

    public int getTabMode() {
        return this.mode;
    }

    public void setTabGravity(int gravity) {
        if (this.tabGravity != gravity) {
            this.tabGravity = gravity;
            applyModeAndGravity();
        }
    }

    public int getTabGravity() {
        return this.tabGravity;
    }

    public void setSelectedTabIndicatorGravity(int indicatorGravity) {
        if (this.tabIndicatorGravity != indicatorGravity) {
            this.tabIndicatorGravity = indicatorGravity;
            ViewCompat.postInvalidateOnAnimation(this.slidingTabIndicator);
        }
    }

    public int getTabIndicatorGravity() {
        return this.tabIndicatorGravity;
    }

    public void setTabIndicatorFullWidth(boolean tabIndicatorFullWidth2) {
        this.tabIndicatorFullWidth = tabIndicatorFullWidth2;
        ViewCompat.postInvalidateOnAnimation(this.slidingTabIndicator);
    }

    public boolean isTabIndicatorFullWidth() {
        return this.tabIndicatorFullWidth;
    }

    public void setInlineLabel(boolean inline) {
        if (this.inlineLabel != inline) {
            this.inlineLabel = inline;
            for (int i = 0; i < this.slidingTabIndicator.getChildCount(); i++) {
                View child = this.slidingTabIndicator.getChildAt(i);
                if (child instanceof TabView) {
                    ((TabView) child).updateOrientation();
                }
            }
            applyModeAndGravity();
        }
    }

    public void setInlineLabelResource(int inlineResourceId) {
        setInlineLabel(getResources().getBoolean(inlineResourceId));
    }

    public boolean isInlineLabel() {
        return this.inlineLabel;
    }

    public void setUnboundedRipple(boolean unboundedRipple2) {
        if (this.unboundedRipple != unboundedRipple2) {
            this.unboundedRipple = unboundedRipple2;
            for (int i = 0; i < this.slidingTabIndicator.getChildCount(); i++) {
                View child = this.slidingTabIndicator.getChildAt(i);
                if (child instanceof TabView) {
                    ((TabView) child).updateBackgroundDrawable(getContext());
                }
            }
        }
    }

    public void setUnboundedRippleResource(int unboundedRippleResourceId) {
        setUnboundedRipple(getResources().getBoolean(unboundedRippleResourceId));
    }

    public boolean hasUnboundedRipple() {
        return this.unboundedRipple;
    }

    public void setTabTextColors(ColorStateList textColor) {
        if (this.tabTextColors != textColor) {
            this.tabTextColors = textColor;
            updateAllTabs();
        }
    }

    public ColorStateList getTabTextColors() {
        return this.tabTextColors;
    }

    public void setTabTextColors(int normalColor, int selectedColor) {
        setTabTextColors(createColorStateList(normalColor, selectedColor));
    }

    public void setTabIconTint(ColorStateList iconTint) {
        if (this.tabIconTint != iconTint) {
            this.tabIconTint = iconTint;
            updateAllTabs();
        }
    }

    public void setTabIconTintResource(int iconTintResourceId) {
        setTabIconTint(AppCompatResources.getColorStateList(getContext(), iconTintResourceId));
    }

    public ColorStateList getTabIconTint() {
        return this.tabIconTint;
    }

    public ColorStateList getTabRippleColor() {
        return this.tabRippleColorStateList;
    }

    public void setTabRippleColor(ColorStateList color) {
        if (this.tabRippleColorStateList != color) {
            this.tabRippleColorStateList = color;
            for (int i = 0; i < this.slidingTabIndicator.getChildCount(); i++) {
                View child = this.slidingTabIndicator.getChildAt(i);
                if (child instanceof TabView) {
                    ((TabView) child).updateBackgroundDrawable(getContext());
                }
            }
        }
    }

    public void setTabRippleColorResource(int tabRippleColorResourceId) {
        setTabRippleColor(AppCompatResources.getColorStateList(getContext(), tabRippleColorResourceId));
    }

    public Drawable getTabSelectedIndicator() {
        return this.tabSelectedIndicator;
    }

    public void setSelectedTabIndicator(Drawable tabSelectedIndicator2) {
        if (this.tabSelectedIndicator != tabSelectedIndicator2) {
            this.tabSelectedIndicator = tabSelectedIndicator2;
            ViewCompat.postInvalidateOnAnimation(this.slidingTabIndicator);
        }
    }

    public void setSelectedTabIndicator(int tabSelectedIndicatorResourceId) {
        if (tabSelectedIndicatorResourceId != 0) {
            setSelectedTabIndicator(AppCompatResources.getDrawable(getContext(), tabSelectedIndicatorResourceId));
        } else {
            setSelectedTabIndicator((Drawable) null);
        }
    }

    public void setupWithViewPager(ViewPager viewPager2) {
        setupWithViewPager(viewPager2, true);
    }

    public void setupWithViewPager(ViewPager viewPager2, boolean autoRefresh) {
        setupWithViewPager(viewPager2, autoRefresh, false);
    }

    private void setupWithViewPager(ViewPager viewPager2, boolean autoRefresh, boolean implicitSetup) {
        ViewPager viewPager3 = this.viewPager;
        if (viewPager3 != null) {
            TabLayoutOnPageChangeListener tabLayoutOnPageChangeListener = this.pageChangeListener;
            if (tabLayoutOnPageChangeListener != null) {
                viewPager3.removeOnPageChangeListener(tabLayoutOnPageChangeListener);
            }
            AdapterChangeListener adapterChangeListener2 = this.adapterChangeListener;
            if (adapterChangeListener2 != null) {
                this.viewPager.removeOnAdapterChangeListener(adapterChangeListener2);
            }
        }
        BaseOnTabSelectedListener baseOnTabSelectedListener = this.currentVpSelectedListener;
        if (baseOnTabSelectedListener != null) {
            removeOnTabSelectedListener(baseOnTabSelectedListener);
            this.currentVpSelectedListener = null;
        }
        if (viewPager2 != null) {
            this.viewPager = viewPager2;
            if (this.pageChangeListener == null) {
                this.pageChangeListener = new TabLayoutOnPageChangeListener(this);
            }
            this.pageChangeListener.reset();
            viewPager2.addOnPageChangeListener(this.pageChangeListener);
            ViewPagerOnTabSelectedListener viewPagerOnTabSelectedListener = new ViewPagerOnTabSelectedListener(viewPager2);
            this.currentVpSelectedListener = viewPagerOnTabSelectedListener;
            addOnTabSelectedListener(viewPagerOnTabSelectedListener);
            PagerAdapter adapter = viewPager2.getAdapter();
            if (adapter != null) {
                setPagerAdapter(adapter, autoRefresh);
            }
            if (this.adapterChangeListener == null) {
                this.adapterChangeListener = new AdapterChangeListener();
            }
            this.adapterChangeListener.setAutoRefresh(autoRefresh);
            viewPager2.addOnAdapterChangeListener(this.adapterChangeListener);
            setScrollPosition(viewPager2.getCurrentItem(), 0.0f, true);
        } else {
            this.viewPager = null;
            setPagerAdapter(null, false);
        }
        this.setupViewPagerImplicitly = implicitSetup;
    }

    @Deprecated
    public void setTabsFromPagerAdapter(PagerAdapter adapter) {
        setPagerAdapter(adapter, false);
    }

    public boolean shouldDelayChildPressedState() {
        return getTabScrollRange() > 0;
    }

    /* access modifiers changed from: protected */
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.viewPager == null) {
            ViewParent vp = getParent();
            if (vp instanceof ViewPager) {
                setupWithViewPager((ViewPager) vp, true, true);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.setupViewPagerImplicitly) {
            setupWithViewPager(null);
            this.setupViewPagerImplicitly = false;
        }
    }

    private int getTabScrollRange() {
        return Math.max(0, ((this.slidingTabIndicator.getWidth() - getWidth()) - getPaddingLeft()) - getPaddingRight());
    }

    /* access modifiers changed from: 0000 */
    public void setPagerAdapter(PagerAdapter adapter, boolean addObserver) {
        PagerAdapter pagerAdapter2 = this.pagerAdapter;
        if (pagerAdapter2 != null) {
            DataSetObserver dataSetObserver = this.pagerAdapterObserver;
            if (dataSetObserver != null) {
                pagerAdapter2.unregisterDataSetObserver(dataSetObserver);
            }
        }
        this.pagerAdapter = adapter;
        if (addObserver && adapter != null) {
            if (this.pagerAdapterObserver == null) {
                this.pagerAdapterObserver = new PagerAdapterObserver();
            }
            adapter.registerDataSetObserver(this.pagerAdapterObserver);
        }
        populateFromPagerAdapter();
    }

    /* access modifiers changed from: 0000 */
    public void populateFromPagerAdapter() {
        removeAllTabs();
        PagerAdapter pagerAdapter2 = this.pagerAdapter;
        if (pagerAdapter2 != null) {
            int adapterCount = pagerAdapter2.getCount();
            for (int i = 0; i < adapterCount; i++) {
                addTab(newTab().setText(this.pagerAdapter.getPageTitle(i)), false);
            }
            ViewPager viewPager2 = this.viewPager;
            if (viewPager2 != null && adapterCount > 0) {
                int curItem = viewPager2.getCurrentItem();
                if (curItem != getSelectedTabPosition() && curItem < getTabCount()) {
                    selectTab(getTabAt(curItem));
                }
            }
        }
    }

    private void updateAllTabs() {
        int z = this.tabs.size();
        for (int i = 0; i < z; i++) {
            ((Tab) this.tabs.get(i)).updateView();
        }
    }

    private TabView createTabView(Tab tab) {
        Pool<TabView> pool = this.tabViewPool;
        TabView tabView = pool != null ? (TabView) pool.acquire() : null;
        if (tabView == null) {
            tabView = new TabView(getContext());
        }
        tabView.setTab(tab);
        tabView.setFocusable(true);
        tabView.setMinimumWidth(getTabMinWidth());
        if (TextUtils.isEmpty(tab.contentDesc)) {
            tabView.setContentDescription(tab.text);
        } else {
            tabView.setContentDescription(tab.contentDesc);
        }
        return tabView;
    }

    private void configureTab(Tab tab, int position) {
        tab.setPosition(position);
        this.tabs.add(position, tab);
        int count = this.tabs.size();
        for (int i = position + 1; i < count; i++) {
            ((Tab) this.tabs.get(i)).setPosition(i);
        }
    }

    private void addTabView(Tab tab) {
        this.slidingTabIndicator.addView(tab.view, tab.getPosition(), createLayoutParamsForTabs());
    }

    public void addView(View child) {
        addViewInternal(child);
    }

    public void addView(View child, int index) {
        addViewInternal(child);
    }

    public void addView(View child, ViewGroup.LayoutParams params) {
        addViewInternal(child);
    }

    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        addViewInternal(child);
    }

    private void addViewInternal(View child) {
        if (child instanceof TabItem) {
            addTabFromItemView((TabItem) child);
            return;
        }
        throw new IllegalArgumentException("Only TabItem instances can be added to TabLayout");
    }

    private LayoutParams createLayoutParamsForTabs() {
        LayoutParams lp = new LayoutParams(-2, -1);
        updateTabViewLayoutParams(lp);
        return lp;
    }

    private void updateTabViewLayoutParams(LayoutParams lp) {
        if (this.mode == 1 && this.tabGravity == 0) {
            lp.width = 0;
            lp.weight = 1.0f;
            return;
        }
        lp.width = -2;
        lp.weight = 0.0f;
    }

    /* access modifiers changed from: 0000 */
    public int dpToPx(int dps) {
        return Math.round(getResources().getDisplayMetrics().density * ((float) dps));
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        for (int i = 0; i < this.slidingTabIndicator.getChildCount(); i++) {
            View tabView = this.slidingTabIndicator.getChildAt(i);
            if (tabView instanceof TabView) {
                ((TabView) tabView).drawBackground(canvas);
            }
        }
        super.onDraw(canvas);
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int idealHeight = dpToPx(getDefaultHeight()) + getPaddingTop() + getPaddingBottom();
        int mode2 = MeasureSpec.getMode(heightMeasureSpec);
        if (mode2 == Integer.MIN_VALUE) {
            heightMeasureSpec = MeasureSpec.makeMeasureSpec(Math.min(idealHeight, MeasureSpec.getSize(heightMeasureSpec)), 1073741824);
        } else if (mode2 == 0) {
            heightMeasureSpec = MeasureSpec.makeMeasureSpec(idealHeight, 1073741824);
        }
        int specWidth = MeasureSpec.getSize(widthMeasureSpec);
        if (MeasureSpec.getMode(widthMeasureSpec) != 0) {
            int i = this.requestedTabMaxWidth;
            if (i <= 0) {
                i = specWidth - dpToPx(56);
            }
            this.tabMaxWidth = i;
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        boolean z = true;
        if (getChildCount() == 1) {
            View child = getChildAt(0);
            boolean remeasure = false;
            int i2 = this.mode;
            if (i2 == 0) {
                if (child.getMeasuredWidth() >= getMeasuredWidth()) {
                    z = false;
                }
                remeasure = z;
            } else if (i2 == 1) {
                if (child.getMeasuredWidth() == getMeasuredWidth()) {
                    z = false;
                }
                remeasure = z;
            }
            if (remeasure) {
                child.measure(MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824), getChildMeasureSpec(heightMeasureSpec, getPaddingTop() + getPaddingBottom(), child.getLayoutParams().height));
            }
        }
    }

    private void removeTabViewAt(int position) {
        TabView view = (TabView) this.slidingTabIndicator.getChildAt(position);
        this.slidingTabIndicator.removeViewAt(position);
        if (view != null) {
            view.reset();
            this.tabViewPool.release(view);
        }
        requestLayout();
    }

    private void animateToTab(int newPosition) {
        if (newPosition != -1) {
            if (getWindowToken() == null || !ViewCompat.isLaidOut(this) || this.slidingTabIndicator.childrenNeedLayout()) {
                setScrollPosition(newPosition, 0.0f, true);
                return;
            }
            int startScrollX = getScrollX();
            int targetScrollX = calculateScrollXForTab(newPosition, 0.0f);
            if (startScrollX != targetScrollX) {
                ensureScrollAnimator();
                this.scrollAnimator.setIntValues(new int[]{startScrollX, targetScrollX});
                this.scrollAnimator.start();
            }
            this.slidingTabIndicator.animateIndicatorToPosition(newPosition, this.tabIndicatorAnimationDuration);
        }
    }

    private void ensureScrollAnimator() {
        if (this.scrollAnimator == null) {
            ValueAnimator valueAnimator = new ValueAnimator();
            this.scrollAnimator = valueAnimator;
            valueAnimator.setInterpolator(AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR);
            this.scrollAnimator.setDuration((long) this.tabIndicatorAnimationDuration);
            this.scrollAnimator.addUpdateListener(new AnimatorUpdateListener() {
                public void onAnimationUpdate(ValueAnimator animator) {
                    TabLayout.this.scrollTo(((Integer) animator.getAnimatedValue()).intValue(), 0);
                }
            });
        }
    }

    /* access modifiers changed from: 0000 */
    public void setScrollAnimatorListener(AnimatorListener listener) {
        ensureScrollAnimator();
        this.scrollAnimator.addListener(listener);
    }

    private void setSelectedTabView(int position) {
        int tabCount = this.slidingTabIndicator.getChildCount();
        if (position < tabCount) {
            int i = 0;
            while (i < tabCount) {
                View child = this.slidingTabIndicator.getChildAt(i);
                boolean z = false;
                child.setSelected(i == position);
                if (i == position) {
                    z = true;
                }
                child.setActivated(z);
                i++;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void selectTab(Tab tab) {
        selectTab(tab, true);
    }

    /* access modifiers changed from: 0000 */
    public void selectTab(Tab tab, boolean updateIndicator) {
        Tab currentTab = this.selectedTab;
        if (currentTab != tab) {
            int newPosition = tab != null ? tab.getPosition() : -1;
            if (updateIndicator) {
                if ((currentTab == null || currentTab.getPosition() == -1) && newPosition != -1) {
                    setScrollPosition(newPosition, 0.0f, true);
                } else {
                    animateToTab(newPosition);
                }
                if (newPosition != -1) {
                    setSelectedTabView(newPosition);
                }
            }
            this.selectedTab = tab;
            if (currentTab != null) {
                dispatchTabUnselected(currentTab);
            }
            if (tab != null) {
                dispatchTabSelected(tab);
            }
        } else if (currentTab != null) {
            dispatchTabReselected(tab);
            animateToTab(tab.getPosition());
        }
    }

    private void dispatchTabSelected(Tab tab) {
        for (int i = this.selectedListeners.size() - 1; i >= 0; i--) {
            ((BaseOnTabSelectedListener) this.selectedListeners.get(i)).onTabSelected(tab);
        }
    }

    private void dispatchTabUnselected(Tab tab) {
        for (int i = this.selectedListeners.size() - 1; i >= 0; i--) {
            ((BaseOnTabSelectedListener) this.selectedListeners.get(i)).onTabUnselected(tab);
        }
    }

    private void dispatchTabReselected(Tab tab) {
        for (int i = this.selectedListeners.size() - 1; i >= 0; i--) {
            ((BaseOnTabSelectedListener) this.selectedListeners.get(i)).onTabReselected(tab);
        }
    }

    private int calculateScrollXForTab(int position, float positionOffset) {
        int nextWidth = 0;
        if (this.mode != 0) {
            return 0;
        }
        View selectedChild = this.slidingTabIndicator.getChildAt(position);
        View nextChild = position + 1 < this.slidingTabIndicator.getChildCount() ? this.slidingTabIndicator.getChildAt(position + 1) : null;
        int selectedWidth = selectedChild != null ? selectedChild.getWidth() : 0;
        if (nextChild != null) {
            nextWidth = nextChild.getWidth();
        }
        int scrollBase = (selectedChild.getLeft() + (selectedWidth / 2)) - (getWidth() / 2);
        int scrollOffset = (int) (((float) (selectedWidth + nextWidth)) * 0.5f * positionOffset);
        return ViewCompat.getLayoutDirection(this) == 0 ? scrollBase + scrollOffset : scrollBase - scrollOffset;
    }

    private void applyModeAndGravity() {
        int paddingStart = 0;
        if (this.mode == 0) {
            paddingStart = Math.max(0, this.contentInsetStart - this.tabPaddingStart);
        }
        ViewCompat.setPaddingRelative(this.slidingTabIndicator, paddingStart, 0, 0, 0);
        int i = this.mode;
        if (i == 0) {
            this.slidingTabIndicator.setGravity(GravityCompat.START);
        } else if (i == 1) {
            this.slidingTabIndicator.setGravity(1);
        }
        updateTabViews(true);
    }

    /* access modifiers changed from: 0000 */
    public void updateTabViews(boolean requestLayout) {
        for (int i = 0; i < this.slidingTabIndicator.getChildCount(); i++) {
            View child = this.slidingTabIndicator.getChildAt(i);
            child.setMinimumWidth(getTabMinWidth());
            updateTabViewLayoutParams((LayoutParams) child.getLayoutParams());
            if (requestLayout) {
                child.requestLayout();
            }
        }
    }

    private static ColorStateList createColorStateList(int defaultColor, int selectedColor) {
        int[][] states = new int[2][];
        int[] colors = new int[2];
        states[0] = SELECTED_STATE_SET;
        colors[0] = selectedColor;
        int i = 0 + 1;
        states[i] = EMPTY_STATE_SET;
        colors[i] = defaultColor;
        int i2 = i + 1;
        return new ColorStateList(states, colors);
    }

    private int getDefaultHeight() {
        boolean hasIconAndText = false;
        int i = 0;
        int count = this.tabs.size();
        while (true) {
            if (i >= count) {
                break;
            }
            Tab tab = (Tab) this.tabs.get(i);
            if (tab != null && tab.getIcon() != null && !TextUtils.isEmpty(tab.getText())) {
                hasIconAndText = true;
                break;
            }
            i++;
        }
        return (!hasIconAndText || this.inlineLabel) ? 48 : 72;
    }

    private int getTabMinWidth() {
        int i = this.requestedTabMinWidth;
        if (i != -1) {
            return i;
        }
        return this.mode == 0 ? this.scrollableTabMinWidth : 0;
    }

    public FrameLayout.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return generateDefaultLayoutParams();
    }

    /* access modifiers changed from: 0000 */
    public int getTabMaxWidth() {
        return this.tabMaxWidth;
    }
}
