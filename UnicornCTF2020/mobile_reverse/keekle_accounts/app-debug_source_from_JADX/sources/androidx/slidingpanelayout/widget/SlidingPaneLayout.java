package androidx.slidingpanelayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import androidx.core.content.ContextCompat;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.customview.view.AbsSavedState;
import androidx.customview.widget.ViewDragHelper;
import androidx.customview.widget.ViewDragHelper.Callback;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

public class SlidingPaneLayout extends ViewGroup {
    private static final int DEFAULT_FADE_COLOR = -858993460;
    private static final int DEFAULT_OVERHANG_SIZE = 32;
    private static final int MIN_FLING_VELOCITY = 400;
    private static final String TAG = "SlidingPaneLayout";
    private boolean mCanSlide;
    private int mCoveredFadeColor;
    private boolean mDisplayListReflectionLoaded;
    final ViewDragHelper mDragHelper;
    private boolean mFirstLayout;
    private Method mGetDisplayList;
    private float mInitialMotionX;
    private float mInitialMotionY;
    boolean mIsUnableToDrag;
    private final int mOverhangSize;
    private PanelSlideListener mPanelSlideListener;
    private int mParallaxBy;
    private float mParallaxOffset;
    final ArrayList<DisableLayerRunnable> mPostedRunnables;
    boolean mPreservedOpenState;
    private Field mRecreateDisplayList;
    private Drawable mShadowDrawableLeft;
    private Drawable mShadowDrawableRight;
    float mSlideOffset;
    int mSlideRange;
    View mSlideableView;
    private int mSliderFadeColor;
    private final Rect mTmpRect;

    class AccessibilityDelegate extends AccessibilityDelegateCompat {
        private final Rect mTmpRect = new Rect();

        AccessibilityDelegate() {
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            AccessibilityNodeInfoCompat superNode = AccessibilityNodeInfoCompat.obtain(info);
            super.onInitializeAccessibilityNodeInfo(host, superNode);
            copyNodeInfoNoChildren(info, superNode);
            superNode.recycle();
            info.setClassName(SlidingPaneLayout.class.getName());
            info.setSource(host);
            ViewParent parent = ViewCompat.getParentForAccessibility(host);
            if (parent instanceof View) {
                info.setParent((View) parent);
            }
            int childCount = SlidingPaneLayout.this.getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = SlidingPaneLayout.this.getChildAt(i);
                if (!filter(child) && child.getVisibility() == 0) {
                    ViewCompat.setImportantForAccessibility(child, 1);
                    info.addChild(child);
                }
            }
        }

        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(host, event);
            event.setClassName(SlidingPaneLayout.class.getName());
        }

        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
            if (!filter(child)) {
                return super.onRequestSendAccessibilityEvent(host, child, event);
            }
            return false;
        }

        public boolean filter(View child) {
            return SlidingPaneLayout.this.isDimmed(child);
        }

        private void copyNodeInfoNoChildren(AccessibilityNodeInfoCompat dest, AccessibilityNodeInfoCompat src) {
            Rect rect = this.mTmpRect;
            src.getBoundsInParent(rect);
            dest.setBoundsInParent(rect);
            src.getBoundsInScreen(rect);
            dest.setBoundsInScreen(rect);
            dest.setVisibleToUser(src.isVisibleToUser());
            dest.setPackageName(src.getPackageName());
            dest.setClassName(src.getClassName());
            dest.setContentDescription(src.getContentDescription());
            dest.setEnabled(src.isEnabled());
            dest.setClickable(src.isClickable());
            dest.setFocusable(src.isFocusable());
            dest.setFocused(src.isFocused());
            dest.setAccessibilityFocused(src.isAccessibilityFocused());
            dest.setSelected(src.isSelected());
            dest.setLongClickable(src.isLongClickable());
            dest.addAction(src.getActions());
            dest.setMovementGranularities(src.getMovementGranularities());
        }
    }

    private class DisableLayerRunnable implements Runnable {
        final View mChildView;

        DisableLayerRunnable(View childView) {
            this.mChildView = childView;
        }

        public void run() {
            if (this.mChildView.getParent() == SlidingPaneLayout.this) {
                this.mChildView.setLayerType(0, null);
                SlidingPaneLayout.this.invalidateChildRegion(this.mChildView);
            }
            SlidingPaneLayout.this.mPostedRunnables.remove(this);
        }
    }

    private class DragHelperCallback extends Callback {
        DragHelperCallback() {
        }

        public boolean tryCaptureView(View child, int pointerId) {
            if (SlidingPaneLayout.this.mIsUnableToDrag) {
                return false;
            }
            return ((LayoutParams) child.getLayoutParams()).slideable;
        }

        public void onViewDragStateChanged(int state) {
            if (SlidingPaneLayout.this.mDragHelper.getViewDragState() != 0) {
                return;
            }
            if (SlidingPaneLayout.this.mSlideOffset == 0.0f) {
                SlidingPaneLayout slidingPaneLayout = SlidingPaneLayout.this;
                slidingPaneLayout.updateObscuredViewsVisibility(slidingPaneLayout.mSlideableView);
                SlidingPaneLayout slidingPaneLayout2 = SlidingPaneLayout.this;
                slidingPaneLayout2.dispatchOnPanelClosed(slidingPaneLayout2.mSlideableView);
                SlidingPaneLayout.this.mPreservedOpenState = false;
                return;
            }
            SlidingPaneLayout slidingPaneLayout3 = SlidingPaneLayout.this;
            slidingPaneLayout3.dispatchOnPanelOpened(slidingPaneLayout3.mSlideableView);
            SlidingPaneLayout.this.mPreservedOpenState = true;
        }

        public void onViewCaptured(View capturedChild, int activePointerId) {
            SlidingPaneLayout.this.setAllChildrenVisible();
        }

        public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
            SlidingPaneLayout.this.onPanelDragged(left);
            SlidingPaneLayout.this.invalidate();
        }

        public void onViewReleased(View releasedChild, float xvel, float yvel) {
            int left;
            LayoutParams lp = (LayoutParams) releasedChild.getLayoutParams();
            if (SlidingPaneLayout.this.isLayoutRtlSupport()) {
                int startToRight = SlidingPaneLayout.this.getPaddingRight() + lp.rightMargin;
                if (xvel < 0.0f || (xvel == 0.0f && SlidingPaneLayout.this.mSlideOffset > 0.5f)) {
                    startToRight += SlidingPaneLayout.this.mSlideRange;
                }
                left = (SlidingPaneLayout.this.getWidth() - startToRight) - SlidingPaneLayout.this.mSlideableView.getWidth();
            } else {
                int left2 = SlidingPaneLayout.this.getPaddingLeft() + lp.leftMargin;
                if (xvel > 0.0f || (xvel == 0.0f && SlidingPaneLayout.this.mSlideOffset > 0.5f)) {
                    left = left2 + SlidingPaneLayout.this.mSlideRange;
                } else {
                    left = left2;
                }
            }
            SlidingPaneLayout.this.mDragHelper.settleCapturedViewAt(left, releasedChild.getTop());
            SlidingPaneLayout.this.invalidate();
        }

        public int getViewHorizontalDragRange(View child) {
            return SlidingPaneLayout.this.mSlideRange;
        }

        public int clampViewPositionHorizontal(View child, int left, int dx) {
            LayoutParams lp = (LayoutParams) SlidingPaneLayout.this.mSlideableView.getLayoutParams();
            if (SlidingPaneLayout.this.isLayoutRtlSupport()) {
                int startBound = SlidingPaneLayout.this.getWidth() - ((SlidingPaneLayout.this.getPaddingRight() + lp.rightMargin) + SlidingPaneLayout.this.mSlideableView.getWidth());
                return Math.max(Math.min(left, startBound), startBound - SlidingPaneLayout.this.mSlideRange);
            }
            int startBound2 = SlidingPaneLayout.this.getPaddingLeft() + lp.leftMargin;
            return Math.min(Math.max(left, startBound2), SlidingPaneLayout.this.mSlideRange + startBound2);
        }

        public int clampViewPositionVertical(View child, int top, int dy) {
            return child.getTop();
        }

        public void onEdgeDragStarted(int edgeFlags, int pointerId) {
            SlidingPaneLayout.this.mDragHelper.captureChildView(SlidingPaneLayout.this.mSlideableView, pointerId);
        }
    }

    public static class LayoutParams extends MarginLayoutParams {
        private static final int[] ATTRS = {16843137};
        Paint dimPaint;
        boolean dimWhenOffset;
        boolean slideable;
        public float weight = 0.0f;

        public LayoutParams() {
            super(-1, -1);
        }

        public LayoutParams(int width, int height) {
            super(width, height);
        }

        public LayoutParams(android.view.ViewGroup.LayoutParams source) {
            super(source);
        }

        public LayoutParams(MarginLayoutParams source) {
            super(source);
        }

        public LayoutParams(LayoutParams source) {
            super(source);
            this.weight = source.weight;
        }

        public LayoutParams(Context c, AttributeSet attrs) {
            super(c, attrs);
            TypedArray a = c.obtainStyledAttributes(attrs, ATTRS);
            this.weight = a.getFloat(0, 0.0f);
            a.recycle();
        }
    }

    public interface PanelSlideListener {
        void onPanelClosed(View view);

        void onPanelOpened(View view);

        void onPanelSlide(View view, float f);
    }

    static class SavedState extends AbsSavedState {
        public static final Creator<SavedState> CREATOR = new ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, null);
            }

            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        boolean isOpen;

        SavedState(Parcelable superState) {
            super(superState);
        }

        SavedState(Parcel in, ClassLoader loader) {
            super(in, loader);
            this.isOpen = in.readInt() != 0;
        }

        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.isOpen ? 1 : 0);
        }
    }

    public static class SimplePanelSlideListener implements PanelSlideListener {
        public void onPanelSlide(View panel, float slideOffset) {
        }

        public void onPanelOpened(View panel) {
        }

        public void onPanelClosed(View panel) {
        }
    }

    public SlidingPaneLayout(Context context) {
        this(context, null);
    }

    public SlidingPaneLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SlidingPaneLayout(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        this.mSliderFadeColor = DEFAULT_FADE_COLOR;
        this.mFirstLayout = true;
        this.mTmpRect = new Rect();
        this.mPostedRunnables = new ArrayList<>();
        float density = context.getResources().getDisplayMetrics().density;
        this.mOverhangSize = (int) ((32.0f * density) + 0.5f);
        setWillNotDraw(false);
        ViewCompat.setAccessibilityDelegate(this, new AccessibilityDelegate());
        ViewCompat.setImportantForAccessibility(this, 1);
        ViewDragHelper create = ViewDragHelper.create(this, 0.5f, new DragHelperCallback());
        this.mDragHelper = create;
        create.setMinVelocity(400.0f * density);
    }

    public void setParallaxDistance(int parallaxBy) {
        this.mParallaxBy = parallaxBy;
        requestLayout();
    }

    public int getParallaxDistance() {
        return this.mParallaxBy;
    }

    public void setSliderFadeColor(int color) {
        this.mSliderFadeColor = color;
    }

    public int getSliderFadeColor() {
        return this.mSliderFadeColor;
    }

    public void setCoveredFadeColor(int color) {
        this.mCoveredFadeColor = color;
    }

    public int getCoveredFadeColor() {
        return this.mCoveredFadeColor;
    }

    public void setPanelSlideListener(PanelSlideListener listener) {
        this.mPanelSlideListener = listener;
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnPanelSlide(View panel) {
        PanelSlideListener panelSlideListener = this.mPanelSlideListener;
        if (panelSlideListener != null) {
            panelSlideListener.onPanelSlide(panel, this.mSlideOffset);
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnPanelOpened(View panel) {
        PanelSlideListener panelSlideListener = this.mPanelSlideListener;
        if (panelSlideListener != null) {
            panelSlideListener.onPanelOpened(panel);
        }
        sendAccessibilityEvent(32);
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnPanelClosed(View panel) {
        PanelSlideListener panelSlideListener = this.mPanelSlideListener;
        if (panelSlideListener != null) {
            panelSlideListener.onPanelClosed(panel);
        }
        sendAccessibilityEvent(32);
    }

    /* access modifiers changed from: 0000 */
    public void updateObscuredViewsVisibility(View panel) {
        int bottom;
        int top;
        int right;
        int left;
        boolean isLayoutRtl;
        int clampedChildRight;
        View view = panel;
        boolean isLayoutRtl2 = isLayoutRtlSupport();
        int startBound = isLayoutRtl2 ? getWidth() - getPaddingRight() : getPaddingLeft();
        int endBound = isLayoutRtl2 ? getPaddingLeft() : getWidth() - getPaddingRight();
        int topBound = getPaddingTop();
        int bottomBound = getHeight() - getPaddingBottom();
        if (view == null || !viewIsOpaque(panel)) {
            left = 0;
            bottom = 0;
            top = 0;
            right = 0;
        } else {
            left = panel.getLeft();
            right = panel.getRight();
            top = panel.getTop();
            bottom = panel.getBottom();
        }
        int i = 0;
        int childCount = getChildCount();
        while (i < childCount) {
            View child = getChildAt(i);
            if (child == view) {
                boolean z = isLayoutRtl2;
                return;
            }
            if (child.getVisibility() == 8) {
                isLayoutRtl = isLayoutRtl2;
            } else {
                int clampedChildLeft = Math.max(isLayoutRtl2 ? endBound : startBound, child.getLeft());
                int clampedChildTop = Math.max(topBound, child.getTop());
                isLayoutRtl = isLayoutRtl2;
                int clampedChildRight2 = Math.min(isLayoutRtl2 ? startBound : endBound, child.getRight());
                int clampedChildBottom = Math.min(bottomBound, child.getBottom());
                if (clampedChildLeft < left || clampedChildTop < top || clampedChildRight2 > right || clampedChildBottom > bottom) {
                    int i2 = clampedChildRight2;
                    clampedChildRight = 0;
                } else {
                    int i3 = clampedChildRight2;
                    clampedChildRight = 4;
                }
                child.setVisibility(clampedChildRight);
            }
            i++;
            view = panel;
            isLayoutRtl2 = isLayoutRtl;
        }
        boolean z2 = isLayoutRtl2;
    }

    /* access modifiers changed from: 0000 */
    public void setAllChildrenVisible() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == 4) {
                child.setVisibility(0);
            }
        }
    }

    private static boolean viewIsOpaque(View v) {
        boolean z = true;
        if (v.isOpaque()) {
            return true;
        }
        if (VERSION.SDK_INT >= 18) {
            return false;
        }
        Drawable bg = v.getBackground();
        if (bg == null) {
            return false;
        }
        if (bg.getOpacity() != -1) {
            z = false;
        }
        return z;
    }

    /* access modifiers changed from: protected */
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mFirstLayout = true;
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mFirstLayout = true;
        int count = this.mPostedRunnables.size();
        for (int i = 0; i < count; i++) {
            ((DisableLayerRunnable) this.mPostedRunnables.get(i)).run();
        }
        this.mPostedRunnables.clear();
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int i;
        int maxLayoutHeight;
        int fixedPanelWidthLimit;
        int childCount;
        int heightMode;
        int childHeightSpec;
        int childHeightSpec2;
        int i2;
        int heightSize;
        int childWidthSpec;
        int childHeightSpec3;
        int widthMode = MeasureSpec.getMode(widthMeasureSpec);
        int widthSize = MeasureSpec.getSize(widthMeasureSpec);
        int heightMode2 = MeasureSpec.getMode(heightMeasureSpec);
        int heightSize2 = MeasureSpec.getSize(heightMeasureSpec);
        if (widthMode != 1073741824) {
            if (!isInEditMode()) {
                throw new IllegalStateException("Width must have an exact value or MATCH_PARENT");
            } else if (widthMode == Integer.MIN_VALUE) {
                widthMode = 1073741824;
            } else if (widthMode == 0) {
                widthMode = 1073741824;
                widthSize = 300;
            }
        } else if (heightMode2 == 0) {
            if (!isInEditMode()) {
                throw new IllegalStateException("Height must not be UNSPECIFIED");
            } else if (heightMode2 == 0) {
                heightMode2 = Integer.MIN_VALUE;
                heightSize2 = 300;
            }
        }
        int layoutHeight = 0;
        int maxLayoutHeight2 = 0;
        if (heightMode2 == Integer.MIN_VALUE) {
            maxLayoutHeight2 = (heightSize2 - getPaddingTop()) - getPaddingBottom();
        } else if (heightMode2 == 1073741824) {
            int paddingTop = (heightSize2 - getPaddingTop()) - getPaddingBottom();
            maxLayoutHeight2 = paddingTop;
            layoutHeight = paddingTop;
        }
        float weightSum = 0.0f;
        boolean canSlide = false;
        int widthAvailable = (widthSize - getPaddingLeft()) - getPaddingRight();
        int widthRemaining = widthAvailable;
        int childCount2 = getChildCount();
        if (childCount2 > 2) {
            Log.e(TAG, "onMeasure: More than two child views are not supported.");
        }
        this.mSlideableView = null;
        int i3 = 0;
        while (true) {
            i = 8;
            if (i3 >= childCount2) {
                break;
            }
            View child = getChildAt(i3);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            int widthMode2 = widthMode;
            if (child.getVisibility() == 8) {
                lp.dimWhenOffset = false;
                heightSize = heightSize2;
            } else {
                if (lp.weight > 0.0f) {
                    weightSum += lp.weight;
                    if (lp.width == 0) {
                        heightSize = heightSize2;
                    }
                }
                int horizontalMargin = lp.leftMargin + lp.rightMargin;
                heightSize = heightSize2;
                if (lp.width == -2) {
                    childWidthSpec = MeasureSpec.makeMeasureSpec(widthAvailable - horizontalMargin, Integer.MIN_VALUE);
                } else if (lp.width == -1) {
                    childWidthSpec = MeasureSpec.makeMeasureSpec(widthAvailable - horizontalMargin, 1073741824);
                } else {
                    childWidthSpec = MeasureSpec.makeMeasureSpec(lp.width, 1073741824);
                }
                int i4 = horizontalMargin;
                if (lp.height == -2) {
                    childHeightSpec3 = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, Integer.MIN_VALUE);
                } else if (lp.height == -1) {
                    childHeightSpec3 = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, 1073741824);
                } else {
                    childHeightSpec3 = MeasureSpec.makeMeasureSpec(lp.height, 1073741824);
                }
                child.measure(childWidthSpec, childHeightSpec3);
                int childWidth = child.getMeasuredWidth();
                int i5 = childWidthSpec;
                int childHeight = child.getMeasuredHeight();
                float weightSum2 = weightSum;
                if (heightMode2 == Integer.MIN_VALUE && childHeight > layoutHeight) {
                    layoutHeight = Math.min(childHeight, maxLayoutHeight2);
                }
                widthRemaining -= childWidth;
                boolean z = widthRemaining < 0;
                lp.slideable = z;
                boolean canSlide2 = z | canSlide;
                if (lp.slideable) {
                    this.mSlideableView = child;
                }
                canSlide = canSlide2;
                weightSum = weightSum2;
            }
            i3++;
            widthMode = widthMode2;
            heightSize2 = heightSize;
        }
        int i6 = heightSize2;
        if (canSlide || weightSum > 0.0f) {
            int fixedPanelWidthLimit2 = widthAvailable - this.mOverhangSize;
            int i7 = 0;
            while (i7 < childCount2) {
                View child2 = getChildAt(i7);
                if (child2.getVisibility() == i) {
                    fixedPanelWidthLimit = fixedPanelWidthLimit2;
                    heightMode = heightMode2;
                    maxLayoutHeight = maxLayoutHeight2;
                    childCount = childCount2;
                } else {
                    LayoutParams lp2 = (LayoutParams) child2.getLayoutParams();
                    if (child2.getVisibility() == i) {
                        fixedPanelWidthLimit = fixedPanelWidthLimit2;
                        heightMode = heightMode2;
                        maxLayoutHeight = maxLayoutHeight2;
                        childCount = childCount2;
                    } else {
                        boolean skippedFirstPass = lp2.width == 0 && lp2.weight > 0.0f;
                        int measuredWidth = skippedFirstPass ? 0 : child2.getMeasuredWidth();
                        if (!canSlide || child2 == this.mSlideableView) {
                            childCount = childCount2;
                            boolean z2 = skippedFirstPass;
                            int measuredWidth2 = measuredWidth;
                            heightMode = heightMode2;
                            if (lp2.weight > 0.0f) {
                                if (lp2.width != 0) {
                                    childHeightSpec = MeasureSpec.makeMeasureSpec(child2.getMeasuredHeight(), 1073741824);
                                } else if (lp2.height == -2) {
                                    childHeightSpec = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, Integer.MIN_VALUE);
                                } else if (lp2.height == -1) {
                                    childHeightSpec = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, 1073741824);
                                } else {
                                    childHeightSpec = MeasureSpec.makeMeasureSpec(lp2.height, 1073741824);
                                }
                                if (canSlide) {
                                    int newWidth = widthAvailable - (lp2.leftMargin + lp2.rightMargin);
                                    fixedPanelWidthLimit = fixedPanelWidthLimit2;
                                    maxLayoutHeight = maxLayoutHeight2;
                                    int maxLayoutHeight3 = MeasureSpec.makeMeasureSpec(newWidth, 1073741824);
                                    if (measuredWidth2 != newWidth) {
                                        child2.measure(maxLayoutHeight3, childHeightSpec);
                                    }
                                } else {
                                    fixedPanelWidthLimit = fixedPanelWidthLimit2;
                                    maxLayoutHeight = maxLayoutHeight2;
                                    child2.measure(MeasureSpec.makeMeasureSpec(measuredWidth2 + ((int) ((lp2.weight * ((float) Math.max(0, widthRemaining))) / weightSum)), 1073741824), childHeightSpec);
                                }
                            } else {
                                fixedPanelWidthLimit = fixedPanelWidthLimit2;
                                maxLayoutHeight = maxLayoutHeight2;
                            }
                        } else if (lp2.width < 0) {
                            if (measuredWidth <= fixedPanelWidthLimit2) {
                                heightMode = heightMode2;
                                if (lp2.weight <= 0.0f) {
                                    fixedPanelWidthLimit = fixedPanelWidthLimit2;
                                    maxLayoutHeight = maxLayoutHeight2;
                                    childCount = childCount2;
                                }
                            } else {
                                heightMode = heightMode2;
                            }
                            if (skippedFirstPass) {
                                childCount = childCount2;
                                if (lp2.height == -2) {
                                    childHeightSpec2 = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, Integer.MIN_VALUE);
                                    i2 = 1073741824;
                                } else if (lp2.height == -1) {
                                    i2 = 1073741824;
                                    childHeightSpec2 = MeasureSpec.makeMeasureSpec(maxLayoutHeight2, 1073741824);
                                } else {
                                    i2 = 1073741824;
                                    childHeightSpec2 = MeasureSpec.makeMeasureSpec(lp2.height, 1073741824);
                                }
                            } else {
                                childCount = childCount2;
                                i2 = 1073741824;
                                childHeightSpec2 = MeasureSpec.makeMeasureSpec(child2.getMeasuredHeight(), 1073741824);
                            }
                            boolean z3 = skippedFirstPass;
                            child2.measure(MeasureSpec.makeMeasureSpec(fixedPanelWidthLimit2, i2), childHeightSpec2);
                            fixedPanelWidthLimit = fixedPanelWidthLimit2;
                            maxLayoutHeight = maxLayoutHeight2;
                        } else {
                            childCount = childCount2;
                            boolean z4 = skippedFirstPass;
                            int i8 = measuredWidth;
                            heightMode = heightMode2;
                            fixedPanelWidthLimit = fixedPanelWidthLimit2;
                            maxLayoutHeight = maxLayoutHeight2;
                        }
                    }
                }
                i7++;
                heightMode2 = heightMode;
                childCount2 = childCount;
                fixedPanelWidthLimit2 = fixedPanelWidthLimit;
                maxLayoutHeight2 = maxLayoutHeight;
                i = 8;
            }
            int i9 = heightMode2;
            int i10 = maxLayoutHeight2;
            int i11 = childCount2;
        } else {
            int i12 = heightMode2;
            int i13 = maxLayoutHeight2;
            int i14 = childCount2;
        }
        setMeasuredDimension(widthSize, getPaddingTop() + layoutHeight + getPaddingBottom());
        this.mCanSlide = canSlide;
        if (this.mDragHelper.getViewDragState() != 0 && !canSlide) {
            this.mDragHelper.abort();
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int l, int t, int r, int b) {
        int paddingStart;
        int childLeft;
        int childRight;
        boolean isLayoutRtl = isLayoutRtlSupport();
        if (isLayoutRtl) {
            this.mDragHelper.setEdgeTrackingEnabled(2);
        } else {
            this.mDragHelper.setEdgeTrackingEnabled(1);
        }
        int width = r - l;
        int paddingStart2 = isLayoutRtl ? getPaddingRight() : getPaddingLeft();
        int paddingEnd = isLayoutRtl ? getPaddingLeft() : getPaddingRight();
        int paddingTop = getPaddingTop();
        int childCount = getChildCount();
        int xStart = paddingStart2;
        int nextXStart = xStart;
        if (this.mFirstLayout) {
            this.mSlideOffset = (!this.mCanSlide || !this.mPreservedOpenState) ? 0.0f : 1.0f;
        }
        int i = 0;
        while (i < childCount) {
            View child = getChildAt(i);
            if (child.getVisibility() == 8) {
                paddingStart = paddingStart2;
            } else {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                int childWidth = child.getMeasuredWidth();
                int offset = 0;
                if (lp.slideable) {
                    int margin = lp.leftMargin + lp.rightMargin;
                    int range = (Math.min(nextXStart, (width - paddingEnd) - this.mOverhangSize) - xStart) - margin;
                    this.mSlideRange = range;
                    int lpMargin = isLayoutRtl ? lp.rightMargin : lp.leftMargin;
                    paddingStart = paddingStart2;
                    int i2 = margin;
                    lp.dimWhenOffset = ((xStart + lpMargin) + range) + (childWidth / 2) > width - paddingEnd;
                    int pos = (int) (((float) range) * this.mSlideOffset);
                    xStart += pos + lpMargin;
                    LayoutParams layoutParams = lp;
                    this.mSlideOffset = ((float) pos) / ((float) this.mSlideRange);
                } else {
                    paddingStart = paddingStart2;
                    if (this.mCanSlide) {
                        int i3 = this.mParallaxBy;
                        if (i3 != 0) {
                            xStart = nextXStart;
                            offset = (int) ((1.0f - this.mSlideOffset) * ((float) i3));
                        }
                    }
                    xStart = nextXStart;
                }
                if (isLayoutRtl) {
                    childRight = (width - xStart) + offset;
                    childLeft = childRight - childWidth;
                } else {
                    childLeft = xStart - offset;
                    childRight = childLeft + childWidth;
                }
                child.layout(childLeft, paddingTop, childRight, child.getMeasuredHeight() + paddingTop);
                nextXStart += child.getWidth();
            }
            i++;
            paddingStart2 = paddingStart;
        }
        if (this.mFirstLayout) {
            if (this.mCanSlide) {
                if (this.mParallaxBy != 0) {
                    parallaxOtherViews(this.mSlideOffset);
                }
                if (((LayoutParams) this.mSlideableView.getLayoutParams()).dimWhenOffset) {
                    dimChildView(this.mSlideableView, this.mSlideOffset, this.mSliderFadeColor);
                }
            } else {
                for (int i4 = 0; i4 < childCount; i4++) {
                    dimChildView(getChildAt(i4), 0.0f, this.mSliderFadeColor);
                }
            }
            updateObscuredViewsVisibility(this.mSlideableView);
        }
        this.mFirstLayout = false;
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (w != oldw) {
            this.mFirstLayout = true;
        }
    }

    public void requestChildFocus(View child, View focused) {
        super.requestChildFocus(child, focused);
        if (!isInTouchMode() && !this.mCanSlide) {
            this.mPreservedOpenState = child == this.mSlideableView;
        }
    }

    public boolean onInterceptTouchEvent(MotionEvent ev) {
        int action = ev.getActionMasked();
        boolean z = true;
        if (!this.mCanSlide && action == 0 && getChildCount() > 1) {
            View secondChild = getChildAt(1);
            if (secondChild != null) {
                this.mPreservedOpenState = !this.mDragHelper.isViewUnder(secondChild, (int) ev.getX(), (int) ev.getY());
            }
        }
        if (!this.mCanSlide || (this.mIsUnableToDrag && action != 0)) {
            this.mDragHelper.cancel();
            return super.onInterceptTouchEvent(ev);
        } else if (action == 3 || action == 1) {
            this.mDragHelper.cancel();
            return false;
        } else {
            boolean interceptTap = false;
            if (action == 0) {
                this.mIsUnableToDrag = false;
                float x = ev.getX();
                float y = ev.getY();
                this.mInitialMotionX = x;
                this.mInitialMotionY = y;
                if (this.mDragHelper.isViewUnder(this.mSlideableView, (int) x, (int) y) && isDimmed(this.mSlideableView)) {
                    interceptTap = true;
                }
            } else if (action == 2) {
                float x2 = ev.getX();
                float y2 = ev.getY();
                float adx = Math.abs(x2 - this.mInitialMotionX);
                float ady = Math.abs(y2 - this.mInitialMotionY);
                if (adx > ((float) this.mDragHelper.getTouchSlop()) && ady > adx) {
                    this.mDragHelper.cancel();
                    this.mIsUnableToDrag = true;
                    return false;
                }
            }
            if (!this.mDragHelper.shouldInterceptTouchEvent(ev) && !interceptTap) {
                z = false;
            }
            return z;
        }
    }

    public boolean onTouchEvent(MotionEvent ev) {
        if (!this.mCanSlide) {
            return super.onTouchEvent(ev);
        }
        this.mDragHelper.processTouchEvent(ev);
        int actionMasked = ev.getActionMasked();
        if (actionMasked == 0) {
            float x = ev.getX();
            float y = ev.getY();
            this.mInitialMotionX = x;
            this.mInitialMotionY = y;
        } else if (actionMasked == 1 && isDimmed(this.mSlideableView)) {
            float x2 = ev.getX();
            float y2 = ev.getY();
            float dx = x2 - this.mInitialMotionX;
            float dy = y2 - this.mInitialMotionY;
            int slop = this.mDragHelper.getTouchSlop();
            if ((dx * dx) + (dy * dy) < ((float) (slop * slop)) && this.mDragHelper.isViewUnder(this.mSlideableView, (int) x2, (int) y2)) {
                closePane(this.mSlideableView, 0);
            }
        }
        return true;
    }

    private boolean closePane(View pane, int initialVelocity) {
        if (!this.mFirstLayout && !smoothSlideTo(0.0f, initialVelocity)) {
            return false;
        }
        this.mPreservedOpenState = false;
        return true;
    }

    private boolean openPane(View pane, int initialVelocity) {
        if (!this.mFirstLayout && !smoothSlideTo(1.0f, initialVelocity)) {
            return false;
        }
        this.mPreservedOpenState = true;
        return true;
    }

    @Deprecated
    public void smoothSlideOpen() {
        openPane();
    }

    public boolean openPane() {
        return openPane(this.mSlideableView, 0);
    }

    @Deprecated
    public void smoothSlideClosed() {
        closePane();
    }

    public boolean closePane() {
        return closePane(this.mSlideableView, 0);
    }

    public boolean isOpen() {
        return !this.mCanSlide || this.mSlideOffset == 1.0f;
    }

    @Deprecated
    public boolean canSlide() {
        return this.mCanSlide;
    }

    public boolean isSlideable() {
        return this.mCanSlide;
    }

    /* access modifiers changed from: 0000 */
    public void onPanelDragged(int newLeft) {
        if (this.mSlideableView == null) {
            this.mSlideOffset = 0.0f;
            return;
        }
        boolean isLayoutRtl = isLayoutRtlSupport();
        LayoutParams lp = (LayoutParams) this.mSlideableView.getLayoutParams();
        float width = ((float) ((isLayoutRtl ? (getWidth() - newLeft) - this.mSlideableView.getWidth() : newLeft) - ((isLayoutRtl ? getPaddingRight() : getPaddingLeft()) + (isLayoutRtl ? lp.rightMargin : lp.leftMargin)))) / ((float) this.mSlideRange);
        this.mSlideOffset = width;
        if (this.mParallaxBy != 0) {
            parallaxOtherViews(width);
        }
        if (lp.dimWhenOffset) {
            dimChildView(this.mSlideableView, this.mSlideOffset, this.mSliderFadeColor);
        }
        dispatchOnPanelSlide(this.mSlideableView);
    }

    private void dimChildView(View v, float mag, int fadeColor) {
        LayoutParams lp = (LayoutParams) v.getLayoutParams();
        if (mag > 0.0f && fadeColor != 0) {
            int color = (((int) (((float) ((-16777216 & fadeColor) >>> 24)) * mag)) << 24) | (16777215 & fadeColor);
            if (lp.dimPaint == null) {
                lp.dimPaint = new Paint();
            }
            lp.dimPaint.setColorFilter(new PorterDuffColorFilter(color, Mode.SRC_OVER));
            if (v.getLayerType() != 2) {
                v.setLayerType(2, lp.dimPaint);
            }
            invalidateChildRegion(v);
        } else if (v.getLayerType() != 0) {
            if (lp.dimPaint != null) {
                lp.dimPaint.setColorFilter(null);
            }
            DisableLayerRunnable dlr = new DisableLayerRunnable(v);
            this.mPostedRunnables.add(dlr);
            ViewCompat.postOnAnimation(this, dlr);
        }
    }

    /* access modifiers changed from: protected */
    public boolean drawChild(Canvas canvas, View child, long drawingTime) {
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        int save = canvas.save();
        if (this.mCanSlide && !lp.slideable && this.mSlideableView != null) {
            canvas.getClipBounds(this.mTmpRect);
            if (isLayoutRtlSupport()) {
                Rect rect = this.mTmpRect;
                rect.left = Math.max(rect.left, this.mSlideableView.getRight());
            } else {
                Rect rect2 = this.mTmpRect;
                rect2.right = Math.min(rect2.right, this.mSlideableView.getLeft());
            }
            canvas.clipRect(this.mTmpRect);
        }
        boolean result = super.drawChild(canvas, child, drawingTime);
        canvas.restoreToCount(save);
        return result;
    }

    /* access modifiers changed from: 0000 */
    public void invalidateChildRegion(View v) {
        if (VERSION.SDK_INT >= 17) {
            ViewCompat.setLayerPaint(v, ((LayoutParams) v.getLayoutParams()).dimPaint);
            return;
        }
        if (VERSION.SDK_INT >= 16) {
            boolean z = this.mDisplayListReflectionLoaded;
            String str = TAG;
            if (!z) {
                try {
                    this.mGetDisplayList = View.class.getDeclaredMethod("getDisplayList", null);
                } catch (NoSuchMethodException e) {
                    Log.e(str, "Couldn't fetch getDisplayList method; dimming won't work right.", e);
                }
                try {
                    Field declaredField = View.class.getDeclaredField("mRecreateDisplayList");
                    this.mRecreateDisplayList = declaredField;
                    declaredField.setAccessible(true);
                } catch (NoSuchFieldException e2) {
                    Log.e(str, "Couldn't fetch mRecreateDisplayList field; dimming will be slow.", e2);
                }
                this.mDisplayListReflectionLoaded = true;
            }
            if (this.mGetDisplayList != null) {
                Field field = this.mRecreateDisplayList;
                if (field != null) {
                    try {
                        field.setBoolean(v, true);
                        this.mGetDisplayList.invoke(v, null);
                    } catch (Exception e3) {
                        Log.e(str, "Error refreshing display list state", e3);
                    }
                }
            }
            v.invalidate();
            return;
        }
        ViewCompat.postInvalidateOnAnimation(this, v.getLeft(), v.getTop(), v.getRight(), v.getBottom());
    }

    /* access modifiers changed from: 0000 */
    public boolean smoothSlideTo(float slideOffset, int velocity) {
        int startBound;
        if (!this.mCanSlide) {
            return false;
        }
        LayoutParams lp = (LayoutParams) this.mSlideableView.getLayoutParams();
        if (isLayoutRtlSupport()) {
            startBound = (int) (((float) getWidth()) - ((((float) (getPaddingRight() + lp.rightMargin)) + (((float) this.mSlideRange) * slideOffset)) + ((float) this.mSlideableView.getWidth())));
        } else {
            startBound = (int) (((float) (getPaddingLeft() + lp.leftMargin)) + (((float) this.mSlideRange) * slideOffset));
        }
        ViewDragHelper viewDragHelper = this.mDragHelper;
        View view = this.mSlideableView;
        if (!viewDragHelper.smoothSlideViewTo(view, startBound, view.getTop())) {
            return false;
        }
        setAllChildrenVisible();
        ViewCompat.postInvalidateOnAnimation(this);
        return true;
    }

    public void computeScroll() {
        if (this.mDragHelper.continueSettling(true)) {
            if (!this.mCanSlide) {
                this.mDragHelper.abort();
                return;
            }
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    @Deprecated
    public void setShadowDrawable(Drawable d) {
        setShadowDrawableLeft(d);
    }

    public void setShadowDrawableLeft(Drawable d) {
        this.mShadowDrawableLeft = d;
    }

    public void setShadowDrawableRight(Drawable d) {
        this.mShadowDrawableRight = d;
    }

    @Deprecated
    public void setShadowResource(int resId) {
        setShadowDrawable(getResources().getDrawable(resId));
    }

    public void setShadowResourceLeft(int resId) {
        setShadowDrawableLeft(ContextCompat.getDrawable(getContext(), resId));
    }

    public void setShadowResourceRight(int resId) {
        setShadowDrawableRight(ContextCompat.getDrawable(getContext(), resId));
    }

    public void draw(Canvas c) {
        Drawable shadowDrawable;
        int right;
        int left;
        super.draw(c);
        if (isLayoutRtlSupport()) {
            shadowDrawable = this.mShadowDrawableRight;
        } else {
            shadowDrawable = this.mShadowDrawableLeft;
        }
        View shadowView = getChildCount() > 1 ? getChildAt(1) : null;
        if (shadowView != null && shadowDrawable != null) {
            int top = shadowView.getTop();
            int bottom = shadowView.getBottom();
            int shadowWidth = shadowDrawable.getIntrinsicWidth();
            if (isLayoutRtlSupport()) {
                left = shadowView.getRight();
                right = left + shadowWidth;
            } else {
                right = shadowView.getLeft();
                left = right - shadowWidth;
            }
            shadowDrawable.setBounds(left, top, right, bottom);
            shadowDrawable.draw(c);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:10:0x0023  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void parallaxOtherViews(float r12) {
        /*
            r11 = this;
            boolean r0 = r11.isLayoutRtlSupport()
            android.view.View r1 = r11.mSlideableView
            android.view.ViewGroup$LayoutParams r1 = r1.getLayoutParams()
            androidx.slidingpanelayout.widget.SlidingPaneLayout$LayoutParams r1 = (androidx.slidingpanelayout.widget.SlidingPaneLayout.LayoutParams) r1
            boolean r2 = r1.dimWhenOffset
            if (r2 == 0) goto L_0x001b
            if (r0 == 0) goto L_0x0015
            int r2 = r1.rightMargin
            goto L_0x0017
        L_0x0015:
            int r2 = r1.leftMargin
        L_0x0017:
            if (r2 > 0) goto L_0x001b
            r2 = 1
            goto L_0x001c
        L_0x001b:
            r2 = 0
        L_0x001c:
            int r3 = r11.getChildCount()
            r4 = 0
        L_0x0021:
            if (r4 >= r3) goto L_0x005a
            android.view.View r5 = r11.getChildAt(r4)
            android.view.View r6 = r11.mSlideableView
            if (r5 != r6) goto L_0x002c
            goto L_0x0057
        L_0x002c:
            float r6 = r11.mParallaxOffset
            r7 = 1065353216(0x3f800000, float:1.0)
            float r6 = r7 - r6
            int r8 = r11.mParallaxBy
            float r9 = (float) r8
            float r6 = r6 * r9
            int r6 = (int) r6
            r11.mParallaxOffset = r12
            float r9 = r7 - r12
            float r8 = (float) r8
            float r9 = r9 * r8
            int r8 = (int) r9
            int r9 = r6 - r8
            if (r0 == 0) goto L_0x0044
            int r10 = -r9
            goto L_0x0045
        L_0x0044:
            r10 = r9
        L_0x0045:
            r5.offsetLeftAndRight(r10)
            if (r2 == 0) goto L_0x0057
            float r10 = r11.mParallaxOffset
            if (r0 == 0) goto L_0x0050
            float r10 = r10 - r7
            goto L_0x0052
        L_0x0050:
            float r10 = r7 - r10
        L_0x0052:
            int r7 = r11.mCoveredFadeColor
            r11.dimChildView(r5, r10, r7)
        L_0x0057:
            int r4 = r4 + 1
            goto L_0x0021
        L_0x005a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.slidingpanelayout.widget.SlidingPaneLayout.parallaxOtherViews(float):void");
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x006f, code lost:
        if (r15.canScrollHorizontally(isLayoutRtlSupport() ? r17 : -r17) != false) goto L_0x0075;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean canScroll(android.view.View r15, boolean r16, int r17, int r18, int r19) {
        /*
            r14 = this;
            r0 = r15
            boolean r1 = r0 instanceof android.view.ViewGroup
            r2 = 1
            if (r1 == 0) goto L_0x005c
            r1 = r0
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
            int r3 = r15.getScrollX()
            int r4 = r15.getScrollY()
            int r5 = r1.getChildCount()
            int r6 = r5 + -1
        L_0x0017:
            if (r6 < 0) goto L_0x005c
            android.view.View r13 = r1.getChildAt(r6)
            int r7 = r18 + r3
            int r8 = r13.getLeft()
            if (r7 < r8) goto L_0x0059
            int r7 = r18 + r3
            int r8 = r13.getRight()
            if (r7 >= r8) goto L_0x0059
            int r7 = r19 + r4
            int r8 = r13.getTop()
            if (r7 < r8) goto L_0x0059
            int r7 = r19 + r4
            int r8 = r13.getBottom()
            if (r7 >= r8) goto L_0x0059
            r9 = 1
            int r7 = r18 + r3
            int r8 = r13.getLeft()
            int r11 = r7 - r8
            int r7 = r19 + r4
            int r8 = r13.getTop()
            int r12 = r7 - r8
            r7 = r14
            r8 = r13
            r10 = r17
            boolean r7 = r7.canScroll(r8, r9, r10, r11, r12)
            if (r7 == 0) goto L_0x0059
            return r2
        L_0x0059:
            int r6 = r6 + -1
            goto L_0x0017
        L_0x005c:
            if (r16 == 0) goto L_0x0072
            boolean r1 = r14.isLayoutRtlSupport()
            if (r1 == 0) goto L_0x0068
            r1 = r17
            r3 = r1
            goto L_0x006b
        L_0x0068:
            r1 = r17
            int r3 = -r1
        L_0x006b:
            boolean r3 = r15.canScrollHorizontally(r3)
            if (r3 == 0) goto L_0x0074
            goto L_0x0075
        L_0x0072:
            r1 = r17
        L_0x0074:
            r2 = 0
        L_0x0075:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.slidingpanelayout.widget.SlidingPaneLayout.canScroll(android.view.View, boolean, int, int, int):boolean");
    }

    /* access modifiers changed from: 0000 */
    public boolean isDimmed(View child) {
        boolean z = false;
        if (child == null) {
            return false;
        }
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        if (this.mCanSlide && lp.dimWhenOffset && this.mSlideOffset > 0.0f) {
            z = true;
        }
        return z;
    }

    /* access modifiers changed from: protected */
    public android.view.ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams();
    }

    /* access modifiers changed from: protected */
    public android.view.ViewGroup.LayoutParams generateLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return p instanceof MarginLayoutParams ? new LayoutParams((MarginLayoutParams) p) : new LayoutParams(p);
    }

    /* access modifiers changed from: protected */
    public boolean checkLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return (p instanceof LayoutParams) && super.checkLayoutParams(p);
    }

    public android.view.ViewGroup.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    /* access modifiers changed from: protected */
    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        ss.isOpen = isSlideable() ? isOpen() : this.mPreservedOpenState;
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
        if (ss.isOpen) {
            openPane();
        } else {
            closePane();
        }
        this.mPreservedOpenState = ss.isOpen;
    }

    /* access modifiers changed from: 0000 */
    public boolean isLayoutRtlSupport() {
        return ViewCompat.getLayoutDirection(this) == 1;
    }
}
