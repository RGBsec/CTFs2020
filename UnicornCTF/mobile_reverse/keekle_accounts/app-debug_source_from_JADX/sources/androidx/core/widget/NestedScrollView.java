package androidx.core.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.View.BaseSavedState;
import android.view.View.MeasureSpec;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.animation.AnimationUtils;
import android.widget.EdgeEffect;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.OverScroller;
import android.widget.ScrollView;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.NestedScrollingChild3;
import androidx.core.view.NestedScrollingChildHelper;
import androidx.core.view.NestedScrollingParent3;
import androidx.core.view.NestedScrollingParentHelper;
import androidx.core.view.ScrollingView;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityRecordCompat;
import java.util.List;

public class NestedScrollView extends FrameLayout implements NestedScrollingParent3, NestedScrollingChild3, ScrollingView {
    private static final AccessibilityDelegate ACCESSIBILITY_DELEGATE = new AccessibilityDelegate();
    static final int ANIMATED_SCROLL_GAP = 250;
    private static final int INVALID_POINTER = -1;
    static final float MAX_SCROLL_FACTOR = 0.5f;
    private static final int[] SCROLLVIEW_STYLEABLE = {16843130};
    private static final String TAG = "NestedScrollView";
    private int mActivePointerId;
    private final NestedScrollingChildHelper mChildHelper;
    private View mChildToScrollTo;
    private EdgeEffect mEdgeGlowBottom;
    private EdgeEffect mEdgeGlowTop;
    private boolean mFillViewport;
    private boolean mIsBeingDragged;
    private boolean mIsLaidOut;
    private boolean mIsLayoutDirty;
    private int mLastMotionY;
    private long mLastScroll;
    private int mLastScrollerY;
    private int mMaximumVelocity;
    private int mMinimumVelocity;
    private int mNestedYOffset;
    private OnScrollChangeListener mOnScrollChangeListener;
    private final NestedScrollingParentHelper mParentHelper;
    private SavedState mSavedState;
    private final int[] mScrollConsumed;
    private final int[] mScrollOffset;
    private OverScroller mScroller;
    private boolean mSmoothScrollingEnabled;
    private final Rect mTempRect;
    private int mTouchSlop;
    private VelocityTracker mVelocityTracker;
    private float mVerticalScrollFactor;

    static class AccessibilityDelegate extends AccessibilityDelegateCompat {
        AccessibilityDelegate() {
        }

        public boolean performAccessibilityAction(View host, int action, Bundle arguments) {
            if (super.performAccessibilityAction(host, action, arguments)) {
                return true;
            }
            NestedScrollView nsvHost = (NestedScrollView) host;
            if (!nsvHost.isEnabled()) {
                return false;
            }
            if (action == 4096) {
                int targetScrollY = Math.min(nsvHost.getScrollY() + ((nsvHost.getHeight() - nsvHost.getPaddingBottom()) - nsvHost.getPaddingTop()), nsvHost.getScrollRange());
                if (targetScrollY == nsvHost.getScrollY()) {
                    return false;
                }
                nsvHost.smoothScrollTo(0, targetScrollY);
                return true;
            } else if (action != 8192) {
                return false;
            } else {
                int targetScrollY2 = Math.max(nsvHost.getScrollY() - ((nsvHost.getHeight() - nsvHost.getPaddingBottom()) - nsvHost.getPaddingTop()), 0);
                if (targetScrollY2 == nsvHost.getScrollY()) {
                    return false;
                }
                nsvHost.smoothScrollTo(0, targetScrollY2);
                return true;
            }
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            NestedScrollView nsvHost = (NestedScrollView) host;
            info.setClassName(ScrollView.class.getName());
            if (nsvHost.isEnabled()) {
                int scrollRange = nsvHost.getScrollRange();
                if (scrollRange > 0) {
                    info.setScrollable(true);
                    if (nsvHost.getScrollY() > 0) {
                        info.addAction(8192);
                    }
                    if (nsvHost.getScrollY() < scrollRange) {
                        info.addAction(4096);
                    }
                }
            }
        }

        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(host, event);
            NestedScrollView nsvHost = (NestedScrollView) host;
            event.setClassName(ScrollView.class.getName());
            event.setScrollable(nsvHost.getScrollRange() > 0);
            event.setScrollX(nsvHost.getScrollX());
            event.setScrollY(nsvHost.getScrollY());
            AccessibilityRecordCompat.setMaxScrollX(event, nsvHost.getScrollX());
            AccessibilityRecordCompat.setMaxScrollY(event, nsvHost.getScrollRange());
        }
    }

    public interface OnScrollChangeListener {
        void onScrollChange(NestedScrollView nestedScrollView, int i, int i2, int i3, int i4);
    }

    static class SavedState extends BaseSavedState {
        public static final Creator<SavedState> CREATOR = new Creator<SavedState>() {
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        public int scrollPosition;

        SavedState(Parcelable superState) {
            super(superState);
        }

        SavedState(Parcel source) {
            super(source);
            this.scrollPosition = source.readInt();
        }

        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            dest.writeInt(this.scrollPosition);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("HorizontalScrollView.SavedState{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" scrollPosition=");
            sb.append(this.scrollPosition);
            sb.append("}");
            return sb.toString();
        }
    }

    public NestedScrollView(Context context) {
        this(context, null);
    }

    public NestedScrollView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public NestedScrollView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mTempRect = new Rect();
        this.mIsLayoutDirty = true;
        this.mIsLaidOut = false;
        this.mChildToScrollTo = null;
        this.mIsBeingDragged = false;
        this.mSmoothScrollingEnabled = true;
        this.mActivePointerId = -1;
        this.mScrollOffset = new int[2];
        this.mScrollConsumed = new int[2];
        initScrollView();
        TypedArray a = context.obtainStyledAttributes(attrs, SCROLLVIEW_STYLEABLE, defStyleAttr, 0);
        setFillViewport(a.getBoolean(0, false));
        a.recycle();
        this.mParentHelper = new NestedScrollingParentHelper(this);
        this.mChildHelper = new NestedScrollingChildHelper(this);
        setNestedScrollingEnabled(true);
        ViewCompat.setAccessibilityDelegate(this, ACCESSIBILITY_DELEGATE);
    }

    public void dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int[] offsetInWindow, int type, int[] consumed) {
        this.mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, offsetInWindow, type, consumed);
    }

    public boolean startNestedScroll(int axes, int type) {
        return this.mChildHelper.startNestedScroll(axes, type);
    }

    public void stopNestedScroll(int type) {
        this.mChildHelper.stopNestedScroll(type);
    }

    public boolean hasNestedScrollingParent(int type) {
        return this.mChildHelper.hasNestedScrollingParent(type);
    }

    public boolean dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int[] offsetInWindow, int type) {
        return this.mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, offsetInWindow, type);
    }

    public boolean dispatchNestedPreScroll(int dx, int dy, int[] consumed, int[] offsetInWindow, int type) {
        return this.mChildHelper.dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow, type);
    }

    public void setNestedScrollingEnabled(boolean enabled) {
        this.mChildHelper.setNestedScrollingEnabled(enabled);
    }

    public boolean isNestedScrollingEnabled() {
        return this.mChildHelper.isNestedScrollingEnabled();
    }

    public boolean startNestedScroll(int axes) {
        return startNestedScroll(axes, 0);
    }

    public void stopNestedScroll() {
        stopNestedScroll(0);
    }

    public boolean hasNestedScrollingParent() {
        return hasNestedScrollingParent(0);
    }

    public boolean dispatchNestedScroll(int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int[] offsetInWindow) {
        return this.mChildHelper.dispatchNestedScroll(dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, offsetInWindow);
    }

    public boolean dispatchNestedPreScroll(int dx, int dy, int[] consumed, int[] offsetInWindow) {
        return dispatchNestedPreScroll(dx, dy, consumed, offsetInWindow, 0);
    }

    public boolean dispatchNestedFling(float velocityX, float velocityY, boolean consumed) {
        return this.mChildHelper.dispatchNestedFling(velocityX, velocityY, consumed);
    }

    public boolean dispatchNestedPreFling(float velocityX, float velocityY) {
        return this.mChildHelper.dispatchNestedPreFling(velocityX, velocityY);
    }

    public void onNestedScroll(View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type, int[] consumed) {
        onNestedScrollInternal(dyUnconsumed, type, consumed);
    }

    private void onNestedScrollInternal(int dyUnconsumed, int type, int[] consumed) {
        int oldScrollY = getScrollY();
        scrollBy(0, dyUnconsumed);
        int myConsumed = getScrollY() - oldScrollY;
        if (consumed != null) {
            consumed[1] = consumed[1] + myConsumed;
        }
        this.mChildHelper.dispatchNestedScroll(0, myConsumed, 0, dyUnconsumed - myConsumed, null, type, consumed);
    }

    public boolean onStartNestedScroll(View child, View target, int axes, int type) {
        return (axes & 2) != 0;
    }

    public void onNestedScrollAccepted(View child, View target, int axes, int type) {
        this.mParentHelper.onNestedScrollAccepted(child, target, axes, type);
        startNestedScroll(2, type);
    }

    public void onStopNestedScroll(View target, int type) {
        this.mParentHelper.onStopNestedScroll(target, type);
        stopNestedScroll(type);
    }

    public void onNestedScroll(View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type) {
        onNestedScrollInternal(dyUnconsumed, type, null);
    }

    public void onNestedPreScroll(View target, int dx, int dy, int[] consumed, int type) {
        dispatchNestedPreScroll(dx, dy, consumed, null, type);
    }

    public boolean onStartNestedScroll(View child, View target, int nestedScrollAxes) {
        return onStartNestedScroll(child, target, nestedScrollAxes, 0);
    }

    public void onNestedScrollAccepted(View child, View target, int nestedScrollAxes) {
        onNestedScrollAccepted(child, target, nestedScrollAxes, 0);
    }

    public void onStopNestedScroll(View target) {
        onStopNestedScroll(target, 0);
    }

    public void onNestedScroll(View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed) {
        onNestedScrollInternal(dyUnconsumed, 0, null);
    }

    public void onNestedPreScroll(View target, int dx, int dy, int[] consumed) {
        onNestedPreScroll(target, dx, dy, consumed, 0);
    }

    public boolean onNestedFling(View target, float velocityX, float velocityY, boolean consumed) {
        if (consumed) {
            return false;
        }
        dispatchNestedFling(0.0f, velocityY, true);
        fling((int) velocityY);
        return true;
    }

    public boolean onNestedPreFling(View target, float velocityX, float velocityY) {
        return dispatchNestedPreFling(velocityX, velocityY);
    }

    public int getNestedScrollAxes() {
        return this.mParentHelper.getNestedScrollAxes();
    }

    public boolean shouldDelayChildPressedState() {
        return true;
    }

    /* access modifiers changed from: protected */
    public float getTopFadingEdgeStrength() {
        if (getChildCount() == 0) {
            return 0.0f;
        }
        int length = getVerticalFadingEdgeLength();
        int scrollY = getScrollY();
        if (scrollY < length) {
            return ((float) scrollY) / ((float) length);
        }
        return 1.0f;
    }

    /* access modifiers changed from: protected */
    public float getBottomFadingEdgeStrength() {
        if (getChildCount() == 0) {
            return 0.0f;
        }
        View child = getChildAt(0);
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        int length = getVerticalFadingEdgeLength();
        int span = ((child.getBottom() + lp.bottomMargin) - getScrollY()) - (getHeight() - getPaddingBottom());
        if (span < length) {
            return ((float) span) / ((float) length);
        }
        return 1.0f;
    }

    public int getMaxScrollAmount() {
        return (int) (((float) getHeight()) * MAX_SCROLL_FACTOR);
    }

    private void initScrollView() {
        this.mScroller = new OverScroller(getContext());
        setFocusable(true);
        setDescendantFocusability(262144);
        setWillNotDraw(false);
        ViewConfiguration configuration = ViewConfiguration.get(getContext());
        this.mTouchSlop = configuration.getScaledTouchSlop();
        this.mMinimumVelocity = configuration.getScaledMinimumFlingVelocity();
        this.mMaximumVelocity = configuration.getScaledMaximumFlingVelocity();
    }

    public void addView(View child) {
        if (getChildCount() <= 0) {
            super.addView(child);
            return;
        }
        throw new IllegalStateException("ScrollView can host only one direct child");
    }

    public void addView(View child, int index) {
        if (getChildCount() <= 0) {
            super.addView(child, index);
            return;
        }
        throw new IllegalStateException("ScrollView can host only one direct child");
    }

    public void addView(View child, ViewGroup.LayoutParams params) {
        if (getChildCount() <= 0) {
            super.addView(child, params);
            return;
        }
        throw new IllegalStateException("ScrollView can host only one direct child");
    }

    public void addView(View child, int index, ViewGroup.LayoutParams params) {
        if (getChildCount() <= 0) {
            super.addView(child, index, params);
            return;
        }
        throw new IllegalStateException("ScrollView can host only one direct child");
    }

    public void setOnScrollChangeListener(OnScrollChangeListener l) {
        this.mOnScrollChangeListener = l;
    }

    private boolean canScroll() {
        boolean z = false;
        if (getChildCount() <= 0) {
            return false;
        }
        View child = getChildAt(0);
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        if (child.getHeight() + lp.topMargin + lp.bottomMargin > (getHeight() - getPaddingTop()) - getPaddingBottom()) {
            z = true;
        }
        return z;
    }

    public boolean isFillViewport() {
        return this.mFillViewport;
    }

    public void setFillViewport(boolean fillViewport) {
        if (fillViewport != this.mFillViewport) {
            this.mFillViewport = fillViewport;
            requestLayout();
        }
    }

    public boolean isSmoothScrollingEnabled() {
        return this.mSmoothScrollingEnabled;
    }

    public void setSmoothScrollingEnabled(boolean smoothScrollingEnabled) {
        this.mSmoothScrollingEnabled = smoothScrollingEnabled;
    }

    /* access modifiers changed from: protected */
    public void onScrollChanged(int l, int t, int oldl, int oldt) {
        super.onScrollChanged(l, t, oldl, oldt);
        OnScrollChangeListener onScrollChangeListener = this.mOnScrollChangeListener;
        if (onScrollChangeListener != null) {
            onScrollChangeListener.onScrollChange(this, l, t, oldl, oldt);
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (this.mFillViewport && MeasureSpec.getMode(heightMeasureSpec) != 0 && getChildCount() > 0) {
            View child = getChildAt(0);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            int parentSpace = (((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom()) - lp.topMargin) - lp.bottomMargin;
            if (child.getMeasuredHeight() < parentSpace) {
                child.measure(getChildMeasureSpec(widthMeasureSpec, getPaddingLeft() + getPaddingRight() + lp.leftMargin + lp.rightMargin, lp.width), MeasureSpec.makeMeasureSpec(parentSpace, 1073741824));
            }
        }
    }

    public boolean dispatchKeyEvent(KeyEvent event) {
        return super.dispatchKeyEvent(event) || executeKeyEvent(event);
    }

    public boolean executeKeyEvent(KeyEvent event) {
        this.mTempRect.setEmpty();
        int i = 130;
        if (!canScroll()) {
            boolean z = false;
            if (!isFocused() || event.getKeyCode() == 4) {
                return false;
            }
            View currentFocused = findFocus();
            if (currentFocused == this) {
                currentFocused = null;
            }
            View nextFocused = FocusFinder.getInstance().findNextFocus(this, currentFocused, 130);
            if (!(nextFocused == null || nextFocused == this || !nextFocused.requestFocus(130))) {
                z = true;
            }
            return z;
        }
        boolean handled = false;
        if (event.getAction() == 0) {
            int keyCode = event.getKeyCode();
            if (keyCode == 19) {
                handled = !event.isAltPressed() ? arrowScroll(33) : fullScroll(33);
            } else if (keyCode == 20) {
                handled = !event.isAltPressed() ? arrowScroll(130) : fullScroll(130);
            } else if (keyCode == 62) {
                if (event.isShiftPressed()) {
                    i = 33;
                }
                pageScroll(i);
            }
        }
        return handled;
    }

    private boolean inChild(int x, int y) {
        boolean z = false;
        if (getChildCount() <= 0) {
            return false;
        }
        int scrollY = getScrollY();
        View child = getChildAt(0);
        if (y >= child.getTop() - scrollY && y < child.getBottom() - scrollY && x >= child.getLeft() && x < child.getRight()) {
            z = true;
        }
        return z;
    }

    private void initOrResetVelocityTracker() {
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        } else {
            velocityTracker.clear();
        }
    }

    private void initVelocityTrackerIfNotExists() {
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        }
    }

    private void recycleVelocityTracker() {
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.mVelocityTracker = null;
        }
    }

    public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
        if (disallowIntercept) {
            recycleVelocityTracker();
        }
        super.requestDisallowInterceptTouchEvent(disallowIntercept);
    }

    public boolean onInterceptTouchEvent(MotionEvent ev) {
        MotionEvent motionEvent = ev;
        int action = ev.getAction();
        if (action == 2 && this.mIsBeingDragged) {
            return true;
        }
        int i = action & 255;
        if (i != 0) {
            if (i != 1) {
                if (i == 2) {
                    int activePointerId = this.mActivePointerId;
                    if (activePointerId != -1) {
                        int pointerIndex = motionEvent.findPointerIndex(activePointerId);
                        if (pointerIndex == -1) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("Invalid pointerId=");
                            sb.append(activePointerId);
                            sb.append(" in onInterceptTouchEvent");
                            Log.e(TAG, sb.toString());
                        } else {
                            int y = (int) motionEvent.getY(pointerIndex);
                            if (Math.abs(y - this.mLastMotionY) > this.mTouchSlop && (2 & getNestedScrollAxes()) == 0) {
                                this.mIsBeingDragged = true;
                                this.mLastMotionY = y;
                                initVelocityTrackerIfNotExists();
                                this.mVelocityTracker.addMovement(motionEvent);
                                this.mNestedYOffset = 0;
                                ViewParent parent = getParent();
                                if (parent != null) {
                                    parent.requestDisallowInterceptTouchEvent(true);
                                }
                            }
                        }
                    }
                } else if (i != 3) {
                    if (i == 6) {
                        onSecondaryPointerUp(ev);
                    }
                }
            }
            this.mIsBeingDragged = false;
            this.mActivePointerId = -1;
            recycleVelocityTracker();
            if (this.mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                ViewCompat.postInvalidateOnAnimation(this);
            }
            stopNestedScroll(0);
        } else {
            int y2 = (int) ev.getY();
            if (!inChild((int) ev.getX(), y2)) {
                this.mIsBeingDragged = false;
                recycleVelocityTracker();
            } else {
                this.mLastMotionY = y2;
                this.mActivePointerId = motionEvent.getPointerId(0);
                initOrResetVelocityTracker();
                this.mVelocityTracker.addMovement(motionEvent);
                this.mScroller.computeScrollOffset();
                this.mIsBeingDragged = true ^ this.mScroller.isFinished();
                startNestedScroll(2, 0);
            }
        }
        return this.mIsBeingDragged;
    }

    public boolean onTouchEvent(MotionEvent ev) {
        int deltaY;
        MotionEvent motionEvent = ev;
        initVelocityTrackerIfNotExists();
        int actionMasked = ev.getActionMasked();
        if (actionMasked == 0) {
            this.mNestedYOffset = 0;
        }
        MotionEvent vtev = MotionEvent.obtain(ev);
        vtev.offsetLocation(0.0f, (float) this.mNestedYOffset);
        if (actionMasked != 0) {
            if (actionMasked == 1) {
                VelocityTracker velocityTracker = this.mVelocityTracker;
                velocityTracker.computeCurrentVelocity(1000, (float) this.mMaximumVelocity);
                int initialVelocity = (int) velocityTracker.getYVelocity(this.mActivePointerId);
                if (Math.abs(initialVelocity) <= this.mMinimumVelocity) {
                    if (this.mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                        ViewCompat.postInvalidateOnAnimation(this);
                    }
                } else if (!dispatchNestedPreFling(0.0f, (float) (-initialVelocity))) {
                    dispatchNestedFling(0.0f, (float) (-initialVelocity), true);
                    fling(-initialVelocity);
                }
                this.mActivePointerId = -1;
                endDrag();
            } else if (actionMasked == 2) {
                int activePointerIndex = motionEvent.findPointerIndex(this.mActivePointerId);
                if (activePointerIndex == -1) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Invalid pointerId=");
                    sb.append(this.mActivePointerId);
                    sb.append(" in onTouchEvent");
                    Log.e(TAG, sb.toString());
                } else {
                    int y = (int) motionEvent.getY(activePointerIndex);
                    int deltaY2 = this.mLastMotionY - y;
                    if (dispatchNestedPreScroll(0, deltaY2, this.mScrollConsumed, this.mScrollOffset, 0)) {
                        deltaY2 -= this.mScrollConsumed[1];
                        this.mNestedYOffset += this.mScrollOffset[1];
                    }
                    if (this.mIsBeingDragged || Math.abs(deltaY2) <= this.mTouchSlop) {
                        deltaY = deltaY2;
                    } else {
                        ViewParent parent = getParent();
                        if (parent != null) {
                            parent.requestDisallowInterceptTouchEvent(true);
                        }
                        this.mIsBeingDragged = true;
                        if (deltaY2 > 0) {
                            deltaY = deltaY2 - this.mTouchSlop;
                        } else {
                            deltaY = deltaY2 + this.mTouchSlop;
                        }
                    }
                    if (this.mIsBeingDragged) {
                        this.mLastMotionY = y - this.mScrollOffset[1];
                        int oldY = getScrollY();
                        int range = getScrollRange();
                        int overscrollMode = getOverScrollMode();
                        boolean canOverscroll = overscrollMode == 0 || (overscrollMode == 1 && range > 0);
                        int i = overscrollMode;
                        int range2 = range;
                        int i2 = y;
                        int activePointerIndex2 = activePointerIndex;
                        if (overScrollByCompat(0, deltaY, 0, getScrollY(), 0, range, 0, 0, true) && !hasNestedScrollingParent(0)) {
                            this.mVelocityTracker.clear();
                        }
                        int scrolledDeltaY = getScrollY() - oldY;
                        int unconsumedY = deltaY - scrolledDeltaY;
                        int[] iArr = this.mScrollConsumed;
                        iArr[1] = 0;
                        dispatchNestedScroll(0, scrolledDeltaY, 0, unconsumedY, this.mScrollOffset, 0, iArr);
                        int i3 = this.mLastMotionY;
                        int[] iArr2 = this.mScrollOffset;
                        this.mLastMotionY = i3 - iArr2[1];
                        this.mNestedYOffset += iArr2[1];
                        if (canOverscroll) {
                            int deltaY3 = deltaY - this.mScrollConsumed[1];
                            ensureGlows();
                            int pulledToY = oldY + deltaY3;
                            if (pulledToY < 0) {
                                EdgeEffectCompat.onPull(this.mEdgeGlowTop, ((float) deltaY3) / ((float) getHeight()), motionEvent.getX(activePointerIndex2) / ((float) getWidth()));
                                if (!this.mEdgeGlowBottom.isFinished()) {
                                    this.mEdgeGlowBottom.onRelease();
                                    int i4 = range2;
                                } else {
                                    int i5 = range2;
                                }
                            } else {
                                int activePointerIndex3 = activePointerIndex2;
                                if (pulledToY > range2) {
                                    EdgeEffectCompat.onPull(this.mEdgeGlowBottom, ((float) deltaY3) / ((float) getHeight()), 1.0f - (motionEvent.getX(activePointerIndex3) / ((float) getWidth())));
                                    if (!this.mEdgeGlowTop.isFinished()) {
                                        this.mEdgeGlowTop.onRelease();
                                    }
                                }
                            }
                            EdgeEffect edgeEffect = this.mEdgeGlowTop;
                            if (edgeEffect != null && (!edgeEffect.isFinished() || !this.mEdgeGlowBottom.isFinished())) {
                                ViewCompat.postInvalidateOnAnimation(this);
                            }
                            int i6 = deltaY3;
                        } else {
                            int i7 = range2;
                            int i8 = activePointerIndex2;
                        }
                    } else {
                        int i9 = activePointerIndex;
                    }
                }
            } else if (actionMasked == 3) {
                if (this.mIsBeingDragged != 0 && getChildCount() > 0 && this.mScroller.springBack(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                    ViewCompat.postInvalidateOnAnimation(this);
                }
                this.mActivePointerId = -1;
                endDrag();
            } else if (actionMasked == 5) {
                int index = ev.getActionIndex();
                this.mLastMotionY = (int) motionEvent.getY(index);
                this.mActivePointerId = motionEvent.getPointerId(index);
            } else if (actionMasked == 6) {
                onSecondaryPointerUp(ev);
                this.mLastMotionY = (int) motionEvent.getY(motionEvent.findPointerIndex(this.mActivePointerId));
            }
        } else if (getChildCount() == 0) {
            return false;
        } else {
            boolean z = !this.mScroller.isFinished();
            this.mIsBeingDragged = z;
            if (z) {
                ViewParent parent2 = getParent();
                if (parent2 != null) {
                    parent2.requestDisallowInterceptTouchEvent(true);
                }
            }
            if (!this.mScroller.isFinished()) {
                abortAnimatedScroll();
            }
            this.mLastMotionY = (int) ev.getY();
            this.mActivePointerId = motionEvent.getPointerId(0);
            startNestedScroll(2, 0);
        }
        VelocityTracker velocityTracker2 = this.mVelocityTracker;
        if (velocityTracker2 != null) {
            velocityTracker2.addMovement(vtev);
        }
        vtev.recycle();
        return true;
    }

    private void onSecondaryPointerUp(MotionEvent ev) {
        int pointerIndex = ev.getActionIndex();
        if (ev.getPointerId(pointerIndex) == this.mActivePointerId) {
            int newPointerIndex = pointerIndex == 0 ? 1 : 0;
            this.mLastMotionY = (int) ev.getY(newPointerIndex);
            this.mActivePointerId = ev.getPointerId(newPointerIndex);
            VelocityTracker velocityTracker = this.mVelocityTracker;
            if (velocityTracker != null) {
                velocityTracker.clear();
            }
        }
    }

    public boolean onGenericMotionEvent(MotionEvent event) {
        if ((event.getSource() & 2) != 0 && event.getAction() == 8 && !this.mIsBeingDragged) {
            float vscroll = event.getAxisValue(9);
            if (vscroll != 0.0f) {
                int delta = (int) (getVerticalScrollFactorCompat() * vscroll);
                int range = getScrollRange();
                int oldScrollY = getScrollY();
                int newScrollY = oldScrollY - delta;
                if (newScrollY < 0) {
                    newScrollY = 0;
                } else if (newScrollY > range) {
                    newScrollY = range;
                }
                if (newScrollY != oldScrollY) {
                    super.scrollTo(getScrollX(), newScrollY);
                    return true;
                }
            }
        }
        return false;
    }

    private float getVerticalScrollFactorCompat() {
        if (this.mVerticalScrollFactor == 0.0f) {
            TypedValue outValue = new TypedValue();
            Context context = getContext();
            if (context.getTheme().resolveAttribute(16842829, outValue, true)) {
                this.mVerticalScrollFactor = outValue.getDimension(context.getResources().getDisplayMetrics());
            } else {
                throw new IllegalStateException("Expected theme to define listPreferredItemHeight.");
            }
        }
        return this.mVerticalScrollFactor;
    }

    /* access modifiers changed from: protected */
    public void onOverScrolled(int scrollX, int scrollY, boolean clampedX, boolean clampedY) {
        super.scrollTo(scrollX, scrollY);
    }

    /* access modifiers changed from: 0000 */
    public boolean overScrollByCompat(int deltaX, int deltaY, int scrollX, int scrollY, int scrollRangeX, int scrollRangeY, int maxOverScrollX, int maxOverScrollY, boolean isTouchEvent) {
        int maxOverScrollX2;
        int maxOverScrollY2;
        boolean clampedX;
        boolean clampedY;
        int overScrollMode = getOverScrollMode();
        boolean canScrollHorizontal = computeHorizontalScrollRange() > computeHorizontalScrollExtent();
        boolean canScrollVertical = computeVerticalScrollRange() > computeVerticalScrollExtent();
        boolean overScrollHorizontal = overScrollMode == 0 || (overScrollMode == 1 && canScrollHorizontal);
        boolean overScrollVertical = overScrollMode == 0 || (overScrollMode == 1 && canScrollVertical);
        int newScrollX = scrollX + deltaX;
        if (!overScrollHorizontal) {
            maxOverScrollX2 = 0;
        } else {
            maxOverScrollX2 = maxOverScrollX;
        }
        int newScrollY = scrollY + deltaY;
        if (!overScrollVertical) {
            maxOverScrollY2 = 0;
        } else {
            maxOverScrollY2 = maxOverScrollY;
        }
        int left = -maxOverScrollX2;
        int right = maxOverScrollX2 + scrollRangeX;
        int top = -maxOverScrollY2;
        int bottom = maxOverScrollY2 + scrollRangeY;
        if (newScrollX > right) {
            newScrollX = right;
            clampedX = true;
        } else if (newScrollX < left) {
            newScrollX = left;
            clampedX = true;
        } else {
            clampedX = false;
        }
        if (newScrollY > bottom) {
            newScrollY = bottom;
            clampedY = true;
        } else if (newScrollY < top) {
            newScrollY = top;
            clampedY = true;
        } else {
            clampedY = false;
        }
        if (clampedY) {
            int i = overScrollMode;
            if (!hasNestedScrollingParent(1)) {
                this.mScroller.springBack(newScrollX, newScrollY, 0, 0, 0, getScrollRange());
            }
        }
        onOverScrolled(newScrollX, newScrollY, clampedX, clampedY);
        return clampedX || clampedY;
    }

    /* access modifiers changed from: 0000 */
    public int getScrollRange() {
        if (getChildCount() <= 0) {
            return 0;
        }
        View child = getChildAt(0);
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        return Math.max(0, ((child.getHeight() + lp.topMargin) + lp.bottomMargin) - ((getHeight() - getPaddingTop()) - getPaddingBottom()));
    }

    private View findFocusableViewInBounds(boolean topFocus, int top, int bottom) {
        List<View> focusables = getFocusables(2);
        View focusCandidate = null;
        boolean foundFullyContainedFocusable = false;
        int count = focusables.size();
        for (int i = 0; i < count; i++) {
            View view = (View) focusables.get(i);
            int viewTop = view.getTop();
            int viewBottom = view.getBottom();
            if (top < viewBottom && viewTop < bottom) {
                boolean viewIsCloserToBoundary = false;
                boolean viewIsFullyContained = top < viewTop && viewBottom < bottom;
                if (focusCandidate == null) {
                    focusCandidate = view;
                    foundFullyContainedFocusable = viewIsFullyContained;
                } else {
                    if ((topFocus && viewTop < focusCandidate.getTop()) || (!topFocus && viewBottom > focusCandidate.getBottom())) {
                        viewIsCloserToBoundary = true;
                    }
                    if (foundFullyContainedFocusable) {
                        if (viewIsFullyContained && viewIsCloserToBoundary) {
                            focusCandidate = view;
                        }
                    } else if (viewIsFullyContained) {
                        focusCandidate = view;
                        foundFullyContainedFocusable = true;
                    } else if (viewIsCloserToBoundary) {
                        focusCandidate = view;
                    }
                }
            }
        }
        return focusCandidate;
    }

    public boolean pageScroll(int direction) {
        boolean down = direction == 130;
        int height = getHeight();
        if (down) {
            this.mTempRect.top = getScrollY() + height;
            int count = getChildCount();
            if (count > 0) {
                View view = getChildAt(count - 1);
                int bottom = view.getBottom() + ((LayoutParams) view.getLayoutParams()).bottomMargin + getPaddingBottom();
                if (this.mTempRect.top + height > bottom) {
                    this.mTempRect.top = bottom - height;
                }
            }
        } else {
            this.mTempRect.top = getScrollY() - height;
            if (this.mTempRect.top < 0) {
                this.mTempRect.top = 0;
            }
        }
        Rect rect = this.mTempRect;
        rect.bottom = rect.top + height;
        return scrollAndFocus(direction, this.mTempRect.top, this.mTempRect.bottom);
    }

    public boolean fullScroll(int direction) {
        boolean down = direction == 130;
        int height = getHeight();
        this.mTempRect.top = 0;
        this.mTempRect.bottom = height;
        if (down) {
            int count = getChildCount();
            if (count > 0) {
                View view = getChildAt(count - 1);
                this.mTempRect.bottom = view.getBottom() + ((LayoutParams) view.getLayoutParams()).bottomMargin + getPaddingBottom();
                Rect rect = this.mTempRect;
                rect.top = rect.bottom - height;
            }
        }
        return scrollAndFocus(direction, this.mTempRect.top, this.mTempRect.bottom);
    }

    private boolean scrollAndFocus(int direction, int top, int bottom) {
        boolean handled = true;
        int height = getHeight();
        int containerTop = getScrollY();
        int containerBottom = containerTop + height;
        boolean up = direction == 33;
        View newFocused = findFocusableViewInBounds(up, top, bottom);
        if (newFocused == null) {
            newFocused = this;
        }
        if (top < containerTop || bottom > containerBottom) {
            doScrollY(up ? top - containerTop : bottom - containerBottom);
        } else {
            handled = false;
        }
        if (newFocused != findFocus()) {
            newFocused.requestFocus(direction);
        }
        return handled;
    }

    public boolean arrowScroll(int direction) {
        View currentFocused = findFocus();
        if (currentFocused == this) {
            currentFocused = null;
        }
        View nextFocused = FocusFinder.getInstance().findNextFocus(this, currentFocused, direction);
        int maxJump = getMaxScrollAmount();
        if (nextFocused == null || !isWithinDeltaOfScreen(nextFocused, maxJump, getHeight())) {
            int scrollDelta = maxJump;
            if (direction == 33 && getScrollY() < scrollDelta) {
                scrollDelta = getScrollY();
            } else if (direction == 130 && getChildCount() > 0) {
                View child = getChildAt(0);
                scrollDelta = Math.min((child.getBottom() + ((LayoutParams) child.getLayoutParams()).bottomMargin) - ((getScrollY() + getHeight()) - getPaddingBottom()), maxJump);
            }
            if (scrollDelta == 0) {
                return false;
            }
            doScrollY(direction == 130 ? scrollDelta : -scrollDelta);
        } else {
            nextFocused.getDrawingRect(this.mTempRect);
            offsetDescendantRectToMyCoords(nextFocused, this.mTempRect);
            doScrollY(computeScrollDeltaToGetChildRectOnScreen(this.mTempRect));
            nextFocused.requestFocus(direction);
        }
        if (currentFocused != null && currentFocused.isFocused() && isOffScreen(currentFocused)) {
            int descendantFocusability = getDescendantFocusability();
            setDescendantFocusability(131072);
            requestFocus();
            setDescendantFocusability(descendantFocusability);
        }
        return true;
    }

    private boolean isOffScreen(View descendant) {
        return !isWithinDeltaOfScreen(descendant, 0, getHeight());
    }

    private boolean isWithinDeltaOfScreen(View descendant, int delta, int height) {
        descendant.getDrawingRect(this.mTempRect);
        offsetDescendantRectToMyCoords(descendant, this.mTempRect);
        return this.mTempRect.bottom + delta >= getScrollY() && this.mTempRect.top - delta <= getScrollY() + height;
    }

    private void doScrollY(int delta) {
        if (delta == 0) {
            return;
        }
        if (this.mSmoothScrollingEnabled) {
            smoothScrollBy(0, delta);
        } else {
            scrollBy(0, delta);
        }
    }

    public final void smoothScrollBy(int dx, int dy) {
        if (getChildCount() != 0) {
            if (AnimationUtils.currentAnimationTimeMillis() - this.mLastScroll > 250) {
                View child = getChildAt(0);
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                int childSize = child.getHeight() + lp.topMargin + lp.bottomMargin;
                int parentSpace = (getHeight() - getPaddingTop()) - getPaddingBottom();
                int scrollY = getScrollY();
                this.mScroller.startScroll(getScrollX(), scrollY, 0, Math.max(0, Math.min(scrollY + dy, Math.max(0, childSize - parentSpace))) - scrollY);
                runAnimatedScroll(false);
            } else {
                if (!this.mScroller.isFinished()) {
                    abortAnimatedScroll();
                }
                scrollBy(dx, dy);
            }
            this.mLastScroll = AnimationUtils.currentAnimationTimeMillis();
        }
    }

    public final void smoothScrollTo(int x, int y) {
        smoothScrollBy(x - getScrollX(), y - getScrollY());
    }

    public int computeVerticalScrollRange() {
        int parentSpace = (getHeight() - getPaddingBottom()) - getPaddingTop();
        if (getChildCount() == 0) {
            return parentSpace;
        }
        View child = getChildAt(0);
        int scrollRange = child.getBottom() + ((LayoutParams) child.getLayoutParams()).bottomMargin;
        int scrollY = getScrollY();
        int overscrollBottom = Math.max(0, scrollRange - parentSpace);
        if (scrollY < 0) {
            scrollRange -= scrollY;
        } else if (scrollY > overscrollBottom) {
            scrollRange += scrollY - overscrollBottom;
        }
        return scrollRange;
    }

    public int computeVerticalScrollOffset() {
        return Math.max(0, super.computeVerticalScrollOffset());
    }

    public int computeVerticalScrollExtent() {
        return super.computeVerticalScrollExtent();
    }

    public int computeHorizontalScrollRange() {
        return super.computeHorizontalScrollRange();
    }

    public int computeHorizontalScrollOffset() {
        return super.computeHorizontalScrollOffset();
    }

    public int computeHorizontalScrollExtent() {
        return super.computeHorizontalScrollExtent();
    }

    /* access modifiers changed from: protected */
    public void measureChild(View child, int parentWidthMeasureSpec, int parentHeightMeasureSpec) {
        child.measure(getChildMeasureSpec(parentWidthMeasureSpec, getPaddingLeft() + getPaddingRight(), child.getLayoutParams().width), MeasureSpec.makeMeasureSpec(0, 0));
    }

    /* access modifiers changed from: protected */
    public void measureChildWithMargins(View child, int parentWidthMeasureSpec, int widthUsed, int parentHeightMeasureSpec, int heightUsed) {
        MarginLayoutParams lp = (MarginLayoutParams) child.getLayoutParams();
        child.measure(getChildMeasureSpec(parentWidthMeasureSpec, getPaddingLeft() + getPaddingRight() + lp.leftMargin + lp.rightMargin + widthUsed, lp.width), MeasureSpec.makeMeasureSpec(lp.topMargin + lp.bottomMargin, 0));
    }

    public void computeScroll() {
        if (!this.mScroller.isFinished()) {
            this.mScroller.computeScrollOffset();
            int y = this.mScroller.getCurrY();
            int unconsumed = y - this.mLastScrollerY;
            this.mLastScrollerY = y;
            int[] iArr = this.mScrollConsumed;
            boolean z = true;
            iArr[1] = 0;
            dispatchNestedPreScroll(0, unconsumed, iArr, null, 1);
            int unconsumed2 = unconsumed - this.mScrollConsumed[1];
            int range = getScrollRange();
            if (unconsumed2 != 0) {
                int oldScrollY = getScrollY();
                overScrollByCompat(0, unconsumed2, getScrollX(), oldScrollY, 0, range, 0, 0, false);
                int scrolledByMe = getScrollY() - oldScrollY;
                int unconsumed3 = unconsumed2 - scrolledByMe;
                int[] iArr2 = this.mScrollConsumed;
                iArr2[1] = 0;
                dispatchNestedScroll(0, scrolledByMe, 0, unconsumed3, this.mScrollOffset, 1, iArr2);
                unconsumed2 = unconsumed3 - this.mScrollConsumed[1];
            }
            if (unconsumed2 != 0) {
                int mode = getOverScrollMode();
                if (mode != 0 && (mode != 1 || range <= 0)) {
                    z = false;
                }
                if (z) {
                    ensureGlows();
                    if (unconsumed2 < 0) {
                        if (this.mEdgeGlowTop.isFinished()) {
                            this.mEdgeGlowTop.onAbsorb((int) this.mScroller.getCurrVelocity());
                        }
                    } else if (this.mEdgeGlowBottom.isFinished()) {
                        this.mEdgeGlowBottom.onAbsorb((int) this.mScroller.getCurrVelocity());
                    }
                }
                abortAnimatedScroll();
            }
            if (!this.mScroller.isFinished()) {
                ViewCompat.postInvalidateOnAnimation(this);
            }
        }
    }

    private void runAnimatedScroll(boolean participateInNestedScrolling) {
        if (participateInNestedScrolling) {
            startNestedScroll(2, 1);
        } else {
            stopNestedScroll(1);
        }
        this.mLastScrollerY = getScrollY();
        ViewCompat.postInvalidateOnAnimation(this);
    }

    private void abortAnimatedScroll() {
        this.mScroller.abortAnimation();
        stopNestedScroll(1);
    }

    private void scrollToChild(View child) {
        child.getDrawingRect(this.mTempRect);
        offsetDescendantRectToMyCoords(child, this.mTempRect);
        int scrollDelta = computeScrollDeltaToGetChildRectOnScreen(this.mTempRect);
        if (scrollDelta != 0) {
            scrollBy(0, scrollDelta);
        }
    }

    private boolean scrollToChildRect(Rect rect, boolean immediate) {
        int delta = computeScrollDeltaToGetChildRectOnScreen(rect);
        boolean scroll = delta != 0;
        if (scroll) {
            if (immediate) {
                scrollBy(0, delta);
            } else {
                smoothScrollBy(0, delta);
            }
        }
        return scroll;
    }

    /* access modifiers changed from: protected */
    public int computeScrollDeltaToGetChildRectOnScreen(Rect rect) {
        int scrollYDelta;
        int scrollYDelta2;
        if (getChildCount() == 0) {
            return 0;
        }
        int height = getHeight();
        int screenTop = getScrollY();
        int screenBottom = screenTop + height;
        int actualScreenBottom = screenBottom;
        int fadingEdge = getVerticalFadingEdgeLength();
        if (rect.top > 0) {
            screenTop += fadingEdge;
        }
        View child = getChildAt(0);
        LayoutParams lp = (LayoutParams) child.getLayoutParams();
        if (rect.bottom < child.getHeight() + lp.topMargin + lp.bottomMargin) {
            screenBottom -= fadingEdge;
        }
        int scrollYDelta3 = 0;
        if (rect.bottom > screenBottom && rect.top > screenTop) {
            if (rect.height() > height) {
                scrollYDelta2 = 0 + (rect.top - screenTop);
            } else {
                scrollYDelta2 = 0 + (rect.bottom - screenBottom);
            }
            scrollYDelta3 = Math.min(scrollYDelta2, (child.getBottom() + lp.bottomMargin) - actualScreenBottom);
        } else if (rect.top < screenTop && rect.bottom < screenBottom) {
            if (rect.height() > height) {
                scrollYDelta = 0 - (screenBottom - rect.bottom);
            } else {
                scrollYDelta = 0 - (screenTop - rect.top);
            }
            scrollYDelta3 = Math.max(scrollYDelta, -getScrollY());
        }
        return scrollYDelta3;
    }

    public void requestChildFocus(View child, View focused) {
        if (!this.mIsLayoutDirty) {
            scrollToChild(focused);
        } else {
            this.mChildToScrollTo = focused;
        }
        super.requestChildFocus(child, focused);
    }

    /* access modifiers changed from: protected */
    public boolean onRequestFocusInDescendants(int direction, Rect previouslyFocusedRect) {
        View nextFocus;
        if (direction == 2) {
            direction = 130;
        } else if (direction == 1) {
            direction = 33;
        }
        if (previouslyFocusedRect == null) {
            nextFocus = FocusFinder.getInstance().findNextFocus(this, null, direction);
        } else {
            nextFocus = FocusFinder.getInstance().findNextFocusFromRect(this, previouslyFocusedRect, direction);
        }
        if (nextFocus != null && !isOffScreen(nextFocus)) {
            return nextFocus.requestFocus(direction, previouslyFocusedRect);
        }
        return false;
    }

    public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
        rectangle.offset(child.getLeft() - child.getScrollX(), child.getTop() - child.getScrollY());
        return scrollToChildRect(rectangle, immediate);
    }

    public void requestLayout() {
        this.mIsLayoutDirty = true;
        super.requestLayout();
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        this.mIsLayoutDirty = false;
        View view = this.mChildToScrollTo;
        if (view != null && isViewDescendantOf(view, this)) {
            scrollToChild(this.mChildToScrollTo);
        }
        this.mChildToScrollTo = null;
        if (!this.mIsLaidOut) {
            if (this.mSavedState != null) {
                scrollTo(getScrollX(), this.mSavedState.scrollPosition);
                this.mSavedState = null;
            }
            int childSize = 0;
            if (getChildCount() > 0) {
                View child = getChildAt(0);
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                childSize = child.getMeasuredHeight() + lp.topMargin + lp.bottomMargin;
            }
            int parentSpace = ((b - t) - getPaddingTop()) - getPaddingBottom();
            int currentScrollY = getScrollY();
            int newScrollY = clamp(currentScrollY, parentSpace, childSize);
            if (newScrollY != currentScrollY) {
                scrollTo(getScrollX(), newScrollY);
            }
        }
        scrollTo(getScrollX(), getScrollY());
        this.mIsLaidOut = true;
    }

    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mIsLaidOut = false;
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        View currentFocused = findFocus();
        if (!(currentFocused == null || this == currentFocused || !isWithinDeltaOfScreen(currentFocused, 0, oldh))) {
            currentFocused.getDrawingRect(this.mTempRect);
            offsetDescendantRectToMyCoords(currentFocused, this.mTempRect);
            doScrollY(computeScrollDeltaToGetChildRectOnScreen(this.mTempRect));
        }
    }

    private static boolean isViewDescendantOf(View child, View parent) {
        boolean z = true;
        if (child == parent) {
            return true;
        }
        ViewParent theParent = child.getParent();
        if (!(theParent instanceof ViewGroup) || !isViewDescendantOf((View) theParent, parent)) {
            z = false;
        }
        return z;
    }

    public void fling(int velocityY) {
        if (getChildCount() > 0) {
            this.mScroller.fling(getScrollX(), getScrollY(), 0, velocityY, 0, 0, Integer.MIN_VALUE, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED, 0, 0);
            runAnimatedScroll(true);
        }
    }

    private void endDrag() {
        this.mIsBeingDragged = false;
        recycleVelocityTracker();
        stopNestedScroll(0);
        EdgeEffect edgeEffect = this.mEdgeGlowTop;
        if (edgeEffect != null) {
            edgeEffect.onRelease();
            this.mEdgeGlowBottom.onRelease();
        }
    }

    public void scrollTo(int x, int y) {
        if (getChildCount() > 0) {
            View child = getChildAt(0);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            int parentSpaceVertical = (getHeight() - getPaddingTop()) - getPaddingBottom();
            int childSizeVertical = child.getHeight() + lp.topMargin + lp.bottomMargin;
            int x2 = clamp(x, (getWidth() - getPaddingLeft()) - getPaddingRight(), child.getWidth() + lp.leftMargin + lp.rightMargin);
            int y2 = clamp(y, parentSpaceVertical, childSizeVertical);
            if (x2 != getScrollX() || y2 != getScrollY()) {
                super.scrollTo(x2, y2);
            }
        }
    }

    private void ensureGlows() {
        if (getOverScrollMode() == 2) {
            this.mEdgeGlowTop = null;
            this.mEdgeGlowBottom = null;
        } else if (this.mEdgeGlowTop == null) {
            Context context = getContext();
            this.mEdgeGlowTop = new EdgeEffect(context);
            this.mEdgeGlowBottom = new EdgeEffect(context);
        }
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        if (this.mEdgeGlowTop != null) {
            int scrollY = getScrollY();
            if (!this.mEdgeGlowTop.isFinished()) {
                int restoreCount = canvas.save();
                int width = getWidth();
                int height = getHeight();
                int xTranslation = 0;
                int yTranslation = Math.min(0, scrollY);
                if (VERSION.SDK_INT < 21 || getClipToPadding()) {
                    width -= getPaddingLeft() + getPaddingRight();
                    xTranslation = 0 + getPaddingLeft();
                }
                if (VERSION.SDK_INT >= 21 && getClipToPadding()) {
                    height -= getPaddingTop() + getPaddingBottom();
                    yTranslation += getPaddingTop();
                }
                canvas.translate((float) xTranslation, (float) yTranslation);
                this.mEdgeGlowTop.setSize(width, height);
                if (this.mEdgeGlowTop.draw(canvas)) {
                    ViewCompat.postInvalidateOnAnimation(this);
                }
                canvas.restoreToCount(restoreCount);
            }
            if (!this.mEdgeGlowBottom.isFinished()) {
                int restoreCount2 = canvas.save();
                int width2 = getWidth();
                int height2 = getHeight();
                int xTranslation2 = 0;
                int yTranslation2 = Math.max(getScrollRange(), scrollY) + height2;
                if (VERSION.SDK_INT < 21 || getClipToPadding()) {
                    width2 -= getPaddingLeft() + getPaddingRight();
                    xTranslation2 = 0 + getPaddingLeft();
                }
                if (VERSION.SDK_INT >= 21 && getClipToPadding()) {
                    height2 -= getPaddingTop() + getPaddingBottom();
                    yTranslation2 -= getPaddingBottom();
                }
                canvas.translate((float) (xTranslation2 - width2), (float) yTranslation2);
                canvas.rotate(180.0f, (float) width2, 0.0f);
                this.mEdgeGlowBottom.setSize(width2, height2);
                if (this.mEdgeGlowBottom.draw(canvas)) {
                    ViewCompat.postInvalidateOnAnimation(this);
                }
                canvas.restoreToCount(restoreCount2);
            }
        }
    }

    private static int clamp(int n, int my, int child) {
        if (my >= child || n < 0) {
            return 0;
        }
        if (my + n > child) {
            return child - my;
        }
        return n;
    }

    /* access modifiers changed from: protected */
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        this.mSavedState = ss;
        requestLayout();
    }

    /* access modifiers changed from: protected */
    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        ss.scrollPosition = getScrollY();
        return ss;
    }
}
