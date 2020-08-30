package com.google.android.material.bottomsheet;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewParent;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior;
import androidx.core.math.MathUtils;
import androidx.core.view.ViewCompat;
import androidx.customview.view.AbsSavedState;
import androidx.customview.widget.ViewDragHelper;
import androidx.customview.widget.ViewDragHelper.Callback;
import com.google.android.material.C0078R;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

public class BottomSheetBehavior<V extends View> extends Behavior<V> {
    private static final float HIDE_FRICTION = 0.1f;
    private static final float HIDE_THRESHOLD = 0.5f;
    public static final int PEEK_HEIGHT_AUTO = -1;
    public static final int STATE_COLLAPSED = 4;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_EXPANDED = 3;
    public static final int STATE_HALF_EXPANDED = 6;
    public static final int STATE_HIDDEN = 5;
    public static final int STATE_SETTLING = 2;
    int activePointerId;
    private BottomSheetCallback callback;
    int collapsedOffset;
    private final Callback dragCallback = new Callback() {
        public boolean tryCaptureView(View child, int pointerId) {
            boolean z = true;
            if (BottomSheetBehavior.this.state == 1 || BottomSheetBehavior.this.touchingScrollingChild) {
                return false;
            }
            if (BottomSheetBehavior.this.state == 3 && BottomSheetBehavior.this.activePointerId == pointerId) {
                View scroll = (View) BottomSheetBehavior.this.nestedScrollingChildRef.get();
                if (scroll != null && scroll.canScrollVertically(-1)) {
                    return false;
                }
            }
            if (BottomSheetBehavior.this.viewRef == null || BottomSheetBehavior.this.viewRef.get() != child) {
                z = false;
            }
            return z;
        }

        public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
            BottomSheetBehavior.this.dispatchOnSlide(top);
        }

        public void onViewDragStateChanged(int state) {
            if (state == 1) {
                BottomSheetBehavior.this.setStateInternal(1);
            }
        }

        public void onViewReleased(View releasedChild, float xvel, float yvel) {
            int targetState;
            int top;
            if (yvel < 0.0f) {
                if (BottomSheetBehavior.this.fitToContents) {
                    top = BottomSheetBehavior.this.fitToContentsOffset;
                    targetState = 3;
                } else if (releasedChild.getTop() > BottomSheetBehavior.this.halfExpandedOffset) {
                    top = BottomSheetBehavior.this.halfExpandedOffset;
                    targetState = 6;
                } else {
                    top = 0;
                    targetState = 3;
                }
            } else if (BottomSheetBehavior.this.hideable && BottomSheetBehavior.this.shouldHide(releasedChild, yvel) && (releasedChild.getTop() > BottomSheetBehavior.this.collapsedOffset || Math.abs(xvel) < Math.abs(yvel))) {
                top = BottomSheetBehavior.this.parentHeight;
                targetState = 5;
            } else if (yvel == 0.0f || Math.abs(xvel) > Math.abs(yvel)) {
                int top2 = releasedChild.getTop();
                if (BottomSheetBehavior.this.fitToContents) {
                    if (Math.abs(top2 - BottomSheetBehavior.this.fitToContentsOffset) < Math.abs(top2 - BottomSheetBehavior.this.collapsedOffset)) {
                        top = BottomSheetBehavior.this.fitToContentsOffset;
                        targetState = 3;
                    } else {
                        top = BottomSheetBehavior.this.collapsedOffset;
                        targetState = 4;
                    }
                } else if (top2 < BottomSheetBehavior.this.halfExpandedOffset) {
                    if (top2 < Math.abs(top2 - BottomSheetBehavior.this.collapsedOffset)) {
                        top = 0;
                        targetState = 3;
                    } else {
                        top = BottomSheetBehavior.this.halfExpandedOffset;
                        targetState = 6;
                    }
                } else if (Math.abs(top2 - BottomSheetBehavior.this.halfExpandedOffset) < Math.abs(top2 - BottomSheetBehavior.this.collapsedOffset)) {
                    top = BottomSheetBehavior.this.halfExpandedOffset;
                    targetState = 6;
                } else {
                    top = BottomSheetBehavior.this.collapsedOffset;
                    targetState = 4;
                }
            } else {
                top = BottomSheetBehavior.this.collapsedOffset;
                targetState = 4;
            }
            if (BottomSheetBehavior.this.viewDragHelper.settleCapturedViewAt(releasedChild.getLeft(), top)) {
                BottomSheetBehavior.this.setStateInternal(2);
                ViewCompat.postOnAnimation(releasedChild, new SettleRunnable(releasedChild, targetState));
                return;
            }
            BottomSheetBehavior.this.setStateInternal(targetState);
        }

        public int clampViewPositionVertical(View child, int top, int dy) {
            return MathUtils.clamp(top, BottomSheetBehavior.this.getExpandedOffset(), BottomSheetBehavior.this.hideable ? BottomSheetBehavior.this.parentHeight : BottomSheetBehavior.this.collapsedOffset);
        }

        public int clampViewPositionHorizontal(View child, int left, int dx) {
            return child.getLeft();
        }

        public int getViewVerticalDragRange(View child) {
            if (BottomSheetBehavior.this.hideable) {
                return BottomSheetBehavior.this.parentHeight;
            }
            return BottomSheetBehavior.this.collapsedOffset;
        }
    };
    /* access modifiers changed from: private */
    public boolean fitToContents = true;
    int fitToContentsOffset;
    int halfExpandedOffset;
    boolean hideable;
    private boolean ignoreEvents;
    private Map<View, Integer> importantForAccessibilityMap;
    private int initialY;
    private int lastNestedScrollDy;
    private int lastPeekHeight;
    private float maximumVelocity;
    private boolean nestedScrolled;
    WeakReference<View> nestedScrollingChildRef;
    int parentHeight;
    private int peekHeight;
    private boolean peekHeightAuto;
    private int peekHeightMin;
    private boolean skipCollapsed;
    int state = 4;
    boolean touchingScrollingChild;
    private VelocityTracker velocityTracker;
    ViewDragHelper viewDragHelper;
    WeakReference<V> viewRef;

    public static abstract class BottomSheetCallback {
        public abstract void onSlide(View view, float f);

        public abstract void onStateChanged(View view, int i);
    }

    protected static class SavedState extends AbsSavedState {
        public static final Creator<SavedState> CREATOR = new ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, (ClassLoader) null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        final int state;

        public SavedState(Parcel source) {
            this(source, (ClassLoader) null);
        }

        public SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            this.state = source.readInt();
        }

        public SavedState(Parcelable superState, int state2) {
            super(superState);
            this.state = state2;
        }

        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.state);
        }
    }

    private class SettleRunnable implements Runnable {
        private final int targetState;
        private final View view;

        SettleRunnable(View view2, int targetState2) {
            this.view = view2;
            this.targetState = targetState2;
        }

        public void run() {
            if (BottomSheetBehavior.this.viewDragHelper == null || !BottomSheetBehavior.this.viewDragHelper.continueSettling(true)) {
                BottomSheetBehavior.this.setStateInternal(this.targetState);
            } else {
                ViewCompat.postOnAnimation(this.view, this);
            }
        }
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface State {
    }

    public BottomSheetBehavior() {
    }

    public BottomSheetBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
        TypedArray a = context.obtainStyledAttributes(attrs, C0078R.styleable.BottomSheetBehavior_Layout);
        TypedValue value = a.peekValue(C0078R.styleable.BottomSheetBehavior_Layout_behavior_peekHeight);
        if (value == null || value.data != -1) {
            setPeekHeight(a.getDimensionPixelSize(C0078R.styleable.BottomSheetBehavior_Layout_behavior_peekHeight, -1));
        } else {
            setPeekHeight(value.data);
        }
        setHideable(a.getBoolean(C0078R.styleable.BottomSheetBehavior_Layout_behavior_hideable, false));
        setFitToContents(a.getBoolean(C0078R.styleable.BottomSheetBehavior_Layout_behavior_fitToContents, true));
        setSkipCollapsed(a.getBoolean(C0078R.styleable.BottomSheetBehavior_Layout_behavior_skipCollapsed, false));
        a.recycle();
        this.maximumVelocity = (float) ViewConfiguration.get(context).getScaledMaximumFlingVelocity();
    }

    public Parcelable onSaveInstanceState(CoordinatorLayout parent, V child) {
        return new SavedState(super.onSaveInstanceState(parent, child), this.state);
    }

    public void onRestoreInstanceState(CoordinatorLayout parent, V child, Parcelable state2) {
        SavedState ss = (SavedState) state2;
        super.onRestoreInstanceState(parent, child, ss.getSuperState());
        if (ss.state == 1 || ss.state == 2) {
            this.state = 4;
        } else {
            this.state = ss.state;
        }
    }

    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        if (ViewCompat.getFitsSystemWindows(parent) && !ViewCompat.getFitsSystemWindows(child)) {
            child.setFitsSystemWindows(true);
        }
        int savedTop = child.getTop();
        parent.onLayoutChild(child, layoutDirection);
        this.parentHeight = parent.getHeight();
        if (this.peekHeightAuto) {
            if (this.peekHeightMin == 0) {
                this.peekHeightMin = parent.getResources().getDimensionPixelSize(C0078R.dimen.design_bottom_sheet_peek_height_min);
            }
            this.lastPeekHeight = Math.max(this.peekHeightMin, this.parentHeight - ((parent.getWidth() * 9) / 16));
        } else {
            this.lastPeekHeight = this.peekHeight;
        }
        this.fitToContentsOffset = Math.max(0, this.parentHeight - child.getHeight());
        this.halfExpandedOffset = this.parentHeight / 2;
        calculateCollapsedOffset();
        int i = this.state;
        if (i == 3) {
            ViewCompat.offsetTopAndBottom(child, getExpandedOffset());
        } else if (i == 6) {
            ViewCompat.offsetTopAndBottom(child, this.halfExpandedOffset);
        } else if (!this.hideable || i != 5) {
            int i2 = this.state;
            if (i2 == 4) {
                ViewCompat.offsetTopAndBottom(child, this.collapsedOffset);
            } else if (i2 == 1 || i2 == 2) {
                ViewCompat.offsetTopAndBottom(child, savedTop - child.getTop());
            }
        } else {
            ViewCompat.offsetTopAndBottom(child, this.parentHeight);
        }
        if (this.viewDragHelper == null) {
            this.viewDragHelper = ViewDragHelper.create(parent, this.dragCallback);
        }
        this.viewRef = new WeakReference<>(child);
        this.nestedScrollingChildRef = new WeakReference<>(findScrollingChild(child));
        return true;
    }

    public boolean onInterceptTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        boolean z = false;
        if (!child.isShown()) {
            this.ignoreEvents = true;
            return false;
        }
        int action = event.getActionMasked();
        if (action == 0) {
            reset();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        View scroll = null;
        if (action == 0) {
            int initialX = (int) event.getX();
            this.initialY = (int) event.getY();
            WeakReference<View> weakReference = this.nestedScrollingChildRef;
            View scroll2 = weakReference != null ? (View) weakReference.get() : null;
            if (scroll2 != null && parent.isPointInChildBounds(scroll2, initialX, this.initialY)) {
                this.activePointerId = event.getPointerId(event.getActionIndex());
                this.touchingScrollingChild = true;
            }
            this.ignoreEvents = this.activePointerId == -1 && !parent.isPointInChildBounds(child, initialX, this.initialY);
        } else if (action == 1 || action == 3) {
            this.touchingScrollingChild = false;
            this.activePointerId = -1;
            if (this.ignoreEvents) {
                this.ignoreEvents = false;
                return false;
            }
        }
        if (!this.ignoreEvents) {
            ViewDragHelper viewDragHelper2 = this.viewDragHelper;
            if (viewDragHelper2 != null && viewDragHelper2.shouldInterceptTouchEvent(event)) {
                return true;
            }
        }
        WeakReference<View> weakReference2 = this.nestedScrollingChildRef;
        if (weakReference2 != null) {
            scroll = (View) weakReference2.get();
        }
        if (action == 2 && scroll != null && !this.ignoreEvents && this.state != 1 && !parent.isPointInChildBounds(scroll, (int) event.getX(), (int) event.getY()) && this.viewDragHelper != null && Math.abs(((float) this.initialY) - event.getY()) > ((float) this.viewDragHelper.getTouchSlop())) {
            z = true;
        }
        return z;
    }

    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        if (!child.isShown()) {
            return false;
        }
        int action = event.getActionMasked();
        if (this.state == 1 && action == 0) {
            return true;
        }
        ViewDragHelper viewDragHelper2 = this.viewDragHelper;
        if (viewDragHelper2 != null) {
            viewDragHelper2.processTouchEvent(event);
        }
        if (action == 0) {
            reset();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        if (action == 2 && !this.ignoreEvents && Math.abs(((float) this.initialY) - event.getY()) > ((float) this.viewDragHelper.getTouchSlop())) {
            this.viewDragHelper.captureChildView(child, event.getPointerId(event.getActionIndex()));
        }
        return !this.ignoreEvents;
    }

    public boolean onStartNestedScroll(CoordinatorLayout coordinatorLayout, V v, View directTargetChild, View target, int axes, int type) {
        this.lastNestedScrollDy = 0;
        this.nestedScrolled = false;
        if ((axes & 2) != 0) {
            return true;
        }
        return false;
    }

    public void onNestedPreScroll(CoordinatorLayout coordinatorLayout, V child, View target, int dx, int dy, int[] consumed, int type) {
        if (type != 1 && target == ((View) this.nestedScrollingChildRef.get())) {
            int currentTop = child.getTop();
            int newTop = currentTop - dy;
            if (dy > 0) {
                if (newTop < getExpandedOffset()) {
                    consumed[1] = currentTop - getExpandedOffset();
                    ViewCompat.offsetTopAndBottom(child, -consumed[1]);
                    setStateInternal(3);
                } else {
                    consumed[1] = dy;
                    ViewCompat.offsetTopAndBottom(child, -dy);
                    setStateInternal(1);
                }
            } else if (dy < 0 && !target.canScrollVertically(-1)) {
                int i = this.collapsedOffset;
                if (newTop <= i || this.hideable) {
                    consumed[1] = dy;
                    ViewCompat.offsetTopAndBottom(child, -dy);
                    setStateInternal(1);
                } else {
                    consumed[1] = currentTop - i;
                    ViewCompat.offsetTopAndBottom(child, -consumed[1]);
                    setStateInternal(4);
                }
            }
            dispatchOnSlide(child.getTop());
            this.lastNestedScrollDy = dy;
            this.nestedScrolled = true;
        }
    }

    public void onStopNestedScroll(CoordinatorLayout coordinatorLayout, V child, View target, int type) {
        int targetState;
        int top;
        if (child.getTop() == getExpandedOffset()) {
            setStateInternal(3);
        } else if (target == this.nestedScrollingChildRef.get() && this.nestedScrolled) {
            if (this.lastNestedScrollDy > 0) {
                top = getExpandedOffset();
                targetState = 3;
            } else if (this.hideable != 0 && shouldHide(child, getYVelocity())) {
                top = this.parentHeight;
                targetState = 5;
            } else if (this.lastNestedScrollDy == 0) {
                int currentTop = child.getTop();
                if (!this.fitToContents) {
                    int top2 = this.halfExpandedOffset;
                    if (currentTop < top2) {
                        if (currentTop < Math.abs(currentTop - this.collapsedOffset)) {
                            top = 0;
                            targetState = 3;
                        } else {
                            top = this.halfExpandedOffset;
                            targetState = 6;
                        }
                    } else if (Math.abs(currentTop - top2) < Math.abs(currentTop - this.collapsedOffset)) {
                        top = this.halfExpandedOffset;
                        targetState = 6;
                    } else {
                        top = this.collapsedOffset;
                        targetState = 4;
                    }
                } else if (Math.abs(currentTop - this.fitToContentsOffset) < Math.abs(currentTop - this.collapsedOffset)) {
                    top = this.fitToContentsOffset;
                    targetState = 3;
                } else {
                    top = this.collapsedOffset;
                    targetState = 4;
                }
            } else {
                top = this.collapsedOffset;
                targetState = 4;
            }
            if (this.viewDragHelper.smoothSlideViewTo(child, child.getLeft(), top)) {
                setStateInternal(2);
                ViewCompat.postOnAnimation(child, new SettleRunnable(child, targetState));
            } else {
                setStateInternal(targetState);
            }
            this.nestedScrolled = false;
        }
    }

    public boolean onNestedPreFling(CoordinatorLayout coordinatorLayout, V child, View target, float velocityX, float velocityY) {
        return target == this.nestedScrollingChildRef.get() && (this.state != 3 || super.onNestedPreFling(coordinatorLayout, child, target, velocityX, velocityY));
    }

    public boolean isFitToContents() {
        return this.fitToContents;
    }

    public void setFitToContents(boolean fitToContents2) {
        if (this.fitToContents != fitToContents2) {
            this.fitToContents = fitToContents2;
            if (this.viewRef != null) {
                calculateCollapsedOffset();
            }
            setStateInternal((!this.fitToContents || this.state != 6) ? this.state : 3);
        }
    }

    public final void setPeekHeight(int peekHeight2) {
        boolean layout = false;
        if (peekHeight2 == -1) {
            if (!this.peekHeightAuto) {
                this.peekHeightAuto = true;
                layout = true;
            }
        } else if (this.peekHeightAuto || this.peekHeight != peekHeight2) {
            this.peekHeightAuto = false;
            this.peekHeight = Math.max(0, peekHeight2);
            this.collapsedOffset = this.parentHeight - peekHeight2;
            layout = true;
        }
        if (layout && this.state == 4) {
            WeakReference<V> weakReference = this.viewRef;
            if (weakReference != null) {
                V view = (View) weakReference.get();
                if (view != null) {
                    view.requestLayout();
                }
            }
        }
    }

    public final int getPeekHeight() {
        if (this.peekHeightAuto) {
            return -1;
        }
        return this.peekHeight;
    }

    public void setHideable(boolean hideable2) {
        this.hideable = hideable2;
    }

    public boolean isHideable() {
        return this.hideable;
    }

    public void setSkipCollapsed(boolean skipCollapsed2) {
        this.skipCollapsed = skipCollapsed2;
    }

    public boolean getSkipCollapsed() {
        return this.skipCollapsed;
    }

    public void setBottomSheetCallback(BottomSheetCallback callback2) {
        this.callback = callback2;
    }

    public final void setState(int state2) {
        if (state2 != this.state) {
            WeakReference<V> weakReference = this.viewRef;
            if (weakReference == null) {
                if (state2 == 4 || state2 == 3 || state2 == 6 || (this.hideable && state2 == 5)) {
                    this.state = state2;
                }
                return;
            }
            final V child = (View) weakReference.get();
            if (child != null) {
                ViewParent parent = child.getParent();
                if (parent == null || !parent.isLayoutRequested() || !ViewCompat.isAttachedToWindow(child)) {
                    startSettlingAnimation(child, state2);
                } else {
                    final int finalState = state2;
                    child.post(new Runnable() {
                        public void run() {
                            BottomSheetBehavior.this.startSettlingAnimation(child, finalState);
                        }
                    });
                }
            }
        }
    }

    public final int getState() {
        return this.state;
    }

    /* access modifiers changed from: 0000 */
    public void setStateInternal(int state2) {
        if (this.state != state2) {
            this.state = state2;
            if (state2 == 6 || state2 == 3) {
                updateImportantForAccessibility(true);
            } else if (state2 == 5 || state2 == 4) {
                updateImportantForAccessibility(false);
            }
            View bottomSheet = (View) this.viewRef.get();
            if (bottomSheet != null) {
                BottomSheetCallback bottomSheetCallback = this.callback;
                if (bottomSheetCallback != null) {
                    bottomSheetCallback.onStateChanged(bottomSheet, state2);
                }
            }
        }
    }

    private void calculateCollapsedOffset() {
        if (this.fitToContents) {
            this.collapsedOffset = Math.max(this.parentHeight - this.lastPeekHeight, this.fitToContentsOffset);
        } else {
            this.collapsedOffset = this.parentHeight - this.lastPeekHeight;
        }
    }

    private void reset() {
        this.activePointerId = -1;
        VelocityTracker velocityTracker2 = this.velocityTracker;
        if (velocityTracker2 != null) {
            velocityTracker2.recycle();
            this.velocityTracker = null;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean shouldHide(View child, float yvel) {
        boolean z = true;
        if (this.skipCollapsed) {
            return true;
        }
        if (child.getTop() < this.collapsedOffset) {
            return false;
        }
        if (Math.abs((((float) child.getTop()) + (HIDE_FRICTION * yvel)) - ((float) this.collapsedOffset)) / ((float) this.peekHeight) <= HIDE_THRESHOLD) {
            z = false;
        }
        return z;
    }

    /* access modifiers changed from: 0000 */
    public View findScrollingChild(View view) {
        if (ViewCompat.isNestedScrollingEnabled(view)) {
            return view;
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            int count = group.getChildCount();
            for (int i = 0; i < count; i++) {
                View scrollingChild = findScrollingChild(group.getChildAt(i));
                if (scrollingChild != null) {
                    return scrollingChild;
                }
            }
        }
        return null;
    }

    private float getYVelocity() {
        VelocityTracker velocityTracker2 = this.velocityTracker;
        if (velocityTracker2 == null) {
            return 0.0f;
        }
        velocityTracker2.computeCurrentVelocity(1000, this.maximumVelocity);
        return this.velocityTracker.getYVelocity(this.activePointerId);
    }

    /* access modifiers changed from: private */
    public int getExpandedOffset() {
        if (this.fitToContents) {
            return this.fitToContentsOffset;
        }
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public void startSettlingAnimation(View child, int state2) {
        int top;
        if (state2 == 4) {
            top = this.collapsedOffset;
        } else if (state2 == 6) {
            top = this.halfExpandedOffset;
            if (this.fitToContents && top <= this.fitToContentsOffset) {
                state2 = 3;
                top = this.fitToContentsOffset;
            }
        } else if (state2 == 3) {
            top = getExpandedOffset();
        } else if (this.hideable == 0 || state2 != 5) {
            StringBuilder sb = new StringBuilder();
            sb.append("Illegal state argument: ");
            sb.append(state2);
            throw new IllegalArgumentException(sb.toString());
        } else {
            top = this.parentHeight;
        }
        if (this.viewDragHelper.smoothSlideViewTo(child, child.getLeft(), top)) {
            setStateInternal(2);
            ViewCompat.postOnAnimation(child, new SettleRunnable(child, state2));
            return;
        }
        setStateInternal(state2);
    }

    /* access modifiers changed from: 0000 */
    public void dispatchOnSlide(int top) {
        View bottomSheet = (View) this.viewRef.get();
        if (bottomSheet != null) {
            BottomSheetCallback bottomSheetCallback = this.callback;
            if (bottomSheetCallback != null) {
                int i = this.collapsedOffset;
                if (top > i) {
                    bottomSheetCallback.onSlide(bottomSheet, ((float) (i - top)) / ((float) (this.parentHeight - i)));
                } else {
                    bottomSheetCallback.onSlide(bottomSheet, ((float) (i - top)) / ((float) (i - getExpandedOffset())));
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public int getPeekHeightMin() {
        return this.peekHeightMin;
    }

    public static <V extends View> BottomSheetBehavior<V> from(V view) {
        LayoutParams params = view.getLayoutParams();
        if (params instanceof CoordinatorLayout.LayoutParams) {
            Behavior behavior = ((CoordinatorLayout.LayoutParams) params).getBehavior();
            if (behavior instanceof BottomSheetBehavior) {
                return (BottomSheetBehavior) behavior;
            }
            throw new IllegalArgumentException("The view is not associated with BottomSheetBehavior");
        }
        throw new IllegalArgumentException("The view is not a child of CoordinatorLayout");
    }

    private void updateImportantForAccessibility(boolean expanded) {
        WeakReference<V> weakReference = this.viewRef;
        if (weakReference != null) {
            ViewParent viewParent = ((View) weakReference.get()).getParent();
            if (viewParent instanceof CoordinatorLayout) {
                CoordinatorLayout parent = (CoordinatorLayout) viewParent;
                int childCount = parent.getChildCount();
                if (VERSION.SDK_INT >= 16 && expanded) {
                    if (this.importantForAccessibilityMap == null) {
                        this.importantForAccessibilityMap = new HashMap(childCount);
                    } else {
                        return;
                    }
                }
                for (int i = 0; i < childCount; i++) {
                    View child = parent.getChildAt(i);
                    if (child != this.viewRef.get()) {
                        if (!expanded) {
                            Map<View, Integer> map = this.importantForAccessibilityMap;
                            if (map != null && map.containsKey(child)) {
                                ViewCompat.setImportantForAccessibility(child, ((Integer) this.importantForAccessibilityMap.get(child)).intValue());
                            }
                        } else {
                            if (VERSION.SDK_INT >= 16) {
                                this.importantForAccessibilityMap.put(child, Integer.valueOf(child.getImportantForAccessibility()));
                            }
                            ViewCompat.setImportantForAccessibility(child, 4);
                        }
                    }
                }
                if (!expanded) {
                    this.importantForAccessibilityMap = null;
                }
            }
        }
    }
}
