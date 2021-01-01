package androidx.customview.widget;

import android.content.Context;
import android.util.Log;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.widget.OverScroller;
import androidx.core.view.ViewCompat;
import java.util.Arrays;

public class ViewDragHelper {
    private static final int BASE_SETTLE_DURATION = 256;
    public static final int DIRECTION_ALL = 3;
    public static final int DIRECTION_HORIZONTAL = 1;
    public static final int DIRECTION_VERTICAL = 2;
    public static final int EDGE_ALL = 15;
    public static final int EDGE_BOTTOM = 8;
    public static final int EDGE_LEFT = 1;
    public static final int EDGE_RIGHT = 2;
    private static final int EDGE_SIZE = 20;
    public static final int EDGE_TOP = 4;
    public static final int INVALID_POINTER = -1;
    private static final int MAX_SETTLE_DURATION = 600;
    public static final int STATE_DRAGGING = 1;
    public static final int STATE_IDLE = 0;
    public static final int STATE_SETTLING = 2;
    private static final String TAG = "ViewDragHelper";
    private static final Interpolator sInterpolator = new Interpolator() {
        public float getInterpolation(float t) {
            float t2 = t - 1.0f;
            return (t2 * t2 * t2 * t2 * t2) + 1.0f;
        }
    };
    private int mActivePointerId = -1;
    private final Callback mCallback;
    private View mCapturedView;
    private int mDragState;
    private int[] mEdgeDragsInProgress;
    private int[] mEdgeDragsLocked;
    private int mEdgeSize;
    private int[] mInitialEdgesTouched;
    private float[] mInitialMotionX;
    private float[] mInitialMotionY;
    private float[] mLastMotionX;
    private float[] mLastMotionY;
    private float mMaxVelocity;
    private float mMinVelocity;
    private final ViewGroup mParentView;
    private int mPointersDown;
    private boolean mReleaseInProgress;
    private OverScroller mScroller;
    private final Runnable mSetIdleRunnable = new Runnable() {
        public void run() {
            ViewDragHelper.this.setDragState(0);
        }
    };
    private int mTouchSlop;
    private int mTrackingEdges;
    private VelocityTracker mVelocityTracker;

    public static abstract class Callback {
        public abstract boolean tryCaptureView(View view, int i);

        public void onViewDragStateChanged(int state) {
        }

        public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
        }

        public void onViewCaptured(View capturedChild, int activePointerId) {
        }

        public void onViewReleased(View releasedChild, float xvel, float yvel) {
        }

        public void onEdgeTouched(int edgeFlags, int pointerId) {
        }

        public boolean onEdgeLock(int edgeFlags) {
            return false;
        }

        public void onEdgeDragStarted(int edgeFlags, int pointerId) {
        }

        public int getOrderedChildIndex(int index) {
            return index;
        }

        public int getViewHorizontalDragRange(View child) {
            return 0;
        }

        public int getViewVerticalDragRange(View child) {
            return 0;
        }

        public int clampViewPositionHorizontal(View child, int left, int dx) {
            return 0;
        }

        public int clampViewPositionVertical(View child, int top, int dy) {
            return 0;
        }
    }

    public static ViewDragHelper create(ViewGroup forParent, Callback cb) {
        return new ViewDragHelper(forParent.getContext(), forParent, cb);
    }

    public static ViewDragHelper create(ViewGroup forParent, float sensitivity, Callback cb) {
        ViewDragHelper helper = create(forParent, cb);
        helper.mTouchSlop = (int) (((float) helper.mTouchSlop) * (1.0f / sensitivity));
        return helper;
    }

    private ViewDragHelper(Context context, ViewGroup forParent, Callback cb) {
        if (forParent == null) {
            throw new IllegalArgumentException("Parent view may not be null");
        } else if (cb != null) {
            this.mParentView = forParent;
            this.mCallback = cb;
            ViewConfiguration vc = ViewConfiguration.get(context);
            this.mEdgeSize = (int) ((20.0f * context.getResources().getDisplayMetrics().density) + 0.5f);
            this.mTouchSlop = vc.getScaledTouchSlop();
            this.mMaxVelocity = (float) vc.getScaledMaximumFlingVelocity();
            this.mMinVelocity = (float) vc.getScaledMinimumFlingVelocity();
            this.mScroller = new OverScroller(context, sInterpolator);
        } else {
            throw new IllegalArgumentException("Callback may not be null");
        }
    }

    public void setMinVelocity(float minVel) {
        this.mMinVelocity = minVel;
    }

    public float getMinVelocity() {
        return this.mMinVelocity;
    }

    public int getViewDragState() {
        return this.mDragState;
    }

    public void setEdgeTrackingEnabled(int edgeFlags) {
        this.mTrackingEdges = edgeFlags;
    }

    public int getEdgeSize() {
        return this.mEdgeSize;
    }

    public void captureChildView(View childView, int activePointerId) {
        if (childView.getParent() == this.mParentView) {
            this.mCapturedView = childView;
            this.mActivePointerId = activePointerId;
            this.mCallback.onViewCaptured(childView, activePointerId);
            setDragState(1);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("captureChildView: parameter must be a descendant of the ViewDragHelper's tracked parent view (");
        sb.append(this.mParentView);
        sb.append(")");
        throw new IllegalArgumentException(sb.toString());
    }

    public View getCapturedView() {
        return this.mCapturedView;
    }

    public int getActivePointerId() {
        return this.mActivePointerId;
    }

    public int getTouchSlop() {
        return this.mTouchSlop;
    }

    public void cancel() {
        this.mActivePointerId = -1;
        clearMotionHistory();
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.mVelocityTracker = null;
        }
    }

    public void abort() {
        cancel();
        if (this.mDragState == 2) {
            int oldX = this.mScroller.getCurrX();
            int oldY = this.mScroller.getCurrY();
            this.mScroller.abortAnimation();
            int newX = this.mScroller.getCurrX();
            int newY = this.mScroller.getCurrY();
            this.mCallback.onViewPositionChanged(this.mCapturedView, newX, newY, newX - oldX, newY - oldY);
        }
        setDragState(0);
    }

    public boolean smoothSlideViewTo(View child, int finalLeft, int finalTop) {
        this.mCapturedView = child;
        this.mActivePointerId = -1;
        boolean continueSliding = forceSettleCapturedViewAt(finalLeft, finalTop, 0, 0);
        if (!continueSliding && this.mDragState == 0 && this.mCapturedView != null) {
            this.mCapturedView = null;
        }
        return continueSliding;
    }

    public boolean settleCapturedViewAt(int finalLeft, int finalTop) {
        if (this.mReleaseInProgress) {
            return forceSettleCapturedViewAt(finalLeft, finalTop, (int) this.mVelocityTracker.getXVelocity(this.mActivePointerId), (int) this.mVelocityTracker.getYVelocity(this.mActivePointerId));
        }
        throw new IllegalStateException("Cannot settleCapturedViewAt outside of a call to Callback#onViewReleased");
    }

    private boolean forceSettleCapturedViewAt(int finalLeft, int finalTop, int xvel, int yvel) {
        int startLeft = this.mCapturedView.getLeft();
        int startTop = this.mCapturedView.getTop();
        int dx = finalLeft - startLeft;
        int dy = finalTop - startTop;
        if (dx == 0 && dy == 0) {
            this.mScroller.abortAnimation();
            setDragState(0);
            return false;
        }
        this.mScroller.startScroll(startLeft, startTop, dx, dy, computeSettleDuration(this.mCapturedView, dx, dy, xvel, yvel));
        setDragState(2);
        return true;
    }

    private int computeSettleDuration(View child, int dx, int dy, int xvel, int yvel) {
        float f;
        float f2;
        float f3;
        float f4;
        View view = child;
        int xvel2 = clampMag(xvel, (int) this.mMinVelocity, (int) this.mMaxVelocity);
        int yvel2 = clampMag(yvel, (int) this.mMinVelocity, (int) this.mMaxVelocity);
        int absDx = Math.abs(dx);
        int absDy = Math.abs(dy);
        int absXVel = Math.abs(xvel2);
        int absYVel = Math.abs(yvel2);
        int addedVel = absXVel + absYVel;
        int addedDistance = absDx + absDy;
        if (xvel2 != 0) {
            f2 = (float) absXVel;
            f = (float) addedVel;
        } else {
            f2 = (float) absDx;
            f = (float) addedDistance;
        }
        float xweight = f2 / f;
        if (yvel2 != 0) {
            f4 = (float) absYVel;
            f3 = (float) addedVel;
        } else {
            f4 = (float) absDy;
            f3 = (float) addedDistance;
        }
        float yweight = f4 / f3;
        return (int) ((((float) computeAxisDuration(dx, xvel2, this.mCallback.getViewHorizontalDragRange(view))) * xweight) + (((float) computeAxisDuration(dy, yvel2, this.mCallback.getViewVerticalDragRange(view))) * yweight));
    }

    private int computeAxisDuration(int delta, int velocity, int motionRange) {
        int duration;
        if (delta == 0) {
            return 0;
        }
        int width = this.mParentView.getWidth();
        int halfWidth = width / 2;
        float distance = ((float) halfWidth) + (((float) halfWidth) * distanceInfluenceForSnapDuration(Math.min(1.0f, ((float) Math.abs(delta)) / ((float) width))));
        int velocity2 = Math.abs(velocity);
        if (velocity2 > 0) {
            duration = Math.round(Math.abs(distance / ((float) velocity2)) * 1000.0f) * 4;
        } else {
            duration = (int) ((1.0f + (((float) Math.abs(delta)) / ((float) motionRange))) * 256.0f);
        }
        return Math.min(duration, MAX_SETTLE_DURATION);
    }

    private int clampMag(int value, int absMin, int absMax) {
        int absValue = Math.abs(value);
        if (absValue < absMin) {
            return 0;
        }
        if (absValue <= absMax) {
            return value;
        }
        return value > 0 ? absMax : -absMax;
    }

    private float clampMag(float value, float absMin, float absMax) {
        float absValue = Math.abs(value);
        if (absValue < absMin) {
            return 0.0f;
        }
        if (absValue <= absMax) {
            return value;
        }
        return value > 0.0f ? absMax : -absMax;
    }

    private float distanceInfluenceForSnapDuration(float f) {
        return (float) Math.sin((double) ((f - 0.5f) * 0.47123894f));
    }

    public void flingCapturedView(int minLeft, int minTop, int maxLeft, int maxTop) {
        if (this.mReleaseInProgress) {
            this.mScroller.fling(this.mCapturedView.getLeft(), this.mCapturedView.getTop(), (int) this.mVelocityTracker.getXVelocity(this.mActivePointerId), (int) this.mVelocityTracker.getYVelocity(this.mActivePointerId), minLeft, maxLeft, minTop, maxTop);
            setDragState(2);
            return;
        }
        throw new IllegalStateException("Cannot flingCapturedView outside of a call to Callback#onViewReleased");
    }

    public boolean continueSettling(boolean deferCallbacks) {
        if (this.mDragState == 2) {
            boolean keepGoing = this.mScroller.computeScrollOffset();
            int x = this.mScroller.getCurrX();
            int y = this.mScroller.getCurrY();
            int dx = x - this.mCapturedView.getLeft();
            int dy = y - this.mCapturedView.getTop();
            if (dx != 0) {
                ViewCompat.offsetLeftAndRight(this.mCapturedView, dx);
            }
            if (dy != 0) {
                ViewCompat.offsetTopAndBottom(this.mCapturedView, dy);
            }
            if (!(dx == 0 && dy == 0)) {
                this.mCallback.onViewPositionChanged(this.mCapturedView, x, y, dx, dy);
            }
            if (keepGoing && x == this.mScroller.getFinalX() && y == this.mScroller.getFinalY()) {
                this.mScroller.abortAnimation();
                keepGoing = false;
            }
            if (!keepGoing) {
                if (deferCallbacks) {
                    this.mParentView.post(this.mSetIdleRunnable);
                } else {
                    setDragState(0);
                }
            }
        }
        if (this.mDragState == 2) {
            return true;
        }
        return false;
    }

    private void dispatchViewReleased(float xvel, float yvel) {
        this.mReleaseInProgress = true;
        this.mCallback.onViewReleased(this.mCapturedView, xvel, yvel);
        this.mReleaseInProgress = false;
        if (this.mDragState == 1) {
            setDragState(0);
        }
    }

    private void clearMotionHistory() {
        float[] fArr = this.mInitialMotionX;
        if (fArr != null) {
            Arrays.fill(fArr, 0.0f);
            Arrays.fill(this.mInitialMotionY, 0.0f);
            Arrays.fill(this.mLastMotionX, 0.0f);
            Arrays.fill(this.mLastMotionY, 0.0f);
            Arrays.fill(this.mInitialEdgesTouched, 0);
            Arrays.fill(this.mEdgeDragsInProgress, 0);
            Arrays.fill(this.mEdgeDragsLocked, 0);
            this.mPointersDown = 0;
        }
    }

    private void clearMotionHistory(int pointerId) {
        if (this.mInitialMotionX != null && isPointerDown(pointerId)) {
            this.mInitialMotionX[pointerId] = 0.0f;
            this.mInitialMotionY[pointerId] = 0.0f;
            this.mLastMotionX[pointerId] = 0.0f;
            this.mLastMotionY[pointerId] = 0.0f;
            this.mInitialEdgesTouched[pointerId] = 0;
            this.mEdgeDragsInProgress[pointerId] = 0;
            this.mEdgeDragsLocked[pointerId] = 0;
            this.mPointersDown &= ~(1 << pointerId);
        }
    }

    private void ensureMotionHistorySizeForId(int pointerId) {
        float[] fArr = this.mInitialMotionX;
        if (fArr == null || fArr.length <= pointerId) {
            float[] imx = new float[(pointerId + 1)];
            float[] imy = new float[(pointerId + 1)];
            float[] lmx = new float[(pointerId + 1)];
            float[] lmy = new float[(pointerId + 1)];
            int[] iit = new int[(pointerId + 1)];
            int[] edip = new int[(pointerId + 1)];
            int[] edl = new int[(pointerId + 1)];
            float[] fArr2 = this.mInitialMotionX;
            if (fArr2 != null) {
                System.arraycopy(fArr2, 0, imx, 0, fArr2.length);
                float[] fArr3 = this.mInitialMotionY;
                System.arraycopy(fArr3, 0, imy, 0, fArr3.length);
                float[] fArr4 = this.mLastMotionX;
                System.arraycopy(fArr4, 0, lmx, 0, fArr4.length);
                float[] fArr5 = this.mLastMotionY;
                System.arraycopy(fArr5, 0, lmy, 0, fArr5.length);
                int[] iArr = this.mInitialEdgesTouched;
                System.arraycopy(iArr, 0, iit, 0, iArr.length);
                int[] iArr2 = this.mEdgeDragsInProgress;
                System.arraycopy(iArr2, 0, edip, 0, iArr2.length);
                int[] iArr3 = this.mEdgeDragsLocked;
                System.arraycopy(iArr3, 0, edl, 0, iArr3.length);
            }
            this.mInitialMotionX = imx;
            this.mInitialMotionY = imy;
            this.mLastMotionX = lmx;
            this.mLastMotionY = lmy;
            this.mInitialEdgesTouched = iit;
            this.mEdgeDragsInProgress = edip;
            this.mEdgeDragsLocked = edl;
        }
    }

    private void saveInitialMotion(float x, float y, int pointerId) {
        ensureMotionHistorySizeForId(pointerId);
        float[] fArr = this.mInitialMotionX;
        this.mLastMotionX[pointerId] = x;
        fArr[pointerId] = x;
        float[] fArr2 = this.mInitialMotionY;
        this.mLastMotionY[pointerId] = y;
        fArr2[pointerId] = y;
        this.mInitialEdgesTouched[pointerId] = getEdgesTouched((int) x, (int) y);
        this.mPointersDown |= 1 << pointerId;
    }

    private void saveLastMotion(MotionEvent ev) {
        int pointerCount = ev.getPointerCount();
        for (int i = 0; i < pointerCount; i++) {
            int pointerId = ev.getPointerId(i);
            if (isValidPointerForActionMove(pointerId)) {
                float x = ev.getX(i);
                float y = ev.getY(i);
                this.mLastMotionX[pointerId] = x;
                this.mLastMotionY[pointerId] = y;
            }
        }
    }

    public boolean isPointerDown(int pointerId) {
        return (this.mPointersDown & (1 << pointerId)) != 0;
    }

    /* access modifiers changed from: 0000 */
    public void setDragState(int state) {
        this.mParentView.removeCallbacks(this.mSetIdleRunnable);
        if (this.mDragState != state) {
            this.mDragState = state;
            this.mCallback.onViewDragStateChanged(state);
            if (this.mDragState == 0) {
                this.mCapturedView = null;
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean tryCaptureViewForDrag(View toCapture, int pointerId) {
        if (toCapture == this.mCapturedView && this.mActivePointerId == pointerId) {
            return true;
        }
        if (toCapture == null || !this.mCallback.tryCaptureView(toCapture, pointerId)) {
            return false;
        }
        this.mActivePointerId = pointerId;
        captureChildView(toCapture, pointerId);
        return true;
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0071, code lost:
        if (r0.canScrollVertically(-r19) != false) goto L_0x007c;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean canScroll(android.view.View r16, boolean r17, int r18, int r19, int r20, int r21) {
        /*
            r15 = this;
            r0 = r16
            boolean r1 = r0 instanceof android.view.ViewGroup
            r2 = 1
            if (r1 == 0) goto L_0x005f
            r1 = r0
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
            int r3 = r16.getScrollX()
            int r4 = r16.getScrollY()
            int r5 = r1.getChildCount()
            int r6 = r5 + -1
        L_0x0018:
            if (r6 < 0) goto L_0x005f
            android.view.View r14 = r1.getChildAt(r6)
            int r7 = r20 + r3
            int r8 = r14.getLeft()
            if (r7 < r8) goto L_0x005c
            int r7 = r20 + r3
            int r8 = r14.getRight()
            if (r7 >= r8) goto L_0x005c
            int r7 = r21 + r4
            int r8 = r14.getTop()
            if (r7 < r8) goto L_0x005c
            int r7 = r21 + r4
            int r8 = r14.getBottom()
            if (r7 >= r8) goto L_0x005c
            r9 = 1
            int r7 = r20 + r3
            int r8 = r14.getLeft()
            int r12 = r7 - r8
            int r7 = r21 + r4
            int r8 = r14.getTop()
            int r13 = r7 - r8
            r7 = r15
            r8 = r14
            r10 = r18
            r11 = r19
            boolean r7 = r7.canScroll(r8, r9, r10, r11, r12, r13)
            if (r7 == 0) goto L_0x005c
            return r2
        L_0x005c:
            int r6 = r6 + -1
            goto L_0x0018
        L_0x005f:
            if (r17 == 0) goto L_0x0077
            r1 = r18
            int r3 = -r1
            boolean r3 = r0.canScrollHorizontally(r3)
            if (r3 != 0) goto L_0x0074
            r3 = r19
            int r4 = -r3
            boolean r4 = r0.canScrollVertically(r4)
            if (r4 == 0) goto L_0x007b
            goto L_0x007c
        L_0x0074:
            r3 = r19
            goto L_0x007c
        L_0x0077:
            r1 = r18
            r3 = r19
        L_0x007b:
            r2 = 0
        L_0x007c:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.customview.widget.ViewDragHelper.canScroll(android.view.View, boolean, int, int, int, int):boolean");
    }

    /* JADX WARNING: Code restructure failed: missing block: B:50:0x0110, code lost:
        if (r2 != r15) goto L_0x011f;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean shouldInterceptTouchEvent(android.view.MotionEvent r22) {
        /*
            r21 = this;
            r0 = r21
            r1 = r22
            int r2 = r22.getActionMasked()
            int r3 = r22.getActionIndex()
            if (r2 != 0) goto L_0x0011
            r21.cancel()
        L_0x0011:
            android.view.VelocityTracker r4 = r0.mVelocityTracker
            if (r4 != 0) goto L_0x001b
            android.view.VelocityTracker r4 = android.view.VelocityTracker.obtain()
            r0.mVelocityTracker = r4
        L_0x001b:
            android.view.VelocityTracker r4 = r0.mVelocityTracker
            r4.addMovement(r1)
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L_0x0156
            if (r2 == r6) goto L_0x014d
            if (r2 == r5) goto L_0x008d
            r7 = 3
            if (r2 == r7) goto L_0x0087
            r7 = 5
            if (r2 == r7) goto L_0x0046
            r5 = 6
            if (r2 == r5) goto L_0x0038
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x0038:
            int r5 = r1.getPointerId(r3)
            r0.clearMotionHistory(r5)
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x0046:
            int r7 = r1.getPointerId(r3)
            float r8 = r1.getX(r3)
            float r9 = r1.getY(r3)
            r0.saveInitialMotion(r8, r9, r7)
            int r10 = r0.mDragState
            if (r10 != 0) goto L_0x006a
            int[] r5 = r0.mInitialEdgesTouched
            r5 = r5[r7]
            int r10 = r0.mTrackingEdges
            r11 = r5 & r10
            if (r11 == 0) goto L_0x0080
            androidx.customview.widget.ViewDragHelper$Callback r11 = r0.mCallback
            r10 = r10 & r5
            r11.onEdgeTouched(r10, r7)
            goto L_0x0080
        L_0x006a:
            if (r10 != r5) goto L_0x0080
            int r5 = (int) r8
            int r10 = (int) r9
            android.view.View r5 = r0.findTopChildUnder(r5, r10)
            android.view.View r10 = r0.mCapturedView
            if (r5 != r10) goto L_0x0079
            r0.tryCaptureViewForDrag(r5, r7)
        L_0x0079:
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x0080:
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x0087:
            r16 = r2
            r17 = r3
            goto L_0x0151
        L_0x008d:
            float[] r5 = r0.mInitialMotionX
            if (r5 == 0) goto L_0x0147
            float[] r5 = r0.mInitialMotionY
            if (r5 != 0) goto L_0x009c
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x009c:
            int r5 = r22.getPointerCount()
            r7 = 0
        L_0x00a1:
            if (r7 >= r5) goto L_0x013c
            int r8 = r1.getPointerId(r7)
            boolean r9 = r0.isValidPointerForActionMove(r8)
            if (r9 != 0) goto L_0x00b5
            r16 = r2
            r17 = r3
            r19 = r5
            goto L_0x0131
        L_0x00b5:
            float r9 = r1.getX(r7)
            float r10 = r1.getY(r7)
            float[] r11 = r0.mInitialMotionX
            r11 = r11[r8]
            float r11 = r9 - r11
            float[] r12 = r0.mInitialMotionY
            r12 = r12[r8]
            float r12 = r10 - r12
            int r13 = (int) r9
            int r14 = (int) r10
            android.view.View r13 = r0.findTopChildUnder(r13, r14)
            if (r13 == 0) goto L_0x00d9
            boolean r14 = r0.checkTouchSlop(r13, r11, r12)
            if (r14 == 0) goto L_0x00d9
            r14 = r6
            goto L_0x00da
        L_0x00d9:
            r14 = 0
        L_0x00da:
            if (r14 == 0) goto L_0x0119
            int r15 = r13.getLeft()
            int r4 = (int) r11
            int r4 = r4 + r15
            androidx.customview.widget.ViewDragHelper$Callback r6 = r0.mCallback
            r16 = r2
            int r2 = (int) r11
            int r2 = r6.clampViewPositionHorizontal(r13, r4, r2)
            int r6 = r13.getTop()
            r17 = r3
            int r3 = (int) r12
            int r3 = r3 + r6
            r18 = r4
            androidx.customview.widget.ViewDragHelper$Callback r4 = r0.mCallback
            r19 = r5
            int r5 = (int) r12
            int r4 = r4.clampViewPositionVertical(r13, r3, r5)
            androidx.customview.widget.ViewDragHelper$Callback r5 = r0.mCallback
            int r5 = r5.getViewHorizontalDragRange(r13)
            r20 = r3
            androidx.customview.widget.ViewDragHelper$Callback r3 = r0.mCallback
            int r3 = r3.getViewVerticalDragRange(r13)
            if (r5 == 0) goto L_0x0112
            if (r5 <= 0) goto L_0x011f
            if (r2 != r15) goto L_0x011f
        L_0x0112:
            if (r3 == 0) goto L_0x0142
            if (r3 <= 0) goto L_0x011f
            if (r4 != r6) goto L_0x011f
            goto L_0x0142
        L_0x0119:
            r16 = r2
            r17 = r3
            r19 = r5
        L_0x011f:
            r0.reportNewEdgeDrags(r11, r12, r8)
            int r2 = r0.mDragState
            r3 = 1
            if (r2 != r3) goto L_0x0128
            goto L_0x0142
        L_0x0128:
            if (r14 == 0) goto L_0x0131
            boolean r2 = r0.tryCaptureViewForDrag(r13, r8)
            if (r2 == 0) goto L_0x0131
            goto L_0x0142
        L_0x0131:
            int r7 = r7 + 1
            r2 = r16
            r3 = r17
            r5 = r19
            r6 = 1
            goto L_0x00a1
        L_0x013c:
            r16 = r2
            r17 = r3
            r19 = r5
        L_0x0142:
            r21.saveLastMotion(r22)
            r4 = 0
            goto L_0x018b
        L_0x0147:
            r16 = r2
            r17 = r3
            r4 = 0
            goto L_0x018b
        L_0x014d:
            r16 = r2
            r17 = r3
        L_0x0151:
            r21.cancel()
            r4 = 0
            goto L_0x018b
        L_0x0156:
            r16 = r2
            r17 = r3
            float r2 = r22.getX()
            float r3 = r22.getY()
            r4 = 0
            int r6 = r1.getPointerId(r4)
            r0.saveInitialMotion(r2, r3, r6)
            int r7 = (int) r2
            int r8 = (int) r3
            android.view.View r7 = r0.findTopChildUnder(r7, r8)
            android.view.View r8 = r0.mCapturedView
            if (r7 != r8) goto L_0x017b
            int r8 = r0.mDragState
            if (r8 != r5) goto L_0x017b
            r0.tryCaptureViewForDrag(r7, r6)
        L_0x017b:
            int[] r5 = r0.mInitialEdgesTouched
            r5 = r5[r6]
            int r8 = r0.mTrackingEdges
            r9 = r5 & r8
            if (r9 == 0) goto L_0x018b
            androidx.customview.widget.ViewDragHelper$Callback r9 = r0.mCallback
            r8 = r8 & r5
            r9.onEdgeTouched(r8, r6)
        L_0x018b:
            int r2 = r0.mDragState
            r3 = 1
            if (r2 != r3) goto L_0x0191
            r4 = r3
        L_0x0191:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.customview.widget.ViewDragHelper.shouldInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    public void processTouchEvent(MotionEvent ev) {
        int action = ev.getActionMasked();
        int actionIndex = ev.getActionIndex();
        if (action == 0) {
            cancel();
        }
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        }
        this.mVelocityTracker.addMovement(ev);
        if (action == 0) {
            float x = ev.getX();
            float y = ev.getY();
            int pointerId = ev.getPointerId(0);
            View toCapture = findTopChildUnder((int) x, (int) y);
            saveInitialMotion(x, y, pointerId);
            tryCaptureViewForDrag(toCapture, pointerId);
            int edgesTouched = this.mInitialEdgesTouched[pointerId];
            int i = this.mTrackingEdges;
            if ((edgesTouched & i) != 0) {
                this.mCallback.onEdgeTouched(i & edgesTouched, pointerId);
            }
        } else if (action == 1) {
            if (this.mDragState == 1) {
                releaseViewForPointerUp();
            }
            cancel();
        } else if (action != 2) {
            if (action == 3) {
                if (this.mDragState == 1) {
                    dispatchViewReleased(0.0f, 0.0f);
                }
                cancel();
            } else if (action == 5) {
                int pointerId2 = ev.getPointerId(actionIndex);
                float x2 = ev.getX(actionIndex);
                float y2 = ev.getY(actionIndex);
                saveInitialMotion(x2, y2, pointerId2);
                if (this.mDragState == 0) {
                    tryCaptureViewForDrag(findTopChildUnder((int) x2, (int) y2), pointerId2);
                    int edgesTouched2 = this.mInitialEdgesTouched[pointerId2];
                    int i2 = this.mTrackingEdges;
                    if ((edgesTouched2 & i2) != 0) {
                        this.mCallback.onEdgeTouched(i2 & edgesTouched2, pointerId2);
                    }
                } else if (isCapturedViewUnder((int) x2, (int) y2)) {
                    tryCaptureViewForDrag(this.mCapturedView, pointerId2);
                }
            } else if (action == 6) {
                int pointerId3 = ev.getPointerId(actionIndex);
                if (this.mDragState == 1 && pointerId3 == this.mActivePointerId) {
                    int newActivePointer = -1;
                    int pointerCount = ev.getPointerCount();
                    int i3 = 0;
                    while (true) {
                        if (i3 >= pointerCount) {
                            break;
                        }
                        int id = ev.getPointerId(i3);
                        if (id != this.mActivePointerId) {
                            View findTopChildUnder = findTopChildUnder((int) ev.getX(i3), (int) ev.getY(i3));
                            View view = this.mCapturedView;
                            if (findTopChildUnder == view && tryCaptureViewForDrag(view, id)) {
                                newActivePointer = this.mActivePointerId;
                                break;
                            }
                        }
                        i3++;
                    }
                    if (newActivePointer == -1) {
                        releaseViewForPointerUp();
                    }
                }
                clearMotionHistory(pointerId3);
            }
        } else if (this.mDragState != 1) {
            int pointerCount2 = ev.getPointerCount();
            for (int i4 = 0; i4 < pointerCount2; i4++) {
                int pointerId4 = ev.getPointerId(i4);
                if (isValidPointerForActionMove(pointerId4)) {
                    float x3 = ev.getX(i4);
                    float y3 = ev.getY(i4);
                    float dx = x3 - this.mInitialMotionX[pointerId4];
                    float dy = y3 - this.mInitialMotionY[pointerId4];
                    reportNewEdgeDrags(dx, dy, pointerId4);
                    if (this.mDragState != 1) {
                        View toCapture2 = findTopChildUnder((int) x3, (int) y3);
                        if (checkTouchSlop(toCapture2, dx, dy) && tryCaptureViewForDrag(toCapture2, pointerId4)) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            saveLastMotion(ev);
        } else if (isValidPointerForActionMove(this.mActivePointerId)) {
            int index = ev.findPointerIndex(this.mActivePointerId);
            float x4 = ev.getX(index);
            float y4 = ev.getY(index);
            float[] fArr = this.mLastMotionX;
            int i5 = this.mActivePointerId;
            int idx = (int) (x4 - fArr[i5]);
            int idy = (int) (y4 - this.mLastMotionY[i5]);
            dragTo(this.mCapturedView.getLeft() + idx, this.mCapturedView.getTop() + idy, idx, idy);
            saveLastMotion(ev);
        }
    }

    private void reportNewEdgeDrags(float dx, float dy, int pointerId) {
        int dragsStarted = 0;
        if (checkNewEdgeDrag(dx, dy, pointerId, 1)) {
            dragsStarted = 0 | 1;
        }
        if (checkNewEdgeDrag(dy, dx, pointerId, 4)) {
            dragsStarted |= 4;
        }
        if (checkNewEdgeDrag(dx, dy, pointerId, 2)) {
            dragsStarted |= 2;
        }
        if (checkNewEdgeDrag(dy, dx, pointerId, 8)) {
            dragsStarted |= 8;
        }
        if (dragsStarted != 0) {
            int[] iArr = this.mEdgeDragsInProgress;
            iArr[pointerId] = iArr[pointerId] | dragsStarted;
            this.mCallback.onEdgeDragStarted(dragsStarted, pointerId);
        }
    }

    private boolean checkNewEdgeDrag(float delta, float odelta, int pointerId, int edge) {
        float absDelta = Math.abs(delta);
        float absODelta = Math.abs(odelta);
        boolean z = false;
        if (!((this.mInitialEdgesTouched[pointerId] & edge) != edge || (this.mTrackingEdges & edge) == 0 || (this.mEdgeDragsLocked[pointerId] & edge) == edge || (this.mEdgeDragsInProgress[pointerId] & edge) == edge)) {
            int i = this.mTouchSlop;
            if (absDelta > ((float) i) || absODelta > ((float) i)) {
                if (absDelta >= 0.5f * absODelta || !this.mCallback.onEdgeLock(edge)) {
                    if ((this.mEdgeDragsInProgress[pointerId] & edge) == 0 && absDelta > ((float) this.mTouchSlop)) {
                        z = true;
                    }
                    return z;
                }
                int[] iArr = this.mEdgeDragsLocked;
                iArr[pointerId] = iArr[pointerId] | edge;
                return false;
            }
        }
        return false;
    }

    private boolean checkTouchSlop(View child, float dx, float dy) {
        boolean z = false;
        if (child == null) {
            return false;
        }
        boolean checkHorizontal = this.mCallback.getViewHorizontalDragRange(child) > 0;
        boolean checkVertical = this.mCallback.getViewVerticalDragRange(child) > 0;
        if (checkHorizontal && checkVertical) {
            float f = (dx * dx) + (dy * dy);
            int i = this.mTouchSlop;
            if (f > ((float) (i * i))) {
                z = true;
            }
            return z;
        } else if (checkHorizontal) {
            if (Math.abs(dx) > ((float) this.mTouchSlop)) {
                z = true;
            }
            return z;
        } else if (!checkVertical) {
            return false;
        } else {
            if (Math.abs(dy) > ((float) this.mTouchSlop)) {
                z = true;
            }
            return z;
        }
    }

    public boolean checkTouchSlop(int directions) {
        int count = this.mInitialMotionX.length;
        for (int i = 0; i < count; i++) {
            if (checkTouchSlop(directions, i)) {
                return true;
            }
        }
        return false;
    }

    public boolean checkTouchSlop(int directions, int pointerId) {
        boolean z = false;
        if (!isPointerDown(pointerId)) {
            return false;
        }
        boolean checkHorizontal = (directions & 1) == 1;
        boolean checkVertical = (directions & 2) == 2;
        float dx = this.mLastMotionX[pointerId] - this.mInitialMotionX[pointerId];
        float dy = this.mLastMotionY[pointerId] - this.mInitialMotionY[pointerId];
        if (checkHorizontal && checkVertical) {
            float f = (dx * dx) + (dy * dy);
            int i = this.mTouchSlop;
            if (f > ((float) (i * i))) {
                z = true;
            }
            return z;
        } else if (checkHorizontal) {
            if (Math.abs(dx) > ((float) this.mTouchSlop)) {
                z = true;
            }
            return z;
        } else if (!checkVertical) {
            return false;
        } else {
            if (Math.abs(dy) > ((float) this.mTouchSlop)) {
                z = true;
            }
            return z;
        }
    }

    public boolean isEdgeTouched(int edges) {
        int count = this.mInitialEdgesTouched.length;
        for (int i = 0; i < count; i++) {
            if (isEdgeTouched(edges, i)) {
                return true;
            }
        }
        return false;
    }

    public boolean isEdgeTouched(int edges, int pointerId) {
        return isPointerDown(pointerId) && (this.mInitialEdgesTouched[pointerId] & edges) != 0;
    }

    private void releaseViewForPointerUp() {
        this.mVelocityTracker.computeCurrentVelocity(1000, this.mMaxVelocity);
        dispatchViewReleased(clampMag(this.mVelocityTracker.getXVelocity(this.mActivePointerId), this.mMinVelocity, this.mMaxVelocity), clampMag(this.mVelocityTracker.getYVelocity(this.mActivePointerId), this.mMinVelocity, this.mMaxVelocity));
    }

    private void dragTo(int left, int top, int dx, int dy) {
        int i = dx;
        int i2 = dy;
        int clampedX = left;
        int clampedY = top;
        int oldLeft = this.mCapturedView.getLeft();
        int oldTop = this.mCapturedView.getTop();
        if (i != 0) {
            clampedX = this.mCallback.clampViewPositionHorizontal(this.mCapturedView, left, i);
            ViewCompat.offsetLeftAndRight(this.mCapturedView, clampedX - oldLeft);
        } else {
            int i3 = left;
        }
        if (i2 != 0) {
            clampedY = this.mCallback.clampViewPositionVertical(this.mCapturedView, top, i2);
            ViewCompat.offsetTopAndBottom(this.mCapturedView, clampedY - oldTop);
        } else {
            int i4 = top;
        }
        if (i != 0 || i2 != 0) {
            this.mCallback.onViewPositionChanged(this.mCapturedView, clampedX, clampedY, clampedX - oldLeft, clampedY - oldTop);
        }
    }

    public boolean isCapturedViewUnder(int x, int y) {
        return isViewUnder(this.mCapturedView, x, y);
    }

    public boolean isViewUnder(View view, int x, int y) {
        boolean z = false;
        if (view == null) {
            return false;
        }
        if (x >= view.getLeft() && x < view.getRight() && y >= view.getTop() && y < view.getBottom()) {
            z = true;
        }
        return z;
    }

    public View findTopChildUnder(int x, int y) {
        for (int i = this.mParentView.getChildCount() - 1; i >= 0; i--) {
            View child = this.mParentView.getChildAt(this.mCallback.getOrderedChildIndex(i));
            if (x >= child.getLeft() && x < child.getRight() && y >= child.getTop() && y < child.getBottom()) {
                return child;
            }
        }
        return null;
    }

    private int getEdgesTouched(int x, int y) {
        int result = 0;
        if (x < this.mParentView.getLeft() + this.mEdgeSize) {
            result = 0 | 1;
        }
        if (y < this.mParentView.getTop() + this.mEdgeSize) {
            result |= 4;
        }
        if (x > this.mParentView.getRight() - this.mEdgeSize) {
            result |= 2;
        }
        if (y > this.mParentView.getBottom() - this.mEdgeSize) {
            return result | 8;
        }
        return result;
    }

    private boolean isValidPointerForActionMove(int pointerId) {
        if (isPointerDown(pointerId)) {
            return true;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Ignoring pointerId=");
        sb.append(pointerId);
        sb.append(" because ACTION_DOWN was not received ");
        sb.append("for this pointer before ACTION_MOVE. It likely happened because ");
        sb.append(" ViewDragHelper did not receive all the events in the event stream.");
        Log.e(TAG, sb.toString());
        return false;
    }
}
