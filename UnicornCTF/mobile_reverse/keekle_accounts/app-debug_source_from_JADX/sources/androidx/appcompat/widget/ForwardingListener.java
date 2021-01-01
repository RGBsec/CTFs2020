package androidx.appcompat.widget;

import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnAttachStateChangeListener;
import android.view.View.OnTouchListener;
import android.view.ViewConfiguration;
import android.view.ViewParent;
import androidx.appcompat.view.menu.ShowableListMenu;

public abstract class ForwardingListener implements OnTouchListener, OnAttachStateChangeListener {
    private int mActivePointerId;
    private Runnable mDisallowIntercept;
    private boolean mForwarding;
    private final int mLongPressTimeout;
    private final float mScaledTouchSlop;
    final View mSrc;
    private final int mTapTimeout;
    private final int[] mTmpLocation = new int[2];
    private Runnable mTriggerLongPress;

    private class DisallowIntercept implements Runnable {
        DisallowIntercept() {
        }

        public void run() {
            ViewParent parent = ForwardingListener.this.mSrc.getParent();
            if (parent != null) {
                parent.requestDisallowInterceptTouchEvent(true);
            }
        }
    }

    private class TriggerLongPress implements Runnable {
        TriggerLongPress() {
        }

        public void run() {
            ForwardingListener.this.onLongPress();
        }
    }

    public abstract ShowableListMenu getPopup();

    public ForwardingListener(View src) {
        this.mSrc = src;
        src.setLongClickable(true);
        src.addOnAttachStateChangeListener(this);
        this.mScaledTouchSlop = (float) ViewConfiguration.get(src.getContext()).getScaledTouchSlop();
        int tapTimeout = ViewConfiguration.getTapTimeout();
        this.mTapTimeout = tapTimeout;
        this.mLongPressTimeout = (tapTimeout + ViewConfiguration.getLongPressTimeout()) / 2;
    }

    public boolean onTouch(View v, MotionEvent event) {
        boolean forwarding;
        MotionEvent motionEvent = event;
        boolean wasForwarding = this.mForwarding;
        if (wasForwarding) {
            forwarding = onTouchForwarded(motionEvent) || !onForwardingStopped();
        } else {
            forwarding = onTouchObserved(motionEvent) && onForwardingStarted();
            if (forwarding) {
                long now = SystemClock.uptimeMillis();
                MotionEvent e = MotionEvent.obtain(now, now, 3, 0.0f, 0.0f, 0);
                this.mSrc.onTouchEvent(e);
                e.recycle();
            }
        }
        this.mForwarding = forwarding;
        if (forwarding || wasForwarding) {
            return true;
        }
        return false;
    }

    public void onViewAttachedToWindow(View v) {
    }

    public void onViewDetachedFromWindow(View v) {
        this.mForwarding = false;
        this.mActivePointerId = -1;
        Runnable runnable = this.mDisallowIntercept;
        if (runnable != null) {
            this.mSrc.removeCallbacks(runnable);
        }
    }

    /* access modifiers changed from: protected */
    public boolean onForwardingStarted() {
        ShowableListMenu popup = getPopup();
        if (popup != null && !popup.isShowing()) {
            popup.show();
        }
        return true;
    }

    /* access modifiers changed from: protected */
    public boolean onForwardingStopped() {
        ShowableListMenu popup = getPopup();
        if (popup != null && popup.isShowing()) {
            popup.dismiss();
        }
        return true;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0017, code lost:
        if (r1 != 3) goto L_0x006f;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private boolean onTouchObserved(android.view.MotionEvent r9) {
        /*
            r8 = this;
            android.view.View r0 = r8.mSrc
            boolean r1 = r0.isEnabled()
            r2 = 0
            if (r1 != 0) goto L_0x000a
            return r2
        L_0x000a:
            int r1 = r9.getActionMasked()
            if (r1 == 0) goto L_0x0042
            r3 = 1
            if (r1 == r3) goto L_0x003e
            r4 = 2
            if (r1 == r4) goto L_0x001a
            r3 = 3
            if (r1 == r3) goto L_0x003e
            goto L_0x006f
        L_0x001a:
            int r4 = r8.mActivePointerId
            int r4 = r9.findPointerIndex(r4)
            if (r4 < 0) goto L_0x006f
            float r5 = r9.getX(r4)
            float r6 = r9.getY(r4)
            float r7 = r8.mScaledTouchSlop
            boolean r7 = pointInView(r0, r5, r6, r7)
            if (r7 != 0) goto L_0x003d
            r8.clearCallbacks()
            android.view.ViewParent r2 = r0.getParent()
            r2.requestDisallowInterceptTouchEvent(r3)
            return r3
        L_0x003d:
            goto L_0x006f
        L_0x003e:
            r8.clearCallbacks()
            goto L_0x006f
        L_0x0042:
            int r3 = r9.getPointerId(r2)
            r8.mActivePointerId = r3
            java.lang.Runnable r3 = r8.mDisallowIntercept
            if (r3 != 0) goto L_0x0053
            androidx.appcompat.widget.ForwardingListener$DisallowIntercept r3 = new androidx.appcompat.widget.ForwardingListener$DisallowIntercept
            r3.<init>()
            r8.mDisallowIntercept = r3
        L_0x0053:
            java.lang.Runnable r3 = r8.mDisallowIntercept
            int r4 = r8.mTapTimeout
            long r4 = (long) r4
            r0.postDelayed(r3, r4)
            java.lang.Runnable r3 = r8.mTriggerLongPress
            if (r3 != 0) goto L_0x0066
            androidx.appcompat.widget.ForwardingListener$TriggerLongPress r3 = new androidx.appcompat.widget.ForwardingListener$TriggerLongPress
            r3.<init>()
            r8.mTriggerLongPress = r3
        L_0x0066:
            java.lang.Runnable r3 = r8.mTriggerLongPress
            int r4 = r8.mLongPressTimeout
            long r4 = (long) r4
            r0.postDelayed(r3, r4)
        L_0x006f:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ForwardingListener.onTouchObserved(android.view.MotionEvent):boolean");
    }

    private void clearCallbacks() {
        Runnable runnable = this.mTriggerLongPress;
        if (runnable != null) {
            this.mSrc.removeCallbacks(runnable);
        }
        Runnable runnable2 = this.mDisallowIntercept;
        if (runnable2 != null) {
            this.mSrc.removeCallbacks(runnable2);
        }
    }

    /* access modifiers changed from: 0000 */
    public void onLongPress() {
        clearCallbacks();
        View src = this.mSrc;
        if (src.isEnabled() && !src.isLongClickable() && onForwardingStarted()) {
            src.getParent().requestDisallowInterceptTouchEvent(true);
            long now = SystemClock.uptimeMillis();
            MotionEvent e = MotionEvent.obtain(now, now, 3, 0.0f, 0.0f, 0);
            src.onTouchEvent(e);
            e.recycle();
            this.mForwarding = true;
        }
    }

    private boolean onTouchForwarded(MotionEvent srcEvent) {
        View src = this.mSrc;
        ShowableListMenu popup = getPopup();
        boolean z = false;
        if (popup == null || !popup.isShowing()) {
            return false;
        }
        DropDownListView dst = (DropDownListView) popup.getListView();
        if (dst == null || !dst.isShown()) {
            return false;
        }
        MotionEvent dstEvent = MotionEvent.obtainNoHistory(srcEvent);
        toGlobalMotionEvent(src, dstEvent);
        toLocalMotionEvent(dst, dstEvent);
        boolean handled = dst.onForwardedEvent(dstEvent, this.mActivePointerId);
        dstEvent.recycle();
        int action = srcEvent.getActionMasked();
        boolean keepForwarding = (action == 1 || action == 3) ? false : true;
        if (handled && keepForwarding) {
            z = true;
        }
        return z;
    }

    private static boolean pointInView(View view, float localX, float localY, float slop) {
        return localX >= (-slop) && localY >= (-slop) && localX < ((float) (view.getRight() - view.getLeft())) + slop && localY < ((float) (view.getBottom() - view.getTop())) + slop;
    }

    private boolean toLocalMotionEvent(View view, MotionEvent event) {
        int[] loc = this.mTmpLocation;
        view.getLocationOnScreen(loc);
        event.offsetLocation((float) (-loc[0]), (float) (-loc[1]));
        return true;
    }

    private boolean toGlobalMotionEvent(View view, MotionEvent event) {
        int[] loc = this.mTmpLocation;
        view.getLocationOnScreen(loc);
        event.offsetLocation((float) loc[0], (float) loc[1]);
        return true;
    }
}
