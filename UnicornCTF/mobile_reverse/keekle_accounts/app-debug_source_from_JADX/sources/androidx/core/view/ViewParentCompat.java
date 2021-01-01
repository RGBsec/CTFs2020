package androidx.core.view;

import android.os.Build.VERSION;
import android.util.Log;
import android.view.View;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;

public final class ViewParentCompat {
    private static final String TAG = "ViewParentCompat";
    private static int[] sTempNestedScrollConsumed;

    private ViewParentCompat() {
    }

    @Deprecated
    public static boolean requestSendAccessibilityEvent(ViewParent parent, View child, AccessibilityEvent event) {
        return parent.requestSendAccessibilityEvent(child, event);
    }

    public static boolean onStartNestedScroll(ViewParent parent, View child, View target, int nestedScrollAxes) {
        return onStartNestedScroll(parent, child, target, nestedScrollAxes, 0);
    }

    public static void onNestedScrollAccepted(ViewParent parent, View child, View target, int nestedScrollAxes) {
        onNestedScrollAccepted(parent, child, target, nestedScrollAxes, 0);
    }

    public static void onStopNestedScroll(ViewParent parent, View target) {
        onStopNestedScroll(parent, target, 0);
    }

    public static void onNestedScroll(ViewParent parent, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed) {
        onNestedScroll(parent, target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, 0, getTempNestedScrollConsumed());
    }

    public static void onNestedScroll(ViewParent parent, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type) {
        onNestedScroll(parent, target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, type, getTempNestedScrollConsumed());
    }

    public static void onNestedPreScroll(ViewParent parent, View target, int dx, int dy, int[] consumed) {
        onNestedPreScroll(parent, target, dx, dy, consumed, 0);
    }

    public static boolean onStartNestedScroll(ViewParent parent, View child, View target, int nestedScrollAxes, int type) {
        if (parent instanceof NestedScrollingParent2) {
            return ((NestedScrollingParent2) parent).onStartNestedScroll(child, target, nestedScrollAxes, type);
        }
        if (type == 0) {
            if (VERSION.SDK_INT >= 21) {
                try {
                    return parent.onStartNestedScroll(child, target, nestedScrollAxes);
                } catch (AbstractMethodError e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("ViewParent ");
                    sb.append(parent);
                    sb.append(" does not implement interface method onStartNestedScroll");
                    Log.e(TAG, sb.toString(), e);
                }
            } else if (parent instanceof NestedScrollingParent) {
                return ((NestedScrollingParent) parent).onStartNestedScroll(child, target, nestedScrollAxes);
            }
        }
        return false;
    }

    public static void onNestedScrollAccepted(ViewParent parent, View child, View target, int nestedScrollAxes, int type) {
        if (parent instanceof NestedScrollingParent2) {
            ((NestedScrollingParent2) parent).onNestedScrollAccepted(child, target, nestedScrollAxes, type);
        } else if (type != 0) {
        } else {
            if (VERSION.SDK_INT >= 21) {
                try {
                    parent.onNestedScrollAccepted(child, target, nestedScrollAxes);
                } catch (AbstractMethodError e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("ViewParent ");
                    sb.append(parent);
                    sb.append(" does not implement interface method onNestedScrollAccepted");
                    Log.e(TAG, sb.toString(), e);
                }
            } else if (parent instanceof NestedScrollingParent) {
                ((NestedScrollingParent) parent).onNestedScrollAccepted(child, target, nestedScrollAxes);
            }
        }
    }

    public static void onStopNestedScroll(ViewParent parent, View target, int type) {
        if (parent instanceof NestedScrollingParent2) {
            ((NestedScrollingParent2) parent).onStopNestedScroll(target, type);
        } else if (type != 0) {
        } else {
            if (VERSION.SDK_INT >= 21) {
                try {
                    parent.onStopNestedScroll(target);
                } catch (AbstractMethodError e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("ViewParent ");
                    sb.append(parent);
                    sb.append(" does not implement interface method onStopNestedScroll");
                    Log.e(TAG, sb.toString(), e);
                }
            } else if (parent instanceof NestedScrollingParent) {
                ((NestedScrollingParent) parent).onStopNestedScroll(target);
            }
        }
    }

    public static void onNestedScroll(ViewParent parent, View target, int dxConsumed, int dyConsumed, int dxUnconsumed, int dyUnconsumed, int type, int[] consumed) {
        ViewParent viewParent = parent;
        if (viewParent instanceof NestedScrollingParent3) {
            ((NestedScrollingParent3) viewParent).onNestedScroll(target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, type, consumed);
            return;
        }
        consumed[0] = consumed[0] + dxUnconsumed;
        consumed[1] = consumed[1] + dyUnconsumed;
        if (viewParent instanceof NestedScrollingParent2) {
            ((NestedScrollingParent2) viewParent).onNestedScroll(target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed, type);
        } else if (type != 0) {
        } else {
            if (VERSION.SDK_INT >= 21) {
                try {
                    parent.onNestedScroll(target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed);
                } catch (AbstractMethodError e) {
                    AbstractMethodError e2 = e;
                    StringBuilder sb = new StringBuilder();
                    sb.append("ViewParent ");
                    sb.append(parent);
                    sb.append(" does not implement interface method onNestedScroll");
                    Log.e(TAG, sb.toString(), e2);
                }
            } else if (viewParent instanceof NestedScrollingParent) {
                ((NestedScrollingParent) viewParent).onNestedScroll(target, dxConsumed, dyConsumed, dxUnconsumed, dyUnconsumed);
            }
        }
    }

    public static void onNestedPreScroll(ViewParent parent, View target, int dx, int dy, int[] consumed, int type) {
        if (parent instanceof NestedScrollingParent2) {
            ((NestedScrollingParent2) parent).onNestedPreScroll(target, dx, dy, consumed, type);
        } else if (type != 0) {
        } else {
            if (VERSION.SDK_INT >= 21) {
                try {
                    parent.onNestedPreScroll(target, dx, dy, consumed);
                } catch (AbstractMethodError e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("ViewParent ");
                    sb.append(parent);
                    sb.append(" does not implement interface method onNestedPreScroll");
                    Log.e(TAG, sb.toString(), e);
                }
            } else if (parent instanceof NestedScrollingParent) {
                ((NestedScrollingParent) parent).onNestedPreScroll(target, dx, dy, consumed);
            }
        }
    }

    public static boolean onNestedFling(ViewParent parent, View target, float velocityX, float velocityY, boolean consumed) {
        if (VERSION.SDK_INT >= 21) {
            try {
                return parent.onNestedFling(target, velocityX, velocityY, consumed);
            } catch (AbstractMethodError e) {
                StringBuilder sb = new StringBuilder();
                sb.append("ViewParent ");
                sb.append(parent);
                sb.append(" does not implement interface method onNestedFling");
                Log.e(TAG, sb.toString(), e);
            }
        } else {
            if (parent instanceof NestedScrollingParent) {
                return ((NestedScrollingParent) parent).onNestedFling(target, velocityX, velocityY, consumed);
            }
            return false;
        }
    }

    public static boolean onNestedPreFling(ViewParent parent, View target, float velocityX, float velocityY) {
        if (VERSION.SDK_INT >= 21) {
            try {
                return parent.onNestedPreFling(target, velocityX, velocityY);
            } catch (AbstractMethodError e) {
                StringBuilder sb = new StringBuilder();
                sb.append("ViewParent ");
                sb.append(parent);
                sb.append(" does not implement interface method onNestedPreFling");
                Log.e(TAG, sb.toString(), e);
            }
        } else {
            if (parent instanceof NestedScrollingParent) {
                return ((NestedScrollingParent) parent).onNestedPreFling(target, velocityX, velocityY);
            }
            return false;
        }
    }

    public static void notifySubtreeAccessibilityStateChanged(ViewParent parent, View child, View source, int changeType) {
        if (VERSION.SDK_INT >= 19) {
            parent.notifySubtreeAccessibilityStateChanged(child, source, changeType);
        }
    }

    private static int[] getTempNestedScrollConsumed() {
        int[] iArr = sTempNestedScrollConsumed;
        if (iArr == null) {
            sTempNestedScrollConsumed = new int[2];
        } else {
            iArr[0] = 0;
            iArr[1] = 0;
        }
        return sTempNestedScrollConsumed;
    }
}
