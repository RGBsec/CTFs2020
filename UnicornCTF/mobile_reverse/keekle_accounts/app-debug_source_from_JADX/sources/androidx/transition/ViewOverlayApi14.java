package androidx.transition;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.core.view.ViewCompat;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;

class ViewOverlayApi14 implements ViewOverlayImpl {
    protected OverlayViewGroup mOverlayViewGroup;

    static class OverlayViewGroup extends ViewGroup {
        static Method sInvalidateChildInParentFastMethod;
        ArrayList<Drawable> mDrawables = null;
        ViewGroup mHostView;
        View mRequestingView;
        ViewOverlayApi14 mViewOverlay;

        static class TouchInterceptor extends View {
            TouchInterceptor(Context context) {
                super(context);
            }
        }

        static {
            try {
                sInvalidateChildInParentFastMethod = ViewGroup.class.getDeclaredMethod("invalidateChildInParentFast", new Class[]{Integer.TYPE, Integer.TYPE, Rect.class});
            } catch (NoSuchMethodException e) {
            }
        }

        OverlayViewGroup(Context context, ViewGroup hostView, View requestingView, ViewOverlayApi14 viewOverlay) {
            super(context);
            this.mHostView = hostView;
            this.mRequestingView = requestingView;
            setRight(hostView.getWidth());
            setBottom(hostView.getHeight());
            hostView.addView(this);
            this.mViewOverlay = viewOverlay;
        }

        public boolean dispatchTouchEvent(MotionEvent ev) {
            return false;
        }

        public void add(Drawable drawable) {
            if (this.mDrawables == null) {
                this.mDrawables = new ArrayList<>();
            }
            if (!this.mDrawables.contains(drawable)) {
                this.mDrawables.add(drawable);
                invalidate(drawable.getBounds());
                drawable.setCallback(this);
            }
        }

        public void remove(Drawable drawable) {
            ArrayList<Drawable> arrayList = this.mDrawables;
            if (arrayList != null) {
                arrayList.remove(drawable);
                invalidate(drawable.getBounds());
                drawable.setCallback(null);
            }
        }

        /* access modifiers changed from: protected */
        public boolean verifyDrawable(Drawable who) {
            if (!super.verifyDrawable(who)) {
                ArrayList<Drawable> arrayList = this.mDrawables;
                if (arrayList == null || !arrayList.contains(who)) {
                    return false;
                }
            }
            return true;
        }

        public void add(View child) {
            if (child.getParent() instanceof ViewGroup) {
                ViewGroup parent = (ViewGroup) child.getParent();
                if (!(parent == this.mHostView || parent.getParent() == null || !ViewCompat.isAttachedToWindow(parent))) {
                    int[] parentLocation = new int[2];
                    int[] hostViewLocation = new int[2];
                    parent.getLocationOnScreen(parentLocation);
                    this.mHostView.getLocationOnScreen(hostViewLocation);
                    ViewCompat.offsetLeftAndRight(child, parentLocation[0] - hostViewLocation[0]);
                    ViewCompat.offsetTopAndBottom(child, parentLocation[1] - hostViewLocation[1]);
                }
                parent.removeView(child);
                if (child.getParent() != null) {
                    parent.removeView(child);
                }
            }
            super.addView(child, getChildCount() - 1);
        }

        public void remove(View view) {
            super.removeView(view);
            if (isEmpty()) {
                this.mHostView.removeView(this);
            }
        }

        public void clear() {
            removeAllViews();
            ArrayList<Drawable> arrayList = this.mDrawables;
            if (arrayList != null) {
                arrayList.clear();
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean isEmpty() {
            if (getChildCount() == 0) {
                ArrayList<Drawable> arrayList = this.mDrawables;
                if (arrayList == null || arrayList.size() == 0) {
                    return true;
                }
            }
            return false;
        }

        public void invalidateDrawable(Drawable drawable) {
            invalidate(drawable.getBounds());
        }

        /* access modifiers changed from: protected */
        public void dispatchDraw(Canvas canvas) {
            int[] contentViewLocation = new int[2];
            int[] hostViewLocation = new int[2];
            this.mHostView.getLocationOnScreen(contentViewLocation);
            this.mRequestingView.getLocationOnScreen(hostViewLocation);
            int numDrawables = 0;
            canvas.translate((float) (hostViewLocation[0] - contentViewLocation[0]), (float) (hostViewLocation[1] - contentViewLocation[1]));
            canvas.clipRect(new Rect(0, 0, this.mRequestingView.getWidth(), this.mRequestingView.getHeight()));
            super.dispatchDraw(canvas);
            ArrayList<Drawable> arrayList = this.mDrawables;
            if (arrayList != null) {
                numDrawables = arrayList.size();
            }
            for (int i = 0; i < numDrawables; i++) {
                ((Drawable) this.mDrawables.get(i)).draw(canvas);
            }
        }

        /* access modifiers changed from: protected */
        public void onLayout(boolean changed, int l, int t, int r, int b) {
        }

        private void getOffset(int[] offset) {
            int[] contentViewLocation = new int[2];
            int[] hostViewLocation = new int[2];
            this.mHostView.getLocationOnScreen(contentViewLocation);
            this.mRequestingView.getLocationOnScreen(hostViewLocation);
            offset[0] = hostViewLocation[0] - contentViewLocation[0];
            offset[1] = hostViewLocation[1] - contentViewLocation[1];
        }

        public void invalidateChildFast(View child, Rect dirty) {
            if (this.mHostView != null) {
                int left = child.getLeft();
                int top = child.getTop();
                int[] offset = new int[2];
                getOffset(offset);
                dirty.offset(offset[0] + left, offset[1] + top);
                this.mHostView.invalidate(dirty);
            }
        }

        /* access modifiers changed from: protected */
        public ViewParent invalidateChildInParentFast(int left, int top, Rect dirty) {
            if ((this.mHostView instanceof ViewGroup) && sInvalidateChildInParentFastMethod != null) {
                try {
                    getOffset(new int[2]);
                    sInvalidateChildInParentFastMethod.invoke(this.mHostView, new Object[]{Integer.valueOf(left), Integer.valueOf(top), dirty});
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InvocationTargetException e2) {
                    e2.printStackTrace();
                }
            }
            return null;
        }

        public ViewParent invalidateChildInParent(int[] location, Rect dirty) {
            if (this.mHostView != null) {
                dirty.offset(location[0], location[1]);
                if (this.mHostView instanceof ViewGroup) {
                    location[0] = 0;
                    location[1] = 0;
                    int[] offset = new int[2];
                    getOffset(offset);
                    dirty.offset(offset[0], offset[1]);
                    return super.invalidateChildInParent(location, dirty);
                }
                invalidate(dirty);
            }
            return null;
        }
    }

    ViewOverlayApi14(Context context, ViewGroup hostView, View requestingView) {
        this.mOverlayViewGroup = new OverlayViewGroup(context, hostView, requestingView, this);
    }

    static ViewGroup getContentView(View view) {
        View parent = view;
        while (parent != null) {
            if (parent.getId() == 16908290 && (parent instanceof ViewGroup)) {
                return (ViewGroup) parent;
            }
            if (parent.getParent() instanceof ViewGroup) {
                parent = (ViewGroup) parent.getParent();
            }
        }
        return null;
    }

    static ViewOverlayApi14 createFrom(View view) {
        ViewGroup contentView = getContentView(view);
        if (contentView == null) {
            return null;
        }
        int numChildren = contentView.getChildCount();
        for (int i = 0; i < numChildren; i++) {
            View child = contentView.getChildAt(i);
            if (child instanceof OverlayViewGroup) {
                return ((OverlayViewGroup) child).mViewOverlay;
            }
        }
        return new ViewGroupOverlayApi14(contentView.getContext(), contentView, view);
    }

    /* access modifiers changed from: 0000 */
    public ViewGroup getOverlayView() {
        return this.mOverlayViewGroup;
    }

    public void add(Drawable drawable) {
        this.mOverlayViewGroup.add(drawable);
    }

    public void clear() {
        this.mOverlayViewGroup.clear();
    }

    public void remove(Drawable drawable) {
        this.mOverlayViewGroup.remove(drawable);
    }

    /* access modifiers changed from: 0000 */
    public boolean isEmpty() {
        return this.mOverlayViewGroup.isEmpty();
    }

    private ViewOverlayApi14() {
    }
}
