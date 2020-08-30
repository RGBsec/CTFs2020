package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup.LayoutParams;
import android.widget.AbsListView;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.appcompat.C0003R;
import androidx.appcompat.graphics.drawable.DrawableWrapper;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewPropertyAnimatorCompat;
import androidx.core.widget.ListViewAutoScrollHelper;
import java.lang.reflect.Field;

class DropDownListView extends ListView {
    public static final int INVALID_POSITION = -1;
    public static final int NO_POSITION = -1;
    private ViewPropertyAnimatorCompat mClickAnimation;
    private boolean mDrawsInPressedState;
    private boolean mHijackFocus;
    private Field mIsChildViewEnabled;
    private boolean mListSelectionHidden;
    private int mMotionPosition;
    ResolveHoverRunnable mResolveHoverRunnable;
    private ListViewAutoScrollHelper mScrollHelper;
    private int mSelectionBottomPadding = 0;
    private int mSelectionLeftPadding = 0;
    private int mSelectionRightPadding = 0;
    private int mSelectionTopPadding = 0;
    private GateKeeperDrawable mSelector;
    private final Rect mSelectorRect = new Rect();

    private static class GateKeeperDrawable extends DrawableWrapper {
        private boolean mEnabled = true;

        GateKeeperDrawable(Drawable drawable) {
            super(drawable);
        }

        /* access modifiers changed from: 0000 */
        public void setEnabled(boolean enabled) {
            this.mEnabled = enabled;
        }

        public boolean setState(int[] stateSet) {
            if (this.mEnabled) {
                return super.setState(stateSet);
            }
            return false;
        }

        public void draw(Canvas canvas) {
            if (this.mEnabled) {
                super.draw(canvas);
            }
        }

        public void setHotspot(float x, float y) {
            if (this.mEnabled) {
                super.setHotspot(x, y);
            }
        }

        public void setHotspotBounds(int left, int top, int right, int bottom) {
            if (this.mEnabled) {
                super.setHotspotBounds(left, top, right, bottom);
            }
        }

        public boolean setVisible(boolean visible, boolean restart) {
            if (this.mEnabled) {
                return super.setVisible(visible, restart);
            }
            return false;
        }
    }

    private class ResolveHoverRunnable implements Runnable {
        ResolveHoverRunnable() {
        }

        public void run() {
            DropDownListView.this.mResolveHoverRunnable = null;
            DropDownListView.this.drawableStateChanged();
        }

        public void cancel() {
            DropDownListView.this.mResolveHoverRunnable = null;
            DropDownListView.this.removeCallbacks(this);
        }

        public void post() {
            DropDownListView.this.post(this);
        }
    }

    DropDownListView(Context context, boolean hijackFocus) {
        super(context, null, C0003R.attr.dropDownListViewStyle);
        this.mHijackFocus = hijackFocus;
        setCacheColorHint(0);
        try {
            Field declaredField = AbsListView.class.getDeclaredField("mIsChildViewEnabled");
            this.mIsChildViewEnabled = declaredField;
            declaredField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    public boolean isInTouchMode() {
        return (this.mHijackFocus && this.mListSelectionHidden) || super.isInTouchMode();
    }

    public boolean hasWindowFocus() {
        return this.mHijackFocus || super.hasWindowFocus();
    }

    public boolean isFocused() {
        return this.mHijackFocus || super.isFocused();
    }

    public boolean hasFocus() {
        return this.mHijackFocus || super.hasFocus();
    }

    public void setSelector(Drawable sel) {
        GateKeeperDrawable gateKeeperDrawable = sel != null ? new GateKeeperDrawable(sel) : null;
        this.mSelector = gateKeeperDrawable;
        super.setSelector(gateKeeperDrawable);
        Rect padding = new Rect();
        if (sel != null) {
            sel.getPadding(padding);
        }
        this.mSelectionLeftPadding = padding.left;
        this.mSelectionTopPadding = padding.top;
        this.mSelectionRightPadding = padding.right;
        this.mSelectionBottomPadding = padding.bottom;
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        if (this.mResolveHoverRunnable == null) {
            super.drawableStateChanged();
            setSelectorEnabled(true);
            updateSelectorStateCompat();
        }
    }

    /* access modifiers changed from: protected */
    public void dispatchDraw(Canvas canvas) {
        drawSelectorCompat(canvas);
        super.dispatchDraw(canvas);
    }

    public boolean onTouchEvent(MotionEvent ev) {
        if (ev.getAction() == 0) {
            this.mMotionPosition = pointToPosition((int) ev.getX(), (int) ev.getY());
        }
        ResolveHoverRunnable resolveHoverRunnable = this.mResolveHoverRunnable;
        if (resolveHoverRunnable != null) {
            resolveHoverRunnable.cancel();
        }
        return super.onTouchEvent(ev);
    }

    public int lookForSelectablePosition(int position, boolean lookDown) {
        int position2;
        ListAdapter adapter = getAdapter();
        if (adapter == null || isInTouchMode()) {
            return -1;
        }
        int count = adapter.getCount();
        if (!getAdapter().areAllItemsEnabled()) {
            if (lookDown) {
                position2 = Math.max(0, position);
                while (position2 < count && !adapter.isEnabled(position2)) {
                    position2++;
                }
            } else {
                int position3 = Math.min(position, count - 1);
                while (position2 >= 0 && !adapter.isEnabled(position2)) {
                    position3 = position2 - 1;
                }
            }
            if (position2 < 0 || position2 >= count) {
                return -1;
            }
            return position2;
        } else if (position < 0 || position >= count) {
            return -1;
        } else {
            return position;
        }
    }

    public int measureHeightOfChildrenCompat(int widthMeasureSpec, int startPosition, int endPosition, int maxHeight, int disallowPartialChildPosition) {
        LayoutParams childLp;
        int heightMeasureSpec;
        int i = maxHeight;
        int i2 = disallowPartialChildPosition;
        int paddingTop = getListPaddingTop();
        int paddingBottom = getListPaddingBottom();
        int listPaddingLeft = getListPaddingLeft();
        int listPaddingRight = getListPaddingRight();
        int reportedDividerHeight = getDividerHeight();
        Drawable divider = getDivider();
        ListAdapter adapter = getAdapter();
        if (adapter == null) {
            return paddingTop + paddingBottom;
        }
        int returnedHeight = paddingTop + paddingBottom;
        int dividerHeight = (reportedDividerHeight <= 0 || divider == null) ? 0 : reportedDividerHeight;
        int prevHeightWithoutPartialChild = 0;
        View child = null;
        int viewType = 0;
        int count = adapter.getCount();
        int i3 = 0;
        while (i3 < count) {
            int paddingTop2 = paddingTop;
            int paddingTop3 = adapter.getItemViewType(i3);
            if (paddingTop3 != viewType) {
                child = null;
                viewType = paddingTop3;
            }
            int i4 = paddingTop3;
            child = adapter.getView(i3, child, this);
            LayoutParams childLp2 = child.getLayoutParams();
            if (childLp2 == null) {
                childLp = generateDefaultLayoutParams();
                child.setLayoutParams(childLp);
            } else {
                childLp = childLp2;
            }
            int paddingBottom2 = paddingBottom;
            if (childLp.height > 0) {
                LayoutParams layoutParams = childLp;
                heightMeasureSpec = MeasureSpec.makeMeasureSpec(childLp.height, 1073741824);
            } else {
                heightMeasureSpec = MeasureSpec.makeMeasureSpec(0, 0);
            }
            child.measure(widthMeasureSpec, heightMeasureSpec);
            child.forceLayout();
            if (i3 > 0) {
                returnedHeight += dividerHeight;
            }
            returnedHeight += child.getMeasuredHeight();
            if (returnedHeight >= i) {
                return (i2 < 0 || i3 <= i2 || prevHeightWithoutPartialChild <= 0 || returnedHeight == i) ? i : prevHeightWithoutPartialChild;
            }
            if (i2 >= 0 && i3 >= i2) {
                prevHeightWithoutPartialChild = returnedHeight;
            }
            i3++;
            paddingTop = paddingTop2;
            paddingBottom = paddingBottom2;
        }
        return returnedHeight;
    }

    private void setSelectorEnabled(boolean enabled) {
        GateKeeperDrawable gateKeeperDrawable = this.mSelector;
        if (gateKeeperDrawable != null) {
            gateKeeperDrawable.setEnabled(enabled);
        }
    }

    public boolean onHoverEvent(MotionEvent ev) {
        if (VERSION.SDK_INT < 26) {
            return super.onHoverEvent(ev);
        }
        int action = ev.getActionMasked();
        if (action == 10 && this.mResolveHoverRunnable == null) {
            ResolveHoverRunnable resolveHoverRunnable = new ResolveHoverRunnable();
            this.mResolveHoverRunnable = resolveHoverRunnable;
            resolveHoverRunnable.post();
        }
        boolean handled = super.onHoverEvent(ev);
        if (action == 9 || action == 7) {
            int position = pointToPosition((int) ev.getX(), (int) ev.getY());
            if (!(position == -1 || position == getSelectedItemPosition())) {
                View hoveredItem = getChildAt(position - getFirstVisiblePosition());
                if (hoveredItem.isEnabled()) {
                    setSelectionFromTop(position, hoveredItem.getTop() - getTop());
                }
                updateSelectorStateCompat();
            }
        } else {
            setSelection(-1);
        }
        return handled;
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        this.mResolveHoverRunnable = null;
        super.onDetachedFromWindow();
    }

    /* JADX WARNING: Removed duplicated region for block: B:21:0x004c  */
    /* JADX WARNING: Removed duplicated region for block: B:25:0x0062  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean onForwardedEvent(android.view.MotionEvent r12, int r13) {
        /*
            r11 = this;
            r0 = 1
            r1 = 0
            int r2 = r12.getActionMasked()
            r3 = 1
            if (r2 == r3) goto L_0x0012
            r4 = 2
            if (r2 == r4) goto L_0x0013
            r4 = 3
            if (r2 == r4) goto L_0x0010
            goto L_0x0043
        L_0x0010:
            r0 = 0
            goto L_0x0043
        L_0x0012:
            r0 = 0
        L_0x0013:
            int r4 = r12.findPointerIndex(r13)
            if (r4 >= 0) goto L_0x001b
            r0 = 0
            goto L_0x0043
        L_0x001b:
            float r5 = r12.getX(r4)
            int r5 = (int) r5
            float r6 = r12.getY(r4)
            int r6 = (int) r6
            int r7 = r11.pointToPosition(r5, r6)
            r8 = -1
            if (r7 != r8) goto L_0x002e
            r1 = 1
            goto L_0x0043
        L_0x002e:
            int r8 = r11.getFirstVisiblePosition()
            int r8 = r7 - r8
            android.view.View r8 = r11.getChildAt(r8)
            float r9 = (float) r5
            float r10 = (float) r6
            r11.setPressedItem(r8, r7, r9, r10)
            r0 = 1
            if (r2 != r3) goto L_0x0043
            r11.clickPressedItem(r8, r7)
        L_0x0043:
            if (r0 == 0) goto L_0x0047
            if (r1 == 0) goto L_0x004a
        L_0x0047:
            r11.clearPressedItem()
        L_0x004a:
            if (r0 == 0) goto L_0x0062
            androidx.core.widget.ListViewAutoScrollHelper r4 = r11.mScrollHelper
            if (r4 != 0) goto L_0x0057
            androidx.core.widget.ListViewAutoScrollHelper r4 = new androidx.core.widget.ListViewAutoScrollHelper
            r4.<init>(r11)
            r11.mScrollHelper = r4
        L_0x0057:
            androidx.core.widget.ListViewAutoScrollHelper r4 = r11.mScrollHelper
            r4.setEnabled(r3)
            androidx.core.widget.ListViewAutoScrollHelper r3 = r11.mScrollHelper
            r3.onTouch(r11, r12)
            goto L_0x006a
        L_0x0062:
            androidx.core.widget.ListViewAutoScrollHelper r3 = r11.mScrollHelper
            if (r3 == 0) goto L_0x006a
            r4 = 0
            r3.setEnabled(r4)
        L_0x006a:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.DropDownListView.onForwardedEvent(android.view.MotionEvent, int):boolean");
    }

    private void clickPressedItem(View child, int position) {
        performItemClick(child, position, getItemIdAtPosition(position));
    }

    /* access modifiers changed from: 0000 */
    public void setListSelectionHidden(boolean hideListSelection) {
        this.mListSelectionHidden = hideListSelection;
    }

    private void updateSelectorStateCompat() {
        Drawable selector = getSelector();
        if (selector != null && touchModeDrawsInPressedStateCompat() && isPressed()) {
            selector.setState(getDrawableState());
        }
    }

    private void drawSelectorCompat(Canvas canvas) {
        if (!this.mSelectorRect.isEmpty()) {
            Drawable selector = getSelector();
            if (selector != null) {
                selector.setBounds(this.mSelectorRect);
                selector.draw(canvas);
            }
        }
    }

    private void positionSelectorLikeTouchCompat(int position, View sel, float x, float y) {
        positionSelectorLikeFocusCompat(position, sel);
        Drawable selector = getSelector();
        if (selector != null && position != -1) {
            DrawableCompat.setHotspot(selector, x, y);
        }
    }

    private void positionSelectorLikeFocusCompat(int position, View sel) {
        Drawable selector = getSelector();
        boolean z = true;
        boolean manageState = (selector == null || position == -1) ? false : true;
        if (manageState) {
            selector.setVisible(false, false);
        }
        positionSelectorCompat(position, sel);
        if (manageState) {
            Rect bounds = this.mSelectorRect;
            float x = bounds.exactCenterX();
            float y = bounds.exactCenterY();
            if (getVisibility() != 0) {
                z = false;
            }
            selector.setVisible(z, false);
            DrawableCompat.setHotspot(selector, x, y);
        }
    }

    private void positionSelectorCompat(int position, View sel) {
        Rect selectorRect = this.mSelectorRect;
        selectorRect.set(sel.getLeft(), sel.getTop(), sel.getRight(), sel.getBottom());
        selectorRect.left -= this.mSelectionLeftPadding;
        selectorRect.top -= this.mSelectionTopPadding;
        selectorRect.right += this.mSelectionRightPadding;
        selectorRect.bottom += this.mSelectionBottomPadding;
        try {
            boolean isChildViewEnabled = this.mIsChildViewEnabled.getBoolean(this);
            if (sel.isEnabled() != isChildViewEnabled) {
                this.mIsChildViewEnabled.set(this, Boolean.valueOf(!isChildViewEnabled));
                if (position != -1) {
                    refreshDrawableState();
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    private void clearPressedItem() {
        this.mDrawsInPressedState = false;
        setPressed(false);
        drawableStateChanged();
        View motionView = getChildAt(this.mMotionPosition - getFirstVisiblePosition());
        if (motionView != null) {
            motionView.setPressed(false);
        }
        ViewPropertyAnimatorCompat viewPropertyAnimatorCompat = this.mClickAnimation;
        if (viewPropertyAnimatorCompat != null) {
            viewPropertyAnimatorCompat.cancel();
            this.mClickAnimation = null;
        }
    }

    private void setPressedItem(View child, int position, float x, float y) {
        this.mDrawsInPressedState = true;
        if (VERSION.SDK_INT >= 21) {
            drawableHotspotChanged(x, y);
        }
        if (!isPressed()) {
            setPressed(true);
        }
        layoutChildren();
        int i = this.mMotionPosition;
        if (i != -1) {
            View motionView = getChildAt(i - getFirstVisiblePosition());
            if (!(motionView == null || motionView == child || !motionView.isPressed())) {
                motionView.setPressed(false);
            }
        }
        this.mMotionPosition = position;
        float childX = x - ((float) child.getLeft());
        float childY = y - ((float) child.getTop());
        if (VERSION.SDK_INT >= 21) {
            child.drawableHotspotChanged(childX, childY);
        }
        if (!child.isPressed()) {
            child.setPressed(true);
        }
        positionSelectorLikeTouchCompat(position, child, x, y);
        setSelectorEnabled(false);
        refreshDrawableState();
    }

    private boolean touchModeDrawsInPressedStateCompat() {
        return this.mDrawsInPressedState;
    }
}
