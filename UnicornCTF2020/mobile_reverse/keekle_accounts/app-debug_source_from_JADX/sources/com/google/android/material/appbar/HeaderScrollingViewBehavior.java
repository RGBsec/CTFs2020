package com.google.android.material.appbar;

import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams;
import androidx.core.math.MathUtils;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import java.util.List;

abstract class HeaderScrollingViewBehavior extends ViewOffsetBehavior<View> {
    private int overlayTop;
    final Rect tempRect1 = new Rect();
    final Rect tempRect2 = new Rect();
    private int verticalLayoutGap = 0;

    /* access modifiers changed from: 0000 */
    public abstract View findFirstDependency(List<View> list);

    public HeaderScrollingViewBehavior() {
    }

    public HeaderScrollingViewBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean onMeasureChild(CoordinatorLayout parent, View child, int parentWidthMeasureSpec, int widthUsed, int parentHeightMeasureSpec, int heightUsed) {
        int availableHeight;
        int childLpHeight = child.getLayoutParams().height;
        if (childLpHeight == -1 || childLpHeight == -2) {
            View header = findFirstDependency(parent.getDependencies(child));
            if (header != null) {
                if (!ViewCompat.getFitsSystemWindows(header) || ViewCompat.getFitsSystemWindows(child)) {
                    View view = child;
                } else {
                    ViewCompat.setFitsSystemWindows(child, true);
                    if (ViewCompat.getFitsSystemWindows(child)) {
                        child.requestLayout();
                        return true;
                    }
                }
                int availableHeight2 = MeasureSpec.getSize(parentHeightMeasureSpec);
                if (availableHeight2 == 0) {
                    availableHeight = parent.getHeight();
                } else {
                    availableHeight = availableHeight2;
                }
                parent.onMeasureChild(child, parentWidthMeasureSpec, widthUsed, MeasureSpec.makeMeasureSpec((availableHeight - header.getMeasuredHeight()) + getScrollRange(header), childLpHeight == -1 ? 1073741824 : Integer.MIN_VALUE), heightUsed);
                return true;
            }
            View view2 = child;
        } else {
            View view3 = child;
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public void layoutChild(CoordinatorLayout parent, View child, int layoutDirection) {
        View header = findFirstDependency(parent.getDependencies(child));
        if (header != null) {
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            Rect available = this.tempRect1;
            available.set(parent.getPaddingLeft() + lp.leftMargin, header.getBottom() + lp.topMargin, (parent.getWidth() - parent.getPaddingRight()) - lp.rightMargin, ((parent.getHeight() + header.getBottom()) - parent.getPaddingBottom()) - lp.bottomMargin);
            WindowInsetsCompat parentInsets = parent.getLastWindowInsets();
            if (parentInsets != null && ViewCompat.getFitsSystemWindows(parent) && !ViewCompat.getFitsSystemWindows(child)) {
                available.left += parentInsets.getSystemWindowInsetLeft();
                available.right -= parentInsets.getSystemWindowInsetRight();
            }
            Rect out = this.tempRect2;
            GravityCompat.apply(resolveGravity(lp.gravity), child.getMeasuredWidth(), child.getMeasuredHeight(), available, out, layoutDirection);
            int overlap = getOverlapPixelsForOffset(header);
            child.layout(out.left, out.top - overlap, out.right, out.bottom - overlap);
            this.verticalLayoutGap = out.top - header.getBottom();
            return;
        }
        super.layoutChild(parent, child, layoutDirection);
        this.verticalLayoutGap = 0;
    }

    /* access modifiers changed from: 0000 */
    public float getOverlapRatioForOffset(View header) {
        return 1.0f;
    }

    /* access modifiers changed from: 0000 */
    public final int getOverlapPixelsForOffset(View header) {
        if (this.overlayTop == 0) {
            return 0;
        }
        float overlapRatioForOffset = getOverlapRatioForOffset(header);
        int i = this.overlayTop;
        return MathUtils.clamp((int) (overlapRatioForOffset * ((float) i)), 0, i);
    }

    private static int resolveGravity(int gravity) {
        if (gravity == 0) {
            return 8388659;
        }
        return gravity;
    }

    /* access modifiers changed from: 0000 */
    public int getScrollRange(View v) {
        return v.getMeasuredHeight();
    }

    /* access modifiers changed from: 0000 */
    public final int getVerticalLayoutGap() {
        return this.verticalLayoutGap;
    }

    public final void setOverlayTop(int overlayTop2) {
        this.overlayTop = overlayTop2;
    }

    public final int getOverlayTop() {
        return this.overlayTop;
    }
}
