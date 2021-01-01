package com.google.android.material.appbar;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior;

class ViewOffsetBehavior<V extends View> extends Behavior<V> {
    private int tempLeftRightOffset = 0;
    private int tempTopBottomOffset = 0;
    private ViewOffsetHelper viewOffsetHelper;

    public ViewOffsetBehavior() {
    }

    public ViewOffsetBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        layoutChild(parent, child, layoutDirection);
        if (this.viewOffsetHelper == null) {
            this.viewOffsetHelper = new ViewOffsetHelper(child);
        }
        this.viewOffsetHelper.onViewLayout();
        int i = this.tempTopBottomOffset;
        if (i != 0) {
            this.viewOffsetHelper.setTopAndBottomOffset(i);
            this.tempTopBottomOffset = 0;
        }
        int i2 = this.tempLeftRightOffset;
        if (i2 != 0) {
            this.viewOffsetHelper.setLeftAndRightOffset(i2);
            this.tempLeftRightOffset = 0;
        }
        return true;
    }

    /* access modifiers changed from: protected */
    public void layoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        parent.onLayoutChild(child, layoutDirection);
    }

    public boolean setTopAndBottomOffset(int offset) {
        ViewOffsetHelper viewOffsetHelper2 = this.viewOffsetHelper;
        if (viewOffsetHelper2 != null) {
            return viewOffsetHelper2.setTopAndBottomOffset(offset);
        }
        this.tempTopBottomOffset = offset;
        return false;
    }

    public boolean setLeftAndRightOffset(int offset) {
        ViewOffsetHelper viewOffsetHelper2 = this.viewOffsetHelper;
        if (viewOffsetHelper2 != null) {
            return viewOffsetHelper2.setLeftAndRightOffset(offset);
        }
        this.tempLeftRightOffset = offset;
        return false;
    }

    public int getTopAndBottomOffset() {
        ViewOffsetHelper viewOffsetHelper2 = this.viewOffsetHelper;
        if (viewOffsetHelper2 != null) {
            return viewOffsetHelper2.getTopAndBottomOffset();
        }
        return 0;
    }

    public int getLeftAndRightOffset() {
        ViewOffsetHelper viewOffsetHelper2 = this.viewOffsetHelper;
        if (viewOffsetHelper2 != null) {
            return viewOffsetHelper2.getLeftAndRightOffset();
        }
        return 0;
    }
}
