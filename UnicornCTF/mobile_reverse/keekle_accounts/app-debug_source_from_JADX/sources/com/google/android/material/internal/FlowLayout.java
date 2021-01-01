package com.google.android.material.internal;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.C0078R;

public class FlowLayout extends ViewGroup {
    private int itemSpacing;
    private int lineSpacing;
    private boolean singleLine;

    public FlowLayout(Context context) {
        this(context, null);
    }

    public FlowLayout(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public FlowLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.singleLine = false;
        loadFromAttributes(context, attrs);
    }

    public FlowLayout(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        this.singleLine = false;
        loadFromAttributes(context, attrs);
    }

    private void loadFromAttributes(Context context, AttributeSet attrs) {
        TypedArray array = context.getTheme().obtainStyledAttributes(attrs, C0078R.styleable.FlowLayout, 0, 0);
        this.lineSpacing = array.getDimensionPixelSize(C0078R.styleable.FlowLayout_lineSpacing, 0);
        this.itemSpacing = array.getDimensionPixelSize(C0078R.styleable.FlowLayout_itemSpacing, 0);
        array.recycle();
    }

    /* access modifiers changed from: protected */
    public int getLineSpacing() {
        return this.lineSpacing;
    }

    /* access modifiers changed from: protected */
    public void setLineSpacing(int lineSpacing2) {
        this.lineSpacing = lineSpacing2;
    }

    /* access modifiers changed from: protected */
    public int getItemSpacing() {
        return this.itemSpacing;
    }

    /* access modifiers changed from: protected */
    public void setItemSpacing(int itemSpacing2) {
        this.itemSpacing = itemSpacing2;
    }

    /* access modifiers changed from: protected */
    public boolean isSingleLine() {
        return this.singleLine;
    }

    public void setSingleLine(boolean singleLine2) {
        this.singleLine = singleLine2;
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int maxWidth;
        int width = MeasureSpec.getSize(widthMeasureSpec);
        int widthMode = MeasureSpec.getMode(widthMeasureSpec);
        int height = MeasureSpec.getSize(heightMeasureSpec);
        int heightMode = MeasureSpec.getMode(heightMeasureSpec);
        int maxWidth2 = (widthMode == Integer.MIN_VALUE || widthMode == 1073741824) ? width : ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        int childLeft = getPaddingLeft();
        int childTop = getPaddingTop();
        int childBottom = childTop;
        int i = childLeft;
        int maxChildRight = 0;
        int maxRight = maxWidth2 - getPaddingRight();
        int i2 = 0;
        while (i2 < getChildCount()) {
            View child = getChildAt(i2);
            if (child.getVisibility() == 8) {
                int i3 = widthMeasureSpec;
                int i4 = heightMeasureSpec;
                maxWidth = maxWidth2;
            } else {
                measureChild(child, widthMeasureSpec, heightMeasureSpec);
                maxWidth = maxWidth2;
                LayoutParams lp = child.getLayoutParams();
                int leftMargin = 0;
                int rightMargin = 0;
                int childTop2 = childTop;
                if ((lp instanceof MarginLayoutParams) != 0) {
                    MarginLayoutParams marginLp = (MarginLayoutParams) lp;
                    LayoutParams layoutParams = lp;
                    leftMargin = 0 + marginLp.leftMargin;
                    rightMargin = 0 + marginLp.rightMargin;
                }
                if (childLeft + leftMargin + child.getMeasuredWidth() <= maxRight || isSingleLine()) {
                    childTop = childTop2;
                } else {
                    childLeft = getPaddingLeft();
                    childTop = this.lineSpacing + childBottom;
                }
                int childRight = childLeft + leftMargin + child.getMeasuredWidth();
                int childBottom2 = child.getMeasuredHeight() + childTop;
                if (childRight > maxChildRight) {
                    maxChildRight = childRight;
                }
                childLeft += leftMargin + rightMargin + child.getMeasuredWidth() + this.itemSpacing;
                childBottom = childBottom2;
            }
            i2++;
            maxWidth2 = maxWidth;
        }
        int i5 = childTop;
        setMeasuredDimension(getMeasuredDimension(width, widthMode, maxChildRight), getMeasuredDimension(height, heightMode, childBottom));
    }

    private static int getMeasuredDimension(int size, int mode, int childrenEdge) {
        if (mode == Integer.MIN_VALUE) {
            return Math.min(childrenEdge, size);
        }
        if (mode != 1073741824) {
            return childrenEdge;
        }
        return size;
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean sizeChanged, int left, int top, int right, int bottom) {
        if (getChildCount() != 0) {
            boolean z = true;
            if (ViewCompat.getLayoutDirection(this) != 1) {
                z = false;
            }
            boolean isRtl = z;
            int paddingStart = isRtl ? getPaddingRight() : getPaddingLeft();
            int paddingEnd = isRtl ? getPaddingLeft() : getPaddingRight();
            int childStart = paddingStart;
            int childTop = getPaddingTop();
            int childBottom = childTop;
            int maxChildEnd = (right - left) - paddingEnd;
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i);
                if (child.getVisibility() != 8) {
                    LayoutParams lp = child.getLayoutParams();
                    int startMargin = 0;
                    int endMargin = 0;
                    if (lp instanceof MarginLayoutParams) {
                        MarginLayoutParams marginLp = (MarginLayoutParams) lp;
                        startMargin = MarginLayoutParamsCompat.getMarginStart(marginLp);
                        endMargin = MarginLayoutParamsCompat.getMarginEnd(marginLp);
                    }
                    int childEnd = childStart + startMargin + child.getMeasuredWidth();
                    if (!this.singleLine && childEnd > maxChildEnd) {
                        childStart = paddingStart;
                        childTop = childBottom + this.lineSpacing;
                    }
                    int childEnd2 = childStart + startMargin + child.getMeasuredWidth();
                    int childBottom2 = child.getMeasuredHeight() + childTop;
                    if (isRtl) {
                        child.layout(maxChildEnd - childEnd2, childTop, (maxChildEnd - childStart) - startMargin, childBottom2);
                    } else {
                        child.layout(childStart + startMargin, childTop, childEnd2, childBottom2);
                    }
                    childStart += startMargin + endMargin + child.getMeasuredWidth() + this.itemSpacing;
                    childBottom = childBottom2;
                }
            }
        }
    }
}
