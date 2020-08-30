package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import androidx.appcompat.C0003R;
import androidx.appcompat.widget.LinearLayoutCompat.LayoutParams;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;

public class AlertDialogLayout extends LinearLayoutCompat {
    public AlertDialogLayout(Context context) {
        super(context);
    }

    public AlertDialogLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        if (!tryOnMeasure(widthMeasureSpec, heightMeasureSpec)) {
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        }
    }

    private boolean tryOnMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int childHeightSpec;
        int i = widthMeasureSpec;
        int i2 = heightMeasureSpec;
        View topPanel = null;
        View buttonPanel = null;
        View middlePanel = null;
        int count = getChildCount();
        for (int i3 = 0; i3 < count; i3++) {
            View child = getChildAt(i3);
            if (child.getVisibility() != 8) {
                int id = child.getId();
                if (id == C0003R.C0005id.topPanel) {
                    topPanel = child;
                } else if (id == C0003R.C0005id.buttonPanel) {
                    buttonPanel = child;
                } else if ((id != C0003R.C0005id.contentPanel && id != C0003R.C0005id.customPanel) || middlePanel != null) {
                    return false;
                } else {
                    middlePanel = child;
                }
            }
        }
        int i4 = MeasureSpec.getMode(heightMeasureSpec);
        int heightSize = MeasureSpec.getSize(heightMeasureSpec);
        int widthMode = MeasureSpec.getMode(widthMeasureSpec);
        int childState = 0;
        int usedHeight = getPaddingTop() + getPaddingBottom();
        if (topPanel != null) {
            topPanel.measure(i, 0);
            usedHeight += topPanel.getMeasuredHeight();
            childState = View.combineMeasuredStates(0, topPanel.getMeasuredState());
        }
        int buttonHeight = 0;
        int buttonWantsHeight = 0;
        if (buttonPanel != null) {
            buttonPanel.measure(i, 0);
            buttonHeight = resolveMinimumHeight(buttonPanel);
            buttonWantsHeight = buttonPanel.getMeasuredHeight() - buttonHeight;
            usedHeight += buttonHeight;
            childState = View.combineMeasuredStates(childState, buttonPanel.getMeasuredState());
        }
        int middleHeight = 0;
        if (middlePanel != null) {
            if (i4 == 0) {
                View view = topPanel;
                childHeightSpec = 0;
            } else {
                View view2 = topPanel;
                childHeightSpec = MeasureSpec.makeMeasureSpec(Math.max(0, heightSize - usedHeight), i4);
            }
            middlePanel.measure(i, childHeightSpec);
            middleHeight = middlePanel.getMeasuredHeight();
            usedHeight += middleHeight;
            childState = View.combineMeasuredStates(childState, middlePanel.getMeasuredState());
        }
        int remainingHeight = heightSize - usedHeight;
        if (buttonPanel != null) {
            int usedHeight2 = usedHeight - buttonHeight;
            int heightToGive = Math.min(remainingHeight, buttonWantsHeight);
            if (heightToGive > 0) {
                remainingHeight -= heightToGive;
                buttonHeight += heightToGive;
            }
            int remainingHeight2 = remainingHeight;
            buttonPanel.measure(i, MeasureSpec.makeMeasureSpec(buttonHeight, 1073741824));
            usedHeight = usedHeight2 + buttonPanel.getMeasuredHeight();
            childState = View.combineMeasuredStates(childState, buttonPanel.getMeasuredState());
            remainingHeight = remainingHeight2;
        }
        if (middlePanel != null && remainingHeight > 0) {
            int usedHeight3 = usedHeight - middleHeight;
            int heightToGive2 = remainingHeight;
            int remainingHeight3 = remainingHeight - heightToGive2;
            int childHeightSpec2 = MeasureSpec.makeMeasureSpec(middleHeight + heightToGive2, i4);
            middlePanel.measure(i, childHeightSpec2);
            usedHeight = usedHeight3 + middlePanel.getMeasuredHeight();
            int i5 = childHeightSpec2;
            childState = View.combineMeasuredStates(childState, middlePanel.getMeasuredState());
            remainingHeight = remainingHeight3;
        }
        int maxWidth = 0;
        int i6 = remainingHeight;
        int i7 = 0;
        while (i7 < count) {
            View child2 = getChildAt(i7);
            View buttonPanel2 = buttonPanel;
            View middlePanel2 = middlePanel;
            if (child2.getVisibility() != 8) {
                maxWidth = Math.max(maxWidth, child2.getMeasuredWidth());
            }
            i7++;
            buttonPanel = buttonPanel2;
            middlePanel = middlePanel2;
        }
        View view3 = middlePanel;
        setMeasuredDimension(View.resolveSizeAndState(maxWidth + getPaddingLeft() + getPaddingRight(), i, childState), View.resolveSizeAndState(usedHeight, i2, 0));
        if (widthMode != 1073741824) {
            forceUniformWidth(count, i2);
        }
        return true;
    }

    private void forceUniformWidth(int count, int heightMeasureSpec) {
        int uniformMeasureSpec = MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824);
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp.width == -1) {
                    int oldHeight = lp.height;
                    lp.height = child.getMeasuredHeight();
                    measureChildWithMargins(child, uniformMeasureSpec, 0, heightMeasureSpec, 0);
                    lp.height = oldHeight;
                }
            }
        }
    }

    private static int resolveMinimumHeight(View v) {
        int minHeight = ViewCompat.getMinimumHeight(v);
        if (minHeight > 0) {
            return minHeight;
        }
        if (v instanceof ViewGroup) {
            ViewGroup vg = (ViewGroup) v;
            if (vg.getChildCount() == 1) {
                return resolveMinimumHeight(vg.getChildAt(0));
            }
        }
        return 0;
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        int childTop;
        int i;
        int i2;
        int layoutGravity;
        int childLeft;
        AlertDialogLayout alertDialogLayout = this;
        int paddingLeft = getPaddingLeft();
        int width = right - left;
        int childRight = width - getPaddingRight();
        int childSpace = (width - paddingLeft) - getPaddingRight();
        int totalLength = getMeasuredHeight();
        int count = getChildCount();
        int gravity = getGravity();
        int majorGravity = gravity & 112;
        int minorGravity = gravity & GravityCompat.RELATIVE_HORIZONTAL_GRAVITY_MASK;
        if (majorGravity == 16) {
            childTop = getPaddingTop() + (((bottom - top) - totalLength) / 2);
        } else if (majorGravity != 80) {
            childTop = getPaddingTop();
        } else {
            childTop = ((getPaddingTop() + bottom) - top) - totalLength;
        }
        Drawable dividerDrawable = getDividerDrawable();
        if (dividerDrawable == null) {
            i = 0;
        } else {
            i = dividerDrawable.getIntrinsicHeight();
        }
        int dividerHeight = i;
        int i3 = 0;
        while (i3 < count) {
            View child = alertDialogLayout.getChildAt(i3);
            if (child == null || child.getVisibility() == 8) {
                i2 = i3;
            } else {
                int childWidth = child.getMeasuredWidth();
                int childHeight = child.getMeasuredHeight();
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                int layoutGravity2 = lp.gravity;
                if (layoutGravity2 < 0) {
                    layoutGravity = minorGravity;
                } else {
                    layoutGravity = layoutGravity2;
                }
                int layoutDirection = ViewCompat.getLayoutDirection(this);
                int absoluteGravity = GravityCompat.getAbsoluteGravity(layoutGravity, layoutDirection) & 7;
                int i4 = layoutDirection;
                if (absoluteGravity == 1) {
                    childLeft = ((((childSpace - childWidth) / 2) + paddingLeft) + lp.leftMargin) - lp.rightMargin;
                } else if (absoluteGravity != 5) {
                    childLeft = lp.leftMargin + paddingLeft;
                } else {
                    childLeft = (childRight - childWidth) - lp.rightMargin;
                }
                if (alertDialogLayout.hasDividerBeforeChildAt(i3) != 0) {
                    childTop += dividerHeight;
                }
                int childTop2 = childTop + lp.topMargin;
                int i5 = layoutGravity;
                LayoutParams lp2 = lp;
                i2 = i3;
                setChildFrame(child, childLeft, childTop2, childWidth, childHeight);
                childTop = childTop2 + childHeight + lp2.bottomMargin;
            }
            i3 = i2 + 1;
            alertDialogLayout = this;
        }
    }

    private void setChildFrame(View child, int left, int top, int width, int height) {
        child.layout(left, top, left + width, top + height);
    }
}
