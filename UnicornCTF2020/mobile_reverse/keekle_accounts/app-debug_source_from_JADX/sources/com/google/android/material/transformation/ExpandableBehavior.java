package com.google.android.material.transformation;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewTreeObserver.OnPreDrawListener;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior;
import androidx.core.view.ViewCompat;
import com.google.android.material.expandable.ExpandableWidget;
import java.util.List;

public abstract class ExpandableBehavior extends Behavior<View> {
    private static final int STATE_COLLAPSED = 2;
    private static final int STATE_EXPANDED = 1;
    private static final int STATE_UNINITIALIZED = 0;
    /* access modifiers changed from: private */
    public int currentState = 0;

    public abstract boolean layoutDependsOn(CoordinatorLayout coordinatorLayout, View view, View view2);

    /* access modifiers changed from: protected */
    public abstract boolean onExpandedStateChange(View view, View view2, boolean z, boolean z2);

    public ExpandableBehavior() {
    }

    public ExpandableBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public boolean onLayoutChild(CoordinatorLayout parent, final View child, int layoutDirection) {
        if (!ViewCompat.isLaidOut(child)) {
            final ExpandableWidget dep = findExpandableWidget(parent, child);
            if (dep != null && didStateChange(dep.isExpanded())) {
                this.currentState = dep.isExpanded() ? 1 : 2;
                final int expectedState = this.currentState;
                child.getViewTreeObserver().addOnPreDrawListener(new OnPreDrawListener() {
                    public boolean onPreDraw() {
                        child.getViewTreeObserver().removeOnPreDrawListener(this);
                        if (ExpandableBehavior.this.currentState == expectedState) {
                            ExpandableBehavior expandableBehavior = ExpandableBehavior.this;
                            ExpandableWidget expandableWidget = dep;
                            expandableBehavior.onExpandedStateChange((View) expandableWidget, child, expandableWidget.isExpanded(), false);
                        }
                        return false;
                    }
                });
            }
        }
        return false;
    }

    public boolean onDependentViewChanged(CoordinatorLayout parent, View child, View dependency) {
        ExpandableWidget dep = (ExpandableWidget) dependency;
        if (!didStateChange(dep.isExpanded())) {
            return false;
        }
        this.currentState = dep.isExpanded() ? 1 : 2;
        return onExpandedStateChange((View) dep, child, dep.isExpanded(), true);
    }

    /* access modifiers changed from: protected */
    public ExpandableWidget findExpandableWidget(CoordinatorLayout parent, View child) {
        List<View> dependencies = parent.getDependencies(child);
        int size = dependencies.size();
        for (int i = 0; i < size; i++) {
            View dependency = (View) dependencies.get(i);
            if (layoutDependsOn(parent, child, dependency)) {
                return (ExpandableWidget) dependency;
            }
        }
        return null;
    }

    private boolean didStateChange(boolean expanded) {
        boolean z = false;
        if (expanded) {
            int i = this.currentState;
            if (i == 0 || i == 2) {
                z = true;
            }
            return z;
        }
        if (this.currentState == 1) {
            z = true;
        }
        return z;
    }

    public static <T extends ExpandableBehavior> T from(View view, Class<T> klass) {
        LayoutParams params = view.getLayoutParams();
        if (params instanceof CoordinatorLayout.LayoutParams) {
            Behavior<?> behavior = ((CoordinatorLayout.LayoutParams) params).getBehavior();
            if (behavior instanceof ExpandableBehavior) {
                return (ExpandableBehavior) klass.cast(behavior);
            }
            throw new IllegalArgumentException("The view is not associated with ExpandableBehavior");
        }
        throw new IllegalArgumentException("The view is not a child of CoordinatorLayout");
    }
}
