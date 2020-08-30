package androidx.constraintlayout.solver.widgets;

import androidx.constraintlayout.solver.Cache;
import java.util.ArrayList;

public class WidgetContainer extends ConstraintWidget {
    protected ArrayList<ConstraintWidget> mChildren = new ArrayList<>();

    public WidgetContainer() {
    }

    public WidgetContainer(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public WidgetContainer(int width, int height) {
        super(width, height);
    }

    public void reset() {
        this.mChildren.clear();
        super.reset();
    }

    public void add(ConstraintWidget widget) {
        this.mChildren.add(widget);
        if (widget.getParent() != null) {
            ((WidgetContainer) widget.getParent()).remove(widget);
        }
        widget.setParent(this);
    }

    public void add(ConstraintWidget... widgets) {
        for (ConstraintWidget add : widgets) {
            add(add);
        }
    }

    public void remove(ConstraintWidget widget) {
        this.mChildren.remove(widget);
        widget.setParent(null);
    }

    public ArrayList<ConstraintWidget> getChildren() {
        return this.mChildren;
    }

    public ConstraintWidgetContainer getRootConstraintContainer() {
        ConstraintWidget parent = getParent();
        ConstraintWidgetContainer container = null;
        if (this instanceof ConstraintWidgetContainer) {
            container = (ConstraintWidgetContainer) this;
        }
        while (parent != null) {
            ConstraintWidget item = parent;
            parent = item.getParent();
            if (item instanceof ConstraintWidgetContainer) {
                container = (ConstraintWidgetContainer) item;
            }
        }
        return container;
    }

    /* JADX WARNING: type inference failed for: r0v4 */
    /* JADX WARNING: type inference failed for: r8v5, types: [androidx.constraintlayout.solver.widgets.ConstraintWidget] */
    /* JADX WARNING: type inference failed for: r0v5 */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public androidx.constraintlayout.solver.widgets.ConstraintWidget findWidget(float r10, float r11) {
        /*
            r9 = this;
            r0 = 0
            int r1 = r9.getDrawX()
            int r2 = r9.getDrawY()
            int r3 = r9.getWidth()
            int r3 = r3 + r1
            int r4 = r9.getHeight()
            int r4 = r4 + r2
            float r5 = (float) r1
            int r5 = (r10 > r5 ? 1 : (r10 == r5 ? 0 : -1))
            if (r5 < 0) goto L_0x0028
            float r5 = (float) r3
            int r5 = (r10 > r5 ? 1 : (r10 == r5 ? 0 : -1))
            if (r5 > 0) goto L_0x0028
            float r5 = (float) r2
            int r5 = (r11 > r5 ? 1 : (r11 == r5 ? 0 : -1))
            if (r5 < 0) goto L_0x0028
            float r5 = (float) r4
            int r5 = (r11 > r5 ? 1 : (r11 == r5 ? 0 : -1))
            if (r5 > 0) goto L_0x0028
            r0 = r9
        L_0x0028:
            r5 = 0
            java.util.ArrayList<androidx.constraintlayout.solver.widgets.ConstraintWidget> r6 = r9.mChildren
            int r6 = r6.size()
        L_0x002f:
            if (r5 >= r6) goto L_0x0077
            java.util.ArrayList<androidx.constraintlayout.solver.widgets.ConstraintWidget> r7 = r9.mChildren
            java.lang.Object r7 = r7.get(r5)
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r7
            boolean r8 = r7 instanceof androidx.constraintlayout.solver.widgets.WidgetContainer
            if (r8 == 0) goto L_0x0048
            r8 = r7
            androidx.constraintlayout.solver.widgets.WidgetContainer r8 = (androidx.constraintlayout.solver.widgets.WidgetContainer) r8
            androidx.constraintlayout.solver.widgets.ConstraintWidget r8 = r8.findWidget(r10, r11)
            if (r8 == 0) goto L_0x0047
            r0 = r8
        L_0x0047:
            goto L_0x0074
        L_0x0048:
            int r1 = r7.getDrawX()
            int r2 = r7.getDrawY()
            int r8 = r7.getWidth()
            int r8 = r8 + r1
            int r3 = r7.getHeight()
            int r3 = r3 + r2
            float r4 = (float) r1
            int r4 = (r10 > r4 ? 1 : (r10 == r4 ? 0 : -1))
            if (r4 < 0) goto L_0x0072
            float r4 = (float) r8
            int r4 = (r10 > r4 ? 1 : (r10 == r4 ? 0 : -1))
            if (r4 > 0) goto L_0x0072
            float r4 = (float) r2
            int r4 = (r11 > r4 ? 1 : (r11 == r4 ? 0 : -1))
            if (r4 < 0) goto L_0x0072
            float r4 = (float) r3
            int r4 = (r11 > r4 ? 1 : (r11 == r4 ? 0 : -1))
            if (r4 > 0) goto L_0x0072
            r0 = r7
            r4 = r3
            r3 = r8
            goto L_0x0074
        L_0x0072:
            r4 = r3
            r3 = r8
        L_0x0074:
            int r5 = r5 + 1
            goto L_0x002f
        L_0x0077:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.solver.widgets.WidgetContainer.findWidget(float, float):androidx.constraintlayout.solver.widgets.ConstraintWidget");
    }

    public ArrayList<ConstraintWidget> findWidgets(int x, int y, int width, int height) {
        ArrayList<ConstraintWidget> found = new ArrayList<>();
        Rectangle area = new Rectangle();
        area.setBounds(x, y, width, height);
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            Rectangle bounds = new Rectangle();
            bounds.setBounds(widget.getDrawX(), widget.getDrawY(), widget.getWidth(), widget.getHeight());
            if (area.intersects(bounds)) {
                found.add(widget);
            }
        }
        return found;
    }

    public static Rectangle getBounds(ArrayList<ConstraintWidget> widgets) {
        Rectangle bounds = new Rectangle();
        if (widgets.size() == 0) {
            return bounds;
        }
        int minX = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        int maxX = 0;
        int minY = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        int maxY = 0;
        int widgetsSize = widgets.size();
        for (int i = 0; i < widgetsSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) widgets.get(i);
            if (widget.getX() < minX) {
                minX = widget.getX();
            }
            if (widget.getY() < minY) {
                minY = widget.getY();
            }
            if (widget.getRight() > maxX) {
                maxX = widget.getRight();
            }
            if (widget.getBottom() > maxY) {
                maxY = widget.getBottom();
            }
        }
        bounds.setBounds(minX, minY, maxX - minX, maxY - minY);
        return bounds;
    }

    public void setOffset(int x, int y) {
        super.setOffset(x, y);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).setOffset(getRootX(), getRootY());
        }
    }

    public void updateDrawPosition() {
        super.updateDrawPosition();
        ArrayList<ConstraintWidget> arrayList = this.mChildren;
        if (arrayList != null) {
            int count = arrayList.size();
            for (int i = 0; i < count; i++) {
                ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
                widget.setOffset(getDrawX(), getDrawY());
                if (!(widget instanceof ConstraintWidgetContainer)) {
                    widget.updateDrawPosition();
                }
            }
        }
    }

    public void layout() {
        updateDrawPosition();
        ArrayList<ConstraintWidget> arrayList = this.mChildren;
        if (arrayList != null) {
            int count = arrayList.size();
            for (int i = 0; i < count; i++) {
                ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
                if (widget instanceof WidgetContainer) {
                    ((WidgetContainer) widget).layout();
                }
            }
        }
    }

    public void resetSolverVariables(Cache cache) {
        super.resetSolverVariables(cache);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).resetSolverVariables(cache);
        }
    }

    public void removeAllChildren() {
        this.mChildren.clear();
    }
}
