package androidx.constraintlayout.solver.widgets;

public class ConstraintHorizontalLayout extends ConstraintWidgetContainer {
    private ContentAlignment mAlignment = ContentAlignment.MIDDLE;

    public enum ContentAlignment {
        BEGIN,
        MIDDLE,
        END,
        TOP,
        VERTICAL_MIDDLE,
        BOTTOM,
        LEFT,
        RIGHT
    }

    public ConstraintHorizontalLayout() {
    }

    public ConstraintHorizontalLayout(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public ConstraintHorizontalLayout(int width, int height) {
        super(width, height);
    }

    /* JADX WARNING: type inference failed for: r0v4 */
    /* JADX WARNING: Multi-variable type inference failed */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void addToSolver(androidx.constraintlayout.solver.LinearSystem r12) {
        /*
            r11 = this;
            java.util.ArrayList r0 = r11.mChildren
            int r0 = r0.size()
            if (r0 == 0) goto L_0x006d
            r0 = r11
            r1 = 0
            java.util.ArrayList r2 = r11.mChildren
            int r2 = r2.size()
        L_0x0010:
            if (r1 >= r2) goto L_0x0056
            java.util.ArrayList r3 = r11.mChildren
            java.lang.Object r3 = r3.get(r1)
            r9 = r3
            androidx.constraintlayout.solver.widgets.ConstraintWidget r9 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r9
            if (r0 == r11) goto L_0x002c
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.LEFT
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.RIGHT
            r9.connect(r3, r0, r4)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.RIGHT
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.LEFT
            r0.connect(r3, r9, r4)
            goto L_0x0044
        L_0x002c:
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Strength r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength.STRONG
            androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout$ContentAlignment r4 = r11.mAlignment
            androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout$ContentAlignment r5 = androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout.ContentAlignment.END
            if (r4 != r5) goto L_0x0038
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Strength r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength.WEAK
            r10 = r3
            goto L_0x0039
        L_0x0038:
            r10 = r3
        L_0x0039:
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.LEFT
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r6 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.LEFT
            r7 = 0
            r3 = r9
            r5 = r0
            r8 = r10
            r3.connect(r4, r5, r6, r7, r8)
        L_0x0044:
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.TOP
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.TOP
            r9.connect(r3, r11, r4)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r3 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.BOTTOM
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.BOTTOM
            r9.connect(r3, r11, r4)
            r0 = r9
            int r1 = r1 + 1
            goto L_0x0010
        L_0x0056:
            if (r0 == r11) goto L_0x006d
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Strength r1 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength.STRONG
            androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout$ContentAlignment r2 = r11.mAlignment
            androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout$ContentAlignment r3 = androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout.ContentAlignment.BEGIN
            if (r2 != r3) goto L_0x0062
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Strength r1 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength.WEAK
        L_0x0062:
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r4 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.RIGHT
            androidx.constraintlayout.solver.widgets.ConstraintAnchor$Type r6 = androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type.RIGHT
            r7 = 0
            r3 = r0
            r5 = r11
            r8 = r1
            r3.connect(r4, r5, r6, r7, r8)
        L_0x006d:
            super.addToSolver(r12)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.solver.widgets.ConstraintHorizontalLayout.addToSolver(androidx.constraintlayout.solver.LinearSystem):void");
    }
}
