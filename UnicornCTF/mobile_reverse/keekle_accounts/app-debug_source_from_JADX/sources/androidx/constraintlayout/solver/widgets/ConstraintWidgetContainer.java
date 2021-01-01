package androidx.constraintlayout.solver.widgets;

import androidx.constraintlayout.solver.LinearSystem;
import androidx.constraintlayout.solver.Metrics;
import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type;
import androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ConstraintWidgetContainer extends WidgetContainer {
    private static final boolean DEBUG = false;
    static final boolean DEBUG_GRAPH = false;
    private static final boolean DEBUG_LAYOUT = false;
    private static final int MAX_ITERATIONS = 8;
    private static final boolean USE_SNAPSHOT = true;
    int mDebugSolverPassCount = 0;
    public boolean mGroupsWrapOptimized = false;
    private boolean mHeightMeasuredTooSmall = false;
    ChainHead[] mHorizontalChainsArray = new ChainHead[4];
    int mHorizontalChainsSize = 0;
    public boolean mHorizontalWrapOptimized = false;
    private boolean mIsRtl = false;
    private int mOptimizationLevel = 7;
    int mPaddingBottom;
    int mPaddingLeft;
    int mPaddingRight;
    int mPaddingTop;
    public boolean mSkipSolver = false;
    private Snapshot mSnapshot;
    protected LinearSystem mSystem = new LinearSystem();
    ChainHead[] mVerticalChainsArray = new ChainHead[4];
    int mVerticalChainsSize = 0;
    public boolean mVerticalWrapOptimized = false;
    public List<ConstraintWidgetGroup> mWidgetGroups = new ArrayList();
    private boolean mWidthMeasuredTooSmall = false;
    public int mWrapFixedHeight = 0;
    public int mWrapFixedWidth = 0;

    public void fillMetrics(Metrics metrics) {
        this.mSystem.fillMetrics(metrics);
    }

    public ConstraintWidgetContainer() {
    }

    public ConstraintWidgetContainer(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public ConstraintWidgetContainer(int width, int height) {
        super(width, height);
    }

    public void setOptimizationLevel(int value) {
        this.mOptimizationLevel = value;
    }

    public int getOptimizationLevel() {
        return this.mOptimizationLevel;
    }

    public boolean optimizeFor(int feature) {
        if ((this.mOptimizationLevel & feature) == feature) {
            return USE_SNAPSHOT;
        }
        return false;
    }

    public String getType() {
        return "ConstraintLayout";
    }

    public void reset() {
        this.mSystem.reset();
        this.mPaddingLeft = 0;
        this.mPaddingRight = 0;
        this.mPaddingTop = 0;
        this.mPaddingBottom = 0;
        this.mWidgetGroups.clear();
        this.mSkipSolver = false;
        super.reset();
    }

    public boolean isWidthMeasuredTooSmall() {
        return this.mWidthMeasuredTooSmall;
    }

    public boolean isHeightMeasuredTooSmall() {
        return this.mHeightMeasuredTooSmall;
    }

    public boolean addChildrenToSolver(LinearSystem system) {
        addToSolver(system);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof ConstraintWidgetContainer) {
                DimensionBehaviour horizontalBehaviour = widget.mListDimensionBehaviors[0];
                DimensionBehaviour verticalBehaviour = widget.mListDimensionBehaviors[1];
                if (horizontalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
                if (verticalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
                widget.addToSolver(system);
                if (horizontalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setHorizontalDimensionBehaviour(horizontalBehaviour);
                }
                if (verticalBehaviour == DimensionBehaviour.WRAP_CONTENT) {
                    widget.setVerticalDimensionBehaviour(verticalBehaviour);
                }
            } else {
                Optimizer.checkMatchParent(this, system, widget);
                widget.addToSolver(system);
            }
        }
        if (this.mHorizontalChainsSize > 0) {
            Chain.applyChainConstraints(this, system, 0);
        }
        if (this.mVerticalChainsSize > 0) {
            Chain.applyChainConstraints(this, system, 1);
        }
        return USE_SNAPSHOT;
    }

    public void updateChildrenFromSolver(LinearSystem system, boolean[] flags) {
        flags[2] = false;
        updateFromSolver(system);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            widget.updateFromSolver(system);
            if (widget.mListDimensionBehaviors[0] == DimensionBehaviour.MATCH_CONSTRAINT && widget.getWidth() < widget.getWrapWidth()) {
                flags[2] = USE_SNAPSHOT;
            }
            if (widget.mListDimensionBehaviors[1] == DimensionBehaviour.MATCH_CONSTRAINT && widget.getHeight() < widget.getWrapHeight()) {
                flags[2] = USE_SNAPSHOT;
            }
        }
    }

    public void setPadding(int left, int top, int right, int bottom) {
        this.mPaddingLeft = left;
        this.mPaddingTop = top;
        this.mPaddingRight = right;
        this.mPaddingBottom = bottom;
    }

    public void setRtl(boolean isRtl) {
        this.mIsRtl = isRtl;
    }

    public boolean isRtl() {
        return this.mIsRtl;
    }

    public void analyze(int optimizationLevel) {
        super.analyze(optimizationLevel);
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).analyze(optimizationLevel);
        }
    }

    /* JADX WARNING: type inference failed for: r17v2, types: [boolean] */
    /* JADX WARNING: type inference failed for: r0v39, types: [boolean[]] */
    /* JADX WARNING: type inference failed for: r17v3 */
    /* JADX WARNING: type inference failed for: r17v5 */
    /* JADX WARNING: type inference failed for: r17v6 */
    /* JADX WARNING: type inference failed for: r17v7 */
    /* JADX WARNING: Incorrect type for immutable var: ssa=boolean[], code=null, for r0v39, types: [boolean[]] */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r17v6
      assigns: []
      uses: [?[int, short, byte, char], boolean]
      mth insns count: 376
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:99)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:92)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.core.ProcessClass.lambda$processDependencies$0(ProcessClass.java:49)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.ProcessClass.processDependencies(ProcessClass.java:49)
    	at jadx.core.ProcessClass.process(ProcessClass.java:35)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:217)
     */
    /* JADX WARNING: Removed duplicated region for block: B:115:0x0292  */
    /* JADX WARNING: Removed duplicated region for block: B:118:0x02af  */
    /* JADX WARNING: Removed duplicated region for block: B:120:0x02be  */
    /* JADX WARNING: Removed duplicated region for block: B:136:0x0315  */
    /* JADX WARNING: Removed duplicated region for block: B:75:0x019a  */
    /* JADX WARNING: Removed duplicated region for block: B:76:0x01a4  */
    /* JADX WARNING: Removed duplicated region for block: B:94:0x01f9  */
    /* JADX WARNING: Unknown variable types count: 4 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void layout() {
        /*
            r24 = this;
            r1 = r24
            int r2 = r1.f22mX
            int r3 = r1.f23mY
            int r0 = r24.getWidth()
            r4 = 0
            int r5 = java.lang.Math.max(r4, r0)
            int r0 = r24.getHeight()
            int r6 = java.lang.Math.max(r4, r0)
            r1.mWidthMeasuredTooSmall = r4
            r1.mHeightMeasuredTooSmall = r4
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r1.mParent
            if (r0 == 0) goto L_0x0046
            androidx.constraintlayout.solver.widgets.Snapshot r0 = r1.mSnapshot
            if (r0 != 0) goto L_0x002a
            androidx.constraintlayout.solver.widgets.Snapshot r0 = new androidx.constraintlayout.solver.widgets.Snapshot
            r0.<init>(r1)
            r1.mSnapshot = r0
        L_0x002a:
            androidx.constraintlayout.solver.widgets.Snapshot r0 = r1.mSnapshot
            r0.updateFrom(r1)
            int r0 = r1.mPaddingLeft
            r1.setX(r0)
            int r0 = r1.mPaddingTop
            r1.setY(r0)
            r24.resetAnchors()
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem
            androidx.constraintlayout.solver.Cache r0 = r0.getCache()
            r1.resetSolverVariables(r0)
            goto L_0x004a
        L_0x0046:
            r1.f22mX = r4
            r1.f23mY = r4
        L_0x004a:
            int r0 = r1.mOptimizationLevel
            r7 = 32
            r8 = 8
            r9 = 1
            if (r0 == 0) goto L_0x006a
            boolean r0 = r1.optimizeFor(r8)
            if (r0 != 0) goto L_0x005c
            r24.optimizeReset()
        L_0x005c:
            boolean r0 = r1.optimizeFor(r7)
            if (r0 != 0) goto L_0x0065
            r24.optimize()
        L_0x0065:
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem
            r0.graphOptimizer = r9
            goto L_0x006e
        L_0x006a:
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem
            r0.graphOptimizer = r4
        L_0x006e:
            r0 = 0
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r10 = r1.mListDimensionBehaviors
            r10 = r10[r9]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r11 = r1.mListDimensionBehaviors
            r11 = r11[r4]
            r24.resetChains()
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r12 = r1.mWidgetGroups
            int r12 = r12.size()
            if (r12 != 0) goto L_0x0093
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r12 = r1.mWidgetGroups
            r12.clear()
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r12 = r1.mWidgetGroups
            androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup r13 = new androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup
            java.util.ArrayList r14 = r1.mChildren
            r13.<init>(r14)
            r12.add(r4, r13)
        L_0x0093:
            r12 = 0
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r13 = r1.mWidgetGroups
            int r13 = r13.size()
            java.util.ArrayList r14 = r1.mChildren
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r15 = r24.getHorizontalDimensionBehaviour()
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r8 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r15 == r8) goto L_0x00af
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r8 = r24.getVerticalDimensionBehaviour()
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r15 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r8 != r15) goto L_0x00ad
            goto L_0x00af
        L_0x00ad:
            r8 = r4
            goto L_0x00b0
        L_0x00af:
            r8 = r9
        L_0x00b0:
            r15 = 0
        L_0x00b1:
            if (r15 >= r13) goto L_0x0342
            boolean r9 = r1.mSkipSolver
            if (r9 != 0) goto L_0x0342
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r9 = r1.mWidgetGroups
            java.lang.Object r9 = r9.get(r15)
            androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup r9 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup) r9
            boolean r9 = r9.mSkipSolver
            if (r9 == 0) goto L_0x00c7
            r22 = r13
            goto L_0x0338
        L_0x00c7:
            boolean r9 = r1.optimizeFor(r7)
            if (r9 == 0) goto L_0x00fc
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = r24.getHorizontalDimensionBehaviour()
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r7 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            if (r9 != r7) goto L_0x00ee
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r7 = r24.getVerticalDimensionBehaviour()
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            if (r7 != r9) goto L_0x00ee
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r7 = r1.mWidgetGroups
            java.lang.Object r7 = r7.get(r15)
            androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup r7 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup) r7
            java.util.List r7 = r7.getWidgetsToSolve()
            java.util.ArrayList r7 = (java.util.ArrayList) r7
            r1.mChildren = r7
            goto L_0x00fc
        L_0x00ee:
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r7 = r1.mWidgetGroups
            java.lang.Object r7 = r7.get(r15)
            androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup r7 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup) r7
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidget> r7 = r7.mConstrainedGroup
            java.util.ArrayList r7 = (java.util.ArrayList) r7
            r1.mChildren = r7
        L_0x00fc:
            r24.resetChains()
            java.util.ArrayList r7 = r1.mChildren
            int r7 = r7.size()
            r9 = 0
            r12 = 0
        L_0x0107:
            if (r12 >= r7) goto L_0x0123
            java.util.ArrayList r4 = r1.mChildren
            java.lang.Object r4 = r4.get(r12)
            androidx.constraintlayout.solver.widgets.ConstraintWidget r4 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r4
            r19 = r9
            boolean r9 = r4 instanceof androidx.constraintlayout.solver.widgets.WidgetContainer
            if (r9 == 0) goto L_0x011d
            r9 = r4
            androidx.constraintlayout.solver.widgets.WidgetContainer r9 = (androidx.constraintlayout.solver.widgets.WidgetContainer) r9
            r9.layout()
        L_0x011d:
            int r12 = r12 + 1
            r9 = r19
            r4 = 0
            goto L_0x0107
        L_0x0123:
            r19 = r9
            r4 = 1
            r9 = r4
            r4 = r0
        L_0x0128:
            if (r9 == 0) goto L_0x0321
            int r12 = r19 + 1
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem     // Catch:{ Exception -> 0x0174 }
            r0.reset()     // Catch:{ Exception -> 0x0174 }
            r24.resetChains()     // Catch:{ Exception -> 0x0174 }
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem     // Catch:{ Exception -> 0x0174 }
            r1.createObjectVariables(r0)     // Catch:{ Exception -> 0x0174 }
            r0 = 0
        L_0x013a:
            if (r0 >= r7) goto L_0x0158
            r20 = r4
            java.util.ArrayList r4 = r1.mChildren     // Catch:{ Exception -> 0x0154 }
            java.lang.Object r4 = r4.get(r0)     // Catch:{ Exception -> 0x0154 }
            androidx.constraintlayout.solver.widgets.ConstraintWidget r4 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r4     // Catch:{ Exception -> 0x0154 }
            r21 = r9
            androidx.constraintlayout.solver.LinearSystem r9 = r1.mSystem     // Catch:{ Exception -> 0x0170 }
            r4.createObjectVariables(r9)     // Catch:{ Exception -> 0x0170 }
            int r0 = r0 + 1
            r4 = r20
            r9 = r21
            goto L_0x013a
        L_0x0154:
            r0 = move-exception
            r21 = r9
            goto L_0x0179
        L_0x0158:
            r20 = r4
            r21 = r9
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem     // Catch:{ Exception -> 0x0170 }
            boolean r0 = r1.addChildrenToSolver(r0)     // Catch:{ Exception -> 0x0170 }
            r9 = r0
            if (r9 == 0) goto L_0x016d
            androidx.constraintlayout.solver.LinearSystem r0 = r1.mSystem     // Catch:{ Exception -> 0x016b }
            r0.minimize()     // Catch:{ Exception -> 0x016b }
            goto L_0x016d
        L_0x016b:
            r0 = move-exception
            goto L_0x0179
        L_0x016d:
            r22 = r13
            goto L_0x0198
        L_0x0170:
            r0 = move-exception
            r9 = r21
            goto L_0x0179
        L_0x0174:
            r0 = move-exception
            r20 = r4
            r21 = r9
        L_0x0179:
            r0.printStackTrace()
            java.io.PrintStream r4 = java.lang.System.out
            r19 = r9
            java.lang.StringBuilder r9 = new java.lang.StringBuilder
            r9.<init>()
            r22 = r13
            java.lang.String r13 = "EXCEPTION : "
            r9.append(r13)
            r9.append(r0)
            java.lang.String r9 = r9.toString()
            r4.println(r9)
            r9 = r19
        L_0x0198:
            if (r9 == 0) goto L_0x01a4
            androidx.constraintlayout.solver.LinearSystem r4 = r1.mSystem
            boolean[] r13 = androidx.constraintlayout.solver.widgets.Optimizer.flags
            r1.updateChildrenFromSolver(r4, r13)
            r21 = r9
            goto L_0x01f6
        L_0x01a4:
            androidx.constraintlayout.solver.LinearSystem r4 = r1.mSystem
            r1.updateFromSolver(r4)
            r4 = 0
        L_0x01aa:
            if (r4 >= r7) goto L_0x01f4
            java.util.ArrayList r13 = r1.mChildren
            java.lang.Object r13 = r13.get(r4)
            androidx.constraintlayout.solver.widgets.ConstraintWidget r13 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r13
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r13.mListDimensionBehaviors
            r18 = 0
            r0 = r0[r18]
            r21 = r9
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r0 != r9) goto L_0x01d5
            int r0 = r13.getWidth()
            int r9 = r13.getWrapWidth()
            if (r0 >= r9) goto L_0x01d2
            boolean[] r0 = androidx.constraintlayout.solver.widgets.Optimizer.flags
            r9 = 2
            r17 = 1
            r0[r9] = r17
            goto L_0x01f6
        L_0x01d2:
            r17 = 1
            goto L_0x01d7
        L_0x01d5:
            r17 = 1
        L_0x01d7:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r13.mListDimensionBehaviors
            r0 = r0[r17]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r0 != r9) goto L_0x01ef
            int r0 = r13.getHeight()
            int r9 = r13.getWrapHeight()
            if (r0 >= r9) goto L_0x01ef
            boolean[] r0 = androidx.constraintlayout.solver.widgets.Optimizer.flags
            r9 = 2
            r0[r9] = r17
            goto L_0x01f6
        L_0x01ef:
            int r4 = r4 + 1
            r9 = r21
            goto L_0x01aa
        L_0x01f4:
            r21 = r9
        L_0x01f6:
            r0 = 0
            if (r8 == 0) goto L_0x027a
            r4 = 8
            if (r12 >= r4) goto L_0x027a
            boolean[] r9 = androidx.constraintlayout.solver.widgets.Optimizer.flags
            r13 = 2
            boolean r9 = r9[r13]
            if (r9 == 0) goto L_0x027a
            r9 = 0
            r13 = 0
            r16 = 0
            r4 = r16
        L_0x020a:
            if (r4 >= r7) goto L_0x0237
            r19 = r0
            java.util.ArrayList r0 = r1.mChildren
            java.lang.Object r0 = r0.get(r4)
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = (androidx.constraintlayout.solver.widgets.ConstraintWidget) r0
            r23 = r7
            int r7 = r0.f22mX
            int r21 = r0.getWidth()
            int r7 = r7 + r21
            int r9 = java.lang.Math.max(r9, r7)
            int r7 = r0.f23mY
            int r21 = r0.getHeight()
            int r7 = r7 + r21
            int r13 = java.lang.Math.max(r13, r7)
            int r4 = r4 + 1
            r0 = r19
            r7 = r23
            goto L_0x020a
        L_0x0237:
            r19 = r0
            r23 = r7
            int r0 = r1.mMinWidth
            int r0 = java.lang.Math.max(r0, r9)
            int r4 = r1.mMinHeight
            int r4 = java.lang.Math.max(r4, r13)
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r7 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r11 != r7) goto L_0x0261
            int r7 = r24.getWidth()
            if (r7 >= r0) goto L_0x0261
            r1.setWidth(r0)
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r7 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            r13 = 0
            r7[r13] = r9
            r7 = 1
            r9 = 1
            r20 = r7
            r19 = r9
        L_0x0261:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r7 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r10 != r7) goto L_0x027e
            int r7 = r24.getHeight()
            if (r7 >= r4) goto L_0x027e
            r1.setHeight(r4)
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r7 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            r13 = 1
            r7[r13] = r9
            r7 = 1
            r9 = 1
            r4 = r7
            r0 = r9
            goto L_0x0282
        L_0x027a:
            r19 = r0
            r23 = r7
        L_0x027e:
            r0 = r19
            r4 = r20
        L_0x0282:
            int r7 = r1.mMinWidth
            int r9 = r24.getWidth()
            int r7 = java.lang.Math.max(r7, r9)
            int r9 = r24.getWidth()
            if (r7 <= r9) goto L_0x029f
            r1.setWidth(r7)
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r9 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r13 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            r18 = 0
            r9[r18] = r13
            r4 = 1
            r0 = 1
        L_0x029f:
            int r9 = r1.mMinHeight
            int r13 = r24.getHeight()
            int r9 = java.lang.Math.max(r9, r13)
            int r13 = r24.getHeight()
            if (r9 <= r13) goto L_0x02bc
            r1.setHeight(r9)
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r13 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r19 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            r17 = 1
            r13[r17] = r19
            r4 = 1
            r0 = 1
        L_0x02bc:
            if (r4 != 0) goto L_0x0315
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r13 = r1.mListDimensionBehaviors
            r18 = 0
            r13 = r13[r18]
            r19 = r0
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r0 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r13 != r0) goto L_0x02e3
            if (r5 <= 0) goto L_0x02e3
            int r0 = r24.getWidth()
            if (r0 <= r5) goto L_0x02e3
            r13 = 1
            r1.mWidthMeasuredTooSmall = r13
            r4 = 1
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r13 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            r18 = 0
            r0[r18] = r13
            r1.setWidth(r5)
            r0 = 1
            goto L_0x02e5
        L_0x02e3:
            r0 = r19
        L_0x02e5:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r13 = r1.mListDimensionBehaviors
            r19 = r4
            r4 = 1
            r13 = r13[r4]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r4 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r13 != r4) goto L_0x030e
            if (r6 <= 0) goto L_0x030e
            int r4 = r24.getHeight()
            if (r4 <= r6) goto L_0x030b
            r4 = 1
            r1.mHeightMeasuredTooSmall = r4
            r13 = 1
            r20 = r0
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r1.mListDimensionBehaviors
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r17 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.FIXED
            r0[r4] = r17
            r1.setHeight(r6)
            r0 = 1
            r9 = r0
            r4 = r13
            goto L_0x0319
        L_0x030b:
            r20 = r0
            goto L_0x0310
        L_0x030e:
            r20 = r0
        L_0x0310:
            r4 = r19
            r9 = r20
            goto L_0x0319
        L_0x0315:
            r19 = r0
            r9 = r19
        L_0x0319:
            r19 = r12
            r13 = r22
            r7 = r23
            goto L_0x0128
        L_0x0321:
            r20 = r4
            r23 = r7
            r21 = r9
            r22 = r13
            java.util.List<androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup> r0 = r1.mWidgetGroups
            java.lang.Object r0 = r0.get(r15)
            androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup r0 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetGroup) r0
            r0.updateUnresolvedWidgets()
            r12 = r19
            r0 = r20
        L_0x0338:
            int r15 = r15 + 1
            r13 = r22
            r4 = 0
            r7 = 32
            r9 = 1
            goto L_0x00b1
        L_0x0342:
            r22 = r13
            r4 = r14
            java.util.ArrayList r4 = (java.util.ArrayList) r4
            r1.mChildren = r4
            androidx.constraintlayout.solver.widgets.ConstraintWidget r4 = r1.mParent
            if (r4 == 0) goto L_0x0379
            int r4 = r1.mMinWidth
            int r7 = r24.getWidth()
            int r4 = java.lang.Math.max(r4, r7)
            int r7 = r1.mMinHeight
            int r9 = r24.getHeight()
            int r7 = java.lang.Math.max(r7, r9)
            androidx.constraintlayout.solver.widgets.Snapshot r9 = r1.mSnapshot
            r9.applyTo(r1)
            int r9 = r1.mPaddingLeft
            int r9 = r9 + r4
            int r13 = r1.mPaddingRight
            int r9 = r9 + r13
            r1.setWidth(r9)
            int r9 = r1.mPaddingTop
            int r9 = r9 + r7
            int r13 = r1.mPaddingBottom
            int r9 = r9 + r13
            r1.setHeight(r9)
            goto L_0x037d
        L_0x0379:
            r1.f22mX = r2
            r1.f23mY = r3
        L_0x037d:
            if (r0 == 0) goto L_0x0389
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r4 = r1.mListDimensionBehaviors
            r7 = 0
            r4[r7] = r11
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r4 = r1.mListDimensionBehaviors
            r7 = 1
            r4[r7] = r10
        L_0x0389:
            androidx.constraintlayout.solver.LinearSystem r4 = r1.mSystem
            androidx.constraintlayout.solver.Cache r4 = r4.getCache()
            r1.resetSolverVariables(r4)
            androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer r4 = r24.getRootConstraintContainer()
            if (r1 != r4) goto L_0x039b
            r24.updateDrawPosition()
        L_0x039b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer.layout():void");
    }

    public void preOptimize() {
        optimizeReset();
        analyze(this.mOptimizationLevel);
    }

    public void solveGraph() {
        ResolutionAnchor leftNode = getAnchor(Type.LEFT).getResolutionNode();
        ResolutionAnchor topNode = getAnchor(Type.TOP).getResolutionNode();
        leftNode.resolve(null, 0.0f);
        topNode.resolve(null, 0.0f);
    }

    public void resetGraph() {
        ResolutionAnchor leftNode = getAnchor(Type.LEFT).getResolutionNode();
        ResolutionAnchor topNode = getAnchor(Type.TOP).getResolutionNode();
        leftNode.invalidateAnchors();
        topNode.invalidateAnchors();
        leftNode.resolve(null, 0.0f);
        topNode.resolve(null, 0.0f);
    }

    public void optimizeForDimensions(int width, int height) {
        if (!(this.mListDimensionBehaviors[0] == DimensionBehaviour.WRAP_CONTENT || this.mResolutionWidth == null)) {
            this.mResolutionWidth.resolve(width);
        }
        if (this.mListDimensionBehaviors[1] != DimensionBehaviour.WRAP_CONTENT && this.mResolutionHeight != null) {
            this.mResolutionHeight.resolve(height);
        }
    }

    public void optimizeReset() {
        int count = this.mChildren.size();
        resetResolutionNodes();
        for (int i = 0; i < count; i++) {
            ((ConstraintWidget) this.mChildren.get(i)).resetResolutionNodes();
        }
    }

    public void optimize() {
        if (!optimizeFor(8)) {
            analyze(this.mOptimizationLevel);
        }
        solveGraph();
    }

    public boolean handlesInternalConstraints() {
        return false;
    }

    public ArrayList<Guideline> getVerticalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList<>();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 1) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public ArrayList<Guideline> getHorizontalGuidelines() {
        ArrayList<Guideline> guidelines = new ArrayList<>();
        int mChildrenSize = this.mChildren.size();
        for (int i = 0; i < mChildrenSize; i++) {
            ConstraintWidget widget = (ConstraintWidget) this.mChildren.get(i);
            if (widget instanceof Guideline) {
                Guideline guideline = (Guideline) widget;
                if (guideline.getOrientation() == 0) {
                    guidelines.add(guideline);
                }
            }
        }
        return guidelines;
    }

    public LinearSystem getSystem() {
        return this.mSystem;
    }

    private void resetChains() {
        this.mHorizontalChainsSize = 0;
        this.mVerticalChainsSize = 0;
    }

    /* access modifiers changed from: 0000 */
    public void addChain(ConstraintWidget constraintWidget, int type) {
        ConstraintWidget widget = constraintWidget;
        if (type == 0) {
            addHorizontalChain(widget);
        } else if (type == 1) {
            addVerticalChain(widget);
        }
    }

    private void addHorizontalChain(ConstraintWidget widget) {
        int i = this.mHorizontalChainsSize + 1;
        ChainHead[] chainHeadArr = this.mHorizontalChainsArray;
        if (i >= chainHeadArr.length) {
            this.mHorizontalChainsArray = (ChainHead[]) Arrays.copyOf(chainHeadArr, chainHeadArr.length * 2);
        }
        this.mHorizontalChainsArray[this.mHorizontalChainsSize] = new ChainHead(widget, 0, isRtl());
        this.mHorizontalChainsSize++;
    }

    private void addVerticalChain(ConstraintWidget widget) {
        int i = this.mVerticalChainsSize + 1;
        ChainHead[] chainHeadArr = this.mVerticalChainsArray;
        if (i >= chainHeadArr.length) {
            this.mVerticalChainsArray = (ChainHead[]) Arrays.copyOf(chainHeadArr, chainHeadArr.length * 2);
        }
        this.mVerticalChainsArray[this.mVerticalChainsSize] = new ChainHead(widget, 1, isRtl());
        this.mVerticalChainsSize++;
    }

    public List<ConstraintWidgetGroup> getWidgetGroups() {
        return this.mWidgetGroups;
    }
}
