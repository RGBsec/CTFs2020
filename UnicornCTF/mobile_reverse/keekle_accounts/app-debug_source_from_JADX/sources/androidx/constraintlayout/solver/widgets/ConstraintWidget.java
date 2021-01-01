package androidx.constraintlayout.solver.widgets;

import androidx.constraintlayout.solver.Cache;
import androidx.constraintlayout.solver.LinearSystem;
import androidx.constraintlayout.solver.Metrics;
import androidx.constraintlayout.solver.SolverVariable;
import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength;
import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type;
import java.util.ArrayList;

public class ConstraintWidget {
    protected static final int ANCHOR_BASELINE = 4;
    protected static final int ANCHOR_BOTTOM = 3;
    protected static final int ANCHOR_LEFT = 0;
    protected static final int ANCHOR_RIGHT = 1;
    protected static final int ANCHOR_TOP = 2;
    private static final boolean AUTOTAG_CENTER = false;
    public static final int CHAIN_PACKED = 2;
    public static final int CHAIN_SPREAD = 0;
    public static final int CHAIN_SPREAD_INSIDE = 1;
    public static float DEFAULT_BIAS = 0.5f;
    static final int DIMENSION_HORIZONTAL = 0;
    static final int DIMENSION_VERTICAL = 1;
    protected static final int DIRECT = 2;
    public static final int GONE = 8;
    public static final int HORIZONTAL = 0;
    public static final int INVISIBLE = 4;
    public static final int MATCH_CONSTRAINT_PERCENT = 2;
    public static final int MATCH_CONSTRAINT_RATIO = 3;
    public static final int MATCH_CONSTRAINT_RATIO_RESOLVED = 4;
    public static final int MATCH_CONSTRAINT_SPREAD = 0;
    public static final int MATCH_CONSTRAINT_WRAP = 1;
    protected static final int SOLVER = 1;
    public static final int UNKNOWN = -1;
    public static final int VERTICAL = 1;
    public static final int VISIBLE = 0;
    private static final int WRAP = -2;
    protected ArrayList<ConstraintAnchor> mAnchors;
    ConstraintAnchor mBaseline;
    int mBaselineDistance;
    ConstraintWidgetGroup mBelongingGroup;
    ConstraintAnchor mBottom;
    boolean mBottomHasCentered;
    ConstraintAnchor mCenter;
    ConstraintAnchor mCenterX;
    ConstraintAnchor mCenterY;
    private float mCircleConstraintAngle;
    private Object mCompanionWidget;
    private int mContainerItemSkip;
    private String mDebugName;
    protected float mDimensionRatio;
    protected int mDimensionRatioSide;
    int mDistToBottom;
    int mDistToLeft;
    int mDistToRight;
    int mDistToTop;
    private int mDrawHeight;
    private int mDrawWidth;
    private int mDrawX;
    private int mDrawY;
    boolean mGroupsToSolver;
    int mHeight;
    float mHorizontalBiasPercent;
    boolean mHorizontalChainFixedPosition;
    int mHorizontalChainStyle;
    ConstraintWidget mHorizontalNextWidget;
    public int mHorizontalResolution;
    boolean mHorizontalWrapVisited;
    boolean mIsHeightWrapContent;
    boolean mIsWidthWrapContent;
    ConstraintAnchor mLeft;
    boolean mLeftHasCentered;
    protected ConstraintAnchor[] mListAnchors;
    protected DimensionBehaviour[] mListDimensionBehaviors;
    protected ConstraintWidget[] mListNextMatchConstraintsWidget;
    int mMatchConstraintDefaultHeight;
    int mMatchConstraintDefaultWidth;
    int mMatchConstraintMaxHeight;
    int mMatchConstraintMaxWidth;
    int mMatchConstraintMinHeight;
    int mMatchConstraintMinWidth;
    float mMatchConstraintPercentHeight;
    float mMatchConstraintPercentWidth;
    private int[] mMaxDimension;
    protected int mMinHeight;
    protected int mMinWidth;
    protected ConstraintWidget[] mNextChainWidget;
    protected int mOffsetX;
    protected int mOffsetY;
    boolean mOptimizerMeasurable;
    boolean mOptimizerMeasured;
    ConstraintWidget mParent;
    int mRelX;
    int mRelY;
    ResolutionDimension mResolutionHeight;
    ResolutionDimension mResolutionWidth;
    float mResolvedDimensionRatio;
    int mResolvedDimensionRatioSide;
    int[] mResolvedMatchConstraintDefault;
    ConstraintAnchor mRight;
    boolean mRightHasCentered;
    ConstraintAnchor mTop;
    boolean mTopHasCentered;
    private String mType;
    float mVerticalBiasPercent;
    boolean mVerticalChainFixedPosition;
    int mVerticalChainStyle;
    ConstraintWidget mVerticalNextWidget;
    public int mVerticalResolution;
    boolean mVerticalWrapVisited;
    private int mVisibility;
    float[] mWeight;
    int mWidth;
    private int mWrapHeight;
    private int mWrapWidth;

    /* renamed from: mX */
    protected int f22mX;

    /* renamed from: mY */
    protected int f23mY;

    /* renamed from: androidx.constraintlayout.solver.widgets.ConstraintWidget$1 */
    static /* synthetic */ class C01971 {

        /* renamed from: $SwitchMap$androidx$constraintlayout$solver$widgets$ConstraintAnchor$Type */
        static final /* synthetic */ int[] f24x4c44d048;

        /* renamed from: $SwitchMap$androidx$constraintlayout$solver$widgets$ConstraintWidget$DimensionBehaviour */
        static final /* synthetic */ int[] f25xdde91696;

        static {
            int[] iArr = new int[DimensionBehaviour.values().length];
            f25xdde91696 = iArr;
            try {
                iArr[DimensionBehaviour.FIXED.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                f25xdde91696[DimensionBehaviour.WRAP_CONTENT.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                f25xdde91696[DimensionBehaviour.MATCH_PARENT.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                f25xdde91696[DimensionBehaviour.MATCH_CONSTRAINT.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            int[] iArr2 = new int[Type.values().length];
            f24x4c44d048 = iArr2;
            try {
                iArr2[Type.LEFT.ordinal()] = 1;
            } catch (NoSuchFieldError e5) {
            }
            try {
                f24x4c44d048[Type.TOP.ordinal()] = 2;
            } catch (NoSuchFieldError e6) {
            }
            try {
                f24x4c44d048[Type.RIGHT.ordinal()] = 3;
            } catch (NoSuchFieldError e7) {
            }
            try {
                f24x4c44d048[Type.BOTTOM.ordinal()] = 4;
            } catch (NoSuchFieldError e8) {
            }
            try {
                f24x4c44d048[Type.BASELINE.ordinal()] = 5;
            } catch (NoSuchFieldError e9) {
            }
            try {
                f24x4c44d048[Type.CENTER.ordinal()] = 6;
            } catch (NoSuchFieldError e10) {
            }
            try {
                f24x4c44d048[Type.CENTER_X.ordinal()] = 7;
            } catch (NoSuchFieldError e11) {
            }
            try {
                f24x4c44d048[Type.CENTER_Y.ordinal()] = 8;
            } catch (NoSuchFieldError e12) {
            }
            try {
                f24x4c44d048[Type.NONE.ordinal()] = 9;
            } catch (NoSuchFieldError e13) {
            }
        }
    }

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

    public enum DimensionBehaviour {
        FIXED,
        WRAP_CONTENT,
        MATCH_CONSTRAINT,
        MATCH_PARENT
    }

    public int getMaxHeight() {
        return this.mMaxDimension[1];
    }

    public int getMaxWidth() {
        return this.mMaxDimension[0];
    }

    public void setMaxWidth(int maxWidth) {
        this.mMaxDimension[0] = maxWidth;
    }

    public void setMaxHeight(int maxHeight) {
        this.mMaxDimension[1] = maxHeight;
    }

    public boolean isSpreadWidth() {
        return this.mMatchConstraintDefaultWidth == 0 && this.mDimensionRatio == 0.0f && this.mMatchConstraintMinWidth == 0 && this.mMatchConstraintMaxWidth == 0 && this.mListDimensionBehaviors[0] == DimensionBehaviour.MATCH_CONSTRAINT;
    }

    public boolean isSpreadHeight() {
        return this.mMatchConstraintDefaultHeight == 0 && this.mDimensionRatio == 0.0f && this.mMatchConstraintMinHeight == 0 && this.mMatchConstraintMaxHeight == 0 && this.mListDimensionBehaviors[1] == DimensionBehaviour.MATCH_CONSTRAINT;
    }

    public void reset() {
        this.mLeft.reset();
        this.mTop.reset();
        this.mRight.reset();
        this.mBottom.reset();
        this.mBaseline.reset();
        this.mCenterX.reset();
        this.mCenterY.reset();
        this.mCenter.reset();
        this.mParent = null;
        this.mCircleConstraintAngle = 0.0f;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.f22mX = 0;
        this.f23mY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        this.mMinWidth = 0;
        this.mMinHeight = 0;
        this.mWrapWidth = 0;
        this.mWrapHeight = 0;
        float f = DEFAULT_BIAS;
        this.mHorizontalBiasPercent = f;
        this.mVerticalBiasPercent = f;
        this.mListDimensionBehaviors[0] = DimensionBehaviour.FIXED;
        this.mListDimensionBehaviors[1] = DimensionBehaviour.FIXED;
        this.mCompanionWidget = null;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mType = null;
        this.mHorizontalWrapVisited = false;
        this.mVerticalWrapVisited = false;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mHorizontalChainFixedPosition = false;
        this.mVerticalChainFixedPosition = false;
        float[] fArr = this.mWeight;
        fArr[0] = -1.0f;
        fArr[1] = -1.0f;
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
        int[] iArr = this.mMaxDimension;
        iArr[0] = Integer.MAX_VALUE;
        iArr[1] = Integer.MAX_VALUE;
        this.mMatchConstraintDefaultWidth = 0;
        this.mMatchConstraintDefaultHeight = 0;
        this.mMatchConstraintPercentWidth = 1.0f;
        this.mMatchConstraintPercentHeight = 1.0f;
        this.mMatchConstraintMaxWidth = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        this.mMatchConstraintMaxHeight = ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        this.mMatchConstraintMinWidth = 0;
        this.mMatchConstraintMinHeight = 0;
        this.mResolvedDimensionRatioSide = -1;
        this.mResolvedDimensionRatio = 1.0f;
        ResolutionDimension resolutionDimension = this.mResolutionWidth;
        if (resolutionDimension != null) {
            resolutionDimension.reset();
        }
        ResolutionDimension resolutionDimension2 = this.mResolutionHeight;
        if (resolutionDimension2 != null) {
            resolutionDimension2.reset();
        }
        this.mBelongingGroup = null;
        this.mOptimizerMeasurable = false;
        this.mOptimizerMeasured = false;
        this.mGroupsToSolver = false;
    }

    public void resetResolutionNodes() {
        for (int i = 0; i < 6; i++) {
            this.mListAnchors[i].getResolutionNode().reset();
        }
    }

    public void updateResolutionNodes() {
        for (int i = 0; i < 6; i++) {
            this.mListAnchors[i].getResolutionNode().update();
        }
    }

    public void analyze(int optimizationLevel) {
        Optimizer.analyze(optimizationLevel, this);
    }

    public void resolve() {
    }

    public boolean isFullyResolved() {
        if (this.mLeft.getResolutionNode().state == 1 && this.mRight.getResolutionNode().state == 1 && this.mTop.getResolutionNode().state == 1 && this.mBottom.getResolutionNode().state == 1) {
            return true;
        }
        return false;
    }

    public ResolutionDimension getResolutionWidth() {
        if (this.mResolutionWidth == null) {
            this.mResolutionWidth = new ResolutionDimension();
        }
        return this.mResolutionWidth;
    }

    public ResolutionDimension getResolutionHeight() {
        if (this.mResolutionHeight == null) {
            this.mResolutionHeight = new ResolutionDimension();
        }
        return this.mResolutionHeight;
    }

    public ConstraintWidget() {
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
        this.mMatchConstraintDefaultWidth = 0;
        this.mMatchConstraintDefaultHeight = 0;
        this.mResolvedMatchConstraintDefault = new int[2];
        this.mMatchConstraintMinWidth = 0;
        this.mMatchConstraintMaxWidth = 0;
        this.mMatchConstraintPercentWidth = 1.0f;
        this.mMatchConstraintMinHeight = 0;
        this.mMatchConstraintMaxHeight = 0;
        this.mMatchConstraintPercentHeight = 1.0f;
        this.mResolvedDimensionRatioSide = -1;
        this.mResolvedDimensionRatio = 1.0f;
        this.mBelongingGroup = null;
        this.mMaxDimension = new int[]{ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED};
        this.mCircleConstraintAngle = 0.0f;
        this.mLeft = new ConstraintAnchor(this, Type.LEFT);
        this.mTop = new ConstraintAnchor(this, Type.TOP);
        this.mRight = new ConstraintAnchor(this, Type.RIGHT);
        this.mBottom = new ConstraintAnchor(this, Type.BOTTOM);
        this.mBaseline = new ConstraintAnchor(this, Type.BASELINE);
        this.mCenterX = new ConstraintAnchor(this, Type.CENTER_X);
        this.mCenterY = new ConstraintAnchor(this, Type.CENTER_Y);
        ConstraintAnchor constraintAnchor = new ConstraintAnchor(this, Type.CENTER);
        this.mCenter = constraintAnchor;
        this.mListAnchors = new ConstraintAnchor[]{this.mLeft, this.mRight, this.mTop, this.mBottom, this.mBaseline, constraintAnchor};
        this.mAnchors = new ArrayList<>();
        this.mListDimensionBehaviors = new DimensionBehaviour[]{DimensionBehaviour.FIXED, DimensionBehaviour.FIXED};
        this.mParent = null;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.f22mX = 0;
        this.f23mY = 0;
        this.mRelX = 0;
        this.mRelY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        float f = DEFAULT_BIAS;
        this.mHorizontalBiasPercent = f;
        this.mVerticalBiasPercent = f;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mDebugName = null;
        this.mType = null;
        this.mOptimizerMeasurable = false;
        this.mOptimizerMeasured = false;
        this.mGroupsToSolver = false;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mWeight = new float[]{-1.0f, -1.0f};
        this.mListNextMatchConstraintsWidget = new ConstraintWidget[]{null, null};
        this.mNextChainWidget = new ConstraintWidget[]{null, null};
        this.mHorizontalNextWidget = null;
        this.mVerticalNextWidget = null;
        addAnchors();
    }

    public ConstraintWidget(int x, int y, int width, int height) {
        this.mHorizontalResolution = -1;
        this.mVerticalResolution = -1;
        this.mMatchConstraintDefaultWidth = 0;
        this.mMatchConstraintDefaultHeight = 0;
        this.mResolvedMatchConstraintDefault = new int[2];
        this.mMatchConstraintMinWidth = 0;
        this.mMatchConstraintMaxWidth = 0;
        this.mMatchConstraintPercentWidth = 1.0f;
        this.mMatchConstraintMinHeight = 0;
        this.mMatchConstraintMaxHeight = 0;
        this.mMatchConstraintPercentHeight = 1.0f;
        this.mResolvedDimensionRatioSide = -1;
        this.mResolvedDimensionRatio = 1.0f;
        this.mBelongingGroup = null;
        this.mMaxDimension = new int[]{ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED, ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED};
        this.mCircleConstraintAngle = 0.0f;
        this.mLeft = new ConstraintAnchor(this, Type.LEFT);
        this.mTop = new ConstraintAnchor(this, Type.TOP);
        this.mRight = new ConstraintAnchor(this, Type.RIGHT);
        this.mBottom = new ConstraintAnchor(this, Type.BOTTOM);
        this.mBaseline = new ConstraintAnchor(this, Type.BASELINE);
        this.mCenterX = new ConstraintAnchor(this, Type.CENTER_X);
        this.mCenterY = new ConstraintAnchor(this, Type.CENTER_Y);
        ConstraintAnchor constraintAnchor = new ConstraintAnchor(this, Type.CENTER);
        this.mCenter = constraintAnchor;
        this.mListAnchors = new ConstraintAnchor[]{this.mLeft, this.mRight, this.mTop, this.mBottom, this.mBaseline, constraintAnchor};
        this.mAnchors = new ArrayList<>();
        this.mListDimensionBehaviors = new DimensionBehaviour[]{DimensionBehaviour.FIXED, DimensionBehaviour.FIXED};
        this.mParent = null;
        this.mWidth = 0;
        this.mHeight = 0;
        this.mDimensionRatio = 0.0f;
        this.mDimensionRatioSide = -1;
        this.f22mX = 0;
        this.f23mY = 0;
        this.mRelX = 0;
        this.mRelY = 0;
        this.mDrawX = 0;
        this.mDrawY = 0;
        this.mDrawWidth = 0;
        this.mDrawHeight = 0;
        this.mOffsetX = 0;
        this.mOffsetY = 0;
        this.mBaselineDistance = 0;
        float f = DEFAULT_BIAS;
        this.mHorizontalBiasPercent = f;
        this.mVerticalBiasPercent = f;
        this.mContainerItemSkip = 0;
        this.mVisibility = 0;
        this.mDebugName = null;
        this.mType = null;
        this.mOptimizerMeasurable = false;
        this.mOptimizerMeasured = false;
        this.mGroupsToSolver = false;
        this.mHorizontalChainStyle = 0;
        this.mVerticalChainStyle = 0;
        this.mWeight = new float[]{-1.0f, -1.0f};
        this.mListNextMatchConstraintsWidget = new ConstraintWidget[]{null, null};
        this.mNextChainWidget = new ConstraintWidget[]{null, null};
        this.mHorizontalNextWidget = null;
        this.mVerticalNextWidget = null;
        this.f22mX = x;
        this.f23mY = y;
        this.mWidth = width;
        this.mHeight = height;
        addAnchors();
        forceUpdateDrawPosition();
    }

    public ConstraintWidget(int width, int height) {
        this(0, 0, width, height);
    }

    public void resetSolverVariables(Cache cache) {
        this.mLeft.resetSolverVariable(cache);
        this.mTop.resetSolverVariable(cache);
        this.mRight.resetSolverVariable(cache);
        this.mBottom.resetSolverVariable(cache);
        this.mBaseline.resetSolverVariable(cache);
        this.mCenter.resetSolverVariable(cache);
        this.mCenterX.resetSolverVariable(cache);
        this.mCenterY.resetSolverVariable(cache);
    }

    private void addAnchors() {
        this.mAnchors.add(this.mLeft);
        this.mAnchors.add(this.mTop);
        this.mAnchors.add(this.mRight);
        this.mAnchors.add(this.mBottom);
        this.mAnchors.add(this.mCenterX);
        this.mAnchors.add(this.mCenterY);
        this.mAnchors.add(this.mCenter);
        this.mAnchors.add(this.mBaseline);
    }

    public boolean isRoot() {
        return this.mParent == null;
    }

    public boolean isRootContainer() {
        if (this instanceof ConstraintWidgetContainer) {
            ConstraintWidget constraintWidget = this.mParent;
            if (constraintWidget == null || !(constraintWidget instanceof ConstraintWidgetContainer)) {
                return true;
            }
        }
        return false;
    }

    public boolean isInsideConstraintLayout() {
        ConstraintWidget widget = getParent();
        if (widget == null) {
            return false;
        }
        while (widget != null) {
            if (widget instanceof ConstraintWidgetContainer) {
                return true;
            }
            widget = widget.getParent();
        }
        return false;
    }

    public boolean hasAncestor(ConstraintWidget widget) {
        ConstraintWidget parent = getParent();
        if (parent == widget) {
            return true;
        }
        if (parent == widget.getParent()) {
            return false;
        }
        while (parent != null) {
            if (parent == widget || parent == widget.getParent()) {
                return true;
            }
            parent = parent.getParent();
        }
        return false;
    }

    public WidgetContainer getRootWidgetContainer() {
        ConstraintWidget root = this;
        while (root.getParent() != null) {
            root = root.getParent();
        }
        if (root instanceof WidgetContainer) {
            return (WidgetContainer) root;
        }
        return null;
    }

    public ConstraintWidget getParent() {
        return this.mParent;
    }

    public void setParent(ConstraintWidget widget) {
        this.mParent = widget;
    }

    public void setWidthWrapContent(boolean widthWrapContent) {
        this.mIsWidthWrapContent = widthWrapContent;
    }

    public boolean isWidthWrapContent() {
        return this.mIsWidthWrapContent;
    }

    public void setHeightWrapContent(boolean heightWrapContent) {
        this.mIsHeightWrapContent = heightWrapContent;
    }

    public boolean isHeightWrapContent() {
        return this.mIsHeightWrapContent;
    }

    public void connectCircularConstraint(ConstraintWidget target, float angle, int radius) {
        immediateConnect(Type.CENTER, target, Type.CENTER, radius, 0);
        this.mCircleConstraintAngle = angle;
    }

    public String getType() {
        return this.mType;
    }

    public void setType(String type) {
        this.mType = type;
    }

    public void setVisibility(int visibility) {
        this.mVisibility = visibility;
    }

    public int getVisibility() {
        return this.mVisibility;
    }

    public String getDebugName() {
        return this.mDebugName;
    }

    public void setDebugName(String name) {
        this.mDebugName = name;
    }

    public void setDebugSolverName(LinearSystem system, String name) {
        this.mDebugName = name;
        SolverVariable left = system.createObjectVariable(this.mLeft);
        SolverVariable top = system.createObjectVariable(this.mTop);
        SolverVariable right = system.createObjectVariable(this.mRight);
        SolverVariable bottom = system.createObjectVariable(this.mBottom);
        StringBuilder sb = new StringBuilder();
        sb.append(name);
        sb.append(".left");
        left.setName(sb.toString());
        StringBuilder sb2 = new StringBuilder();
        sb2.append(name);
        sb2.append(".top");
        top.setName(sb2.toString());
        StringBuilder sb3 = new StringBuilder();
        sb3.append(name);
        sb3.append(".right");
        right.setName(sb3.toString());
        StringBuilder sb4 = new StringBuilder();
        sb4.append(name);
        sb4.append(".bottom");
        bottom.setName(sb4.toString());
        if (this.mBaselineDistance > 0) {
            SolverVariable baseline = system.createObjectVariable(this.mBaseline);
            StringBuilder sb5 = new StringBuilder();
            sb5.append(name);
            sb5.append(".baseline");
            baseline.setName(sb5.toString());
        }
    }

    public void createObjectVariables(LinearSystem system) {
        SolverVariable createObjectVariable = system.createObjectVariable(this.mLeft);
        SolverVariable createObjectVariable2 = system.createObjectVariable(this.mTop);
        SolverVariable createObjectVariable3 = system.createObjectVariable(this.mRight);
        SolverVariable createObjectVariable4 = system.createObjectVariable(this.mBottom);
        if (this.mBaselineDistance > 0) {
            system.createObjectVariable(this.mBaseline);
        }
    }

    public String toString() {
        String str;
        StringBuilder sb = new StringBuilder();
        String str2 = " ";
        String str3 = "";
        if (this.mType != null) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("type: ");
            sb2.append(this.mType);
            sb2.append(str2);
            str = sb2.toString();
        } else {
            str = str3;
        }
        sb.append(str);
        if (this.mDebugName != null) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("id: ");
            sb3.append(this.mDebugName);
            sb3.append(str2);
            str3 = sb3.toString();
        }
        sb.append(str3);
        sb.append("(");
        sb.append(this.f22mX);
        sb.append(", ");
        sb.append(this.f23mY);
        sb.append(") - (");
        sb.append(this.mWidth);
        String str4 = " x ";
        sb.append(str4);
        sb.append(this.mHeight);
        sb.append(") wrap: (");
        sb.append(this.mWrapWidth);
        sb.append(str4);
        sb.append(this.mWrapHeight);
        sb.append(")");
        return sb.toString();
    }

    /* access modifiers changed from: 0000 */
    public int getInternalDrawX() {
        return this.mDrawX;
    }

    /* access modifiers changed from: 0000 */
    public int getInternalDrawY() {
        return this.mDrawY;
    }

    public int getInternalDrawRight() {
        return this.mDrawX + this.mDrawWidth;
    }

    public int getInternalDrawBottom() {
        return this.mDrawY + this.mDrawHeight;
    }

    public int getX() {
        return this.f22mX;
    }

    public int getY() {
        return this.f23mY;
    }

    public int getWidth() {
        if (this.mVisibility == 8) {
            return 0;
        }
        return this.mWidth;
    }

    public int getOptimizerWrapWidth() {
        int w;
        int w2 = this.mWidth;
        if (this.mListDimensionBehaviors[0] != DimensionBehaviour.MATCH_CONSTRAINT) {
            return w2;
        }
        if (this.mMatchConstraintDefaultWidth == 1) {
            w = Math.max(this.mMatchConstraintMinWidth, w2);
        } else if (this.mMatchConstraintMinWidth > 0) {
            w = this.mMatchConstraintMinWidth;
            this.mWidth = w;
        } else {
            w = 0;
        }
        int i = this.mMatchConstraintMaxWidth;
        if (i <= 0 || i >= w) {
            return w;
        }
        return this.mMatchConstraintMaxWidth;
    }

    public int getOptimizerWrapHeight() {
        int h;
        int h2 = this.mHeight;
        if (this.mListDimensionBehaviors[1] != DimensionBehaviour.MATCH_CONSTRAINT) {
            return h2;
        }
        if (this.mMatchConstraintDefaultHeight == 1) {
            h = Math.max(this.mMatchConstraintMinHeight, h2);
        } else if (this.mMatchConstraintMinHeight > 0) {
            h = this.mMatchConstraintMinHeight;
            this.mHeight = h;
        } else {
            h = 0;
        }
        int i = this.mMatchConstraintMaxHeight;
        if (i <= 0 || i >= h) {
            return h;
        }
        return this.mMatchConstraintMaxHeight;
    }

    public int getWrapWidth() {
        return this.mWrapWidth;
    }

    public int getHeight() {
        if (this.mVisibility == 8) {
            return 0;
        }
        return this.mHeight;
    }

    public int getWrapHeight() {
        return this.mWrapHeight;
    }

    public int getLength(int orientation) {
        if (orientation == 0) {
            return getWidth();
        }
        if (orientation == 1) {
            return getHeight();
        }
        return 0;
    }

    public int getDrawX() {
        return this.mDrawX + this.mOffsetX;
    }

    public int getDrawY() {
        return this.mDrawY + this.mOffsetY;
    }

    public int getDrawWidth() {
        return this.mDrawWidth;
    }

    public int getDrawHeight() {
        return this.mDrawHeight;
    }

    public int getDrawBottom() {
        return getDrawY() + this.mDrawHeight;
    }

    public int getDrawRight() {
        return getDrawX() + this.mDrawWidth;
    }

    /* access modifiers changed from: protected */
    public int getRootX() {
        return this.f22mX + this.mOffsetX;
    }

    /* access modifiers changed from: protected */
    public int getRootY() {
        return this.f23mY + this.mOffsetY;
    }

    public int getMinWidth() {
        return this.mMinWidth;
    }

    public int getMinHeight() {
        return this.mMinHeight;
    }

    public int getLeft() {
        return getX();
    }

    public int getTop() {
        return getY();
    }

    public int getRight() {
        return getX() + this.mWidth;
    }

    public int getBottom() {
        return getY() + this.mHeight;
    }

    public float getHorizontalBiasPercent() {
        return this.mHorizontalBiasPercent;
    }

    public float getVerticalBiasPercent() {
        return this.mVerticalBiasPercent;
    }

    public float getBiasPercent(int orientation) {
        if (orientation == 0) {
            return this.mHorizontalBiasPercent;
        }
        if (orientation == 1) {
            return this.mVerticalBiasPercent;
        }
        return -1.0f;
    }

    public boolean hasBaseline() {
        return this.mBaselineDistance > 0;
    }

    public int getBaselineDistance() {
        return this.mBaselineDistance;
    }

    public Object getCompanionWidget() {
        return this.mCompanionWidget;
    }

    public ArrayList<ConstraintAnchor> getAnchors() {
        return this.mAnchors;
    }

    public void setX(int x) {
        this.f22mX = x;
    }

    public void setY(int y) {
        this.f23mY = y;
    }

    public void setOrigin(int x, int y) {
        this.f22mX = x;
        this.f23mY = y;
    }

    public void setOffset(int x, int y) {
        this.mOffsetX = x;
        this.mOffsetY = y;
    }

    public void setGoneMargin(Type type, int goneMargin) {
        int i = C01971.f24x4c44d048[type.ordinal()];
        if (i == 1) {
            this.mLeft.mGoneMargin = goneMargin;
        } else if (i == 2) {
            this.mTop.mGoneMargin = goneMargin;
        } else if (i == 3) {
            this.mRight.mGoneMargin = goneMargin;
        } else if (i == 4) {
            this.mBottom.mGoneMargin = goneMargin;
        }
    }

    public void updateDrawPosition() {
        int left = this.f22mX;
        int top = this.f23mY;
        int right = this.f22mX + this.mWidth;
        int bottom = this.f23mY + this.mHeight;
        this.mDrawX = left;
        this.mDrawY = top;
        this.mDrawWidth = right - left;
        this.mDrawHeight = bottom - top;
    }

    public void forceUpdateDrawPosition() {
        int left = this.f22mX;
        int top = this.f23mY;
        int right = this.f22mX + this.mWidth;
        int bottom = this.f23mY + this.mHeight;
        this.mDrawX = left;
        this.mDrawY = top;
        this.mDrawWidth = right - left;
        this.mDrawHeight = bottom - top;
    }

    public void setDrawOrigin(int x, int y) {
        int i = x - this.mOffsetX;
        this.mDrawX = i;
        int i2 = y - this.mOffsetY;
        this.mDrawY = i2;
        this.f22mX = i;
        this.f23mY = i2;
    }

    public void setDrawX(int x) {
        int i = x - this.mOffsetX;
        this.mDrawX = i;
        this.f22mX = i;
    }

    public void setDrawY(int y) {
        int i = y - this.mOffsetY;
        this.mDrawY = i;
        this.f23mY = i;
    }

    public void setDrawWidth(int drawWidth) {
        this.mDrawWidth = drawWidth;
    }

    public void setDrawHeight(int drawHeight) {
        this.mDrawHeight = drawHeight;
    }

    public void setWidth(int w) {
        this.mWidth = w;
        int i = this.mMinWidth;
        if (w < i) {
            this.mWidth = i;
        }
    }

    public void setHeight(int h) {
        this.mHeight = h;
        int i = this.mMinHeight;
        if (h < i) {
            this.mHeight = i;
        }
    }

    public void setLength(int length, int orientation) {
        if (orientation == 0) {
            setWidth(length);
        } else if (orientation == 1) {
            setHeight(length);
        }
    }

    public void setHorizontalMatchStyle(int horizontalMatchStyle, int min, int max, float percent) {
        this.mMatchConstraintDefaultWidth = horizontalMatchStyle;
        this.mMatchConstraintMinWidth = min;
        this.mMatchConstraintMaxWidth = max;
        this.mMatchConstraintPercentWidth = percent;
        if (percent < 1.0f && horizontalMatchStyle == 0) {
            this.mMatchConstraintDefaultWidth = 2;
        }
    }

    public void setVerticalMatchStyle(int verticalMatchStyle, int min, int max, float percent) {
        this.mMatchConstraintDefaultHeight = verticalMatchStyle;
        this.mMatchConstraintMinHeight = min;
        this.mMatchConstraintMaxHeight = max;
        this.mMatchConstraintPercentHeight = percent;
        if (percent < 1.0f && verticalMatchStyle == 0) {
            this.mMatchConstraintDefaultHeight = 2;
        }
    }

    public void setDimensionRatio(String ratio) {
        int commaIndex;
        if (ratio == null || ratio.length() == 0) {
            this.mDimensionRatio = 0.0f;
            return;
        }
        int dimensionRatioSide = -1;
        float dimensionRatio = 0.0f;
        int len = ratio.length();
        int commaIndex2 = ratio.indexOf(44);
        if (commaIndex2 <= 0 || commaIndex2 >= len - 1) {
            commaIndex = 0;
        } else {
            String dimension = ratio.substring(0, commaIndex2);
            if (dimension.equalsIgnoreCase("W")) {
                dimensionRatioSide = 0;
            } else if (dimension.equalsIgnoreCase("H")) {
                dimensionRatioSide = 1;
            }
            commaIndex = commaIndex2 + 1;
        }
        int colonIndex = ratio.indexOf(58);
        if (colonIndex < 0 || colonIndex >= len - 1) {
            String r = ratio.substring(commaIndex);
            if (r.length() > 0) {
                try {
                    dimensionRatio = Float.parseFloat(r);
                } catch (NumberFormatException e) {
                }
            }
        } else {
            String nominator = ratio.substring(commaIndex, colonIndex);
            String denominator = ratio.substring(colonIndex + 1);
            if (nominator.length() > 0 && denominator.length() > 0) {
                try {
                    float nominatorValue = Float.parseFloat(nominator);
                    float denominatorValue = Float.parseFloat(denominator);
                    if (nominatorValue > 0.0f && denominatorValue > 0.0f) {
                        dimensionRatio = dimensionRatioSide == 1 ? Math.abs(denominatorValue / nominatorValue) : Math.abs(nominatorValue / denominatorValue);
                    }
                } catch (NumberFormatException e2) {
                }
            }
        }
        if (dimensionRatio > 0.0f) {
            this.mDimensionRatio = dimensionRatio;
            this.mDimensionRatioSide = dimensionRatioSide;
        }
    }

    public void setDimensionRatio(float ratio, int dimensionRatioSide) {
        this.mDimensionRatio = ratio;
        this.mDimensionRatioSide = dimensionRatioSide;
    }

    public float getDimensionRatio() {
        return this.mDimensionRatio;
    }

    public int getDimensionRatioSide() {
        return this.mDimensionRatioSide;
    }

    public void setHorizontalBiasPercent(float horizontalBiasPercent) {
        this.mHorizontalBiasPercent = horizontalBiasPercent;
    }

    public void setVerticalBiasPercent(float verticalBiasPercent) {
        this.mVerticalBiasPercent = verticalBiasPercent;
    }

    public void setMinWidth(int w) {
        if (w < 0) {
            this.mMinWidth = 0;
        } else {
            this.mMinWidth = w;
        }
    }

    public void setMinHeight(int h) {
        if (h < 0) {
            this.mMinHeight = 0;
        } else {
            this.mMinHeight = h;
        }
    }

    public void setWrapWidth(int w) {
        this.mWrapWidth = w;
    }

    public void setWrapHeight(int h) {
        this.mWrapHeight = h;
    }

    public void setDimension(int w, int h) {
        this.mWidth = w;
        int i = this.mMinWidth;
        if (w < i) {
            this.mWidth = i;
        }
        this.mHeight = h;
        int i2 = this.mMinHeight;
        if (h < i2) {
            this.mHeight = i2;
        }
    }

    public void setFrame(int left, int top, int right, int bottom) {
        int w = right - left;
        int h = bottom - top;
        this.f22mX = left;
        this.f23mY = top;
        if (this.mVisibility == 8) {
            this.mWidth = 0;
            this.mHeight = 0;
            return;
        }
        if (this.mListDimensionBehaviors[0] == DimensionBehaviour.FIXED && w < this.mWidth) {
            w = this.mWidth;
        }
        if (this.mListDimensionBehaviors[1] == DimensionBehaviour.FIXED && h < this.mHeight) {
            h = this.mHeight;
        }
        this.mWidth = w;
        this.mHeight = h;
        int i = this.mMinHeight;
        if (h < i) {
            this.mHeight = i;
        }
        int i2 = this.mWidth;
        int i3 = this.mMinWidth;
        if (i2 < i3) {
            this.mWidth = i3;
        }
        this.mOptimizerMeasured = true;
    }

    public void setFrame(int start, int end, int orientation) {
        if (orientation == 0) {
            setHorizontalDimension(start, end);
        } else if (orientation == 1) {
            setVerticalDimension(start, end);
        }
        this.mOptimizerMeasured = true;
    }

    public void setHorizontalDimension(int left, int right) {
        this.f22mX = left;
        int i = right - left;
        this.mWidth = i;
        int i2 = this.mMinWidth;
        if (i < i2) {
            this.mWidth = i2;
        }
    }

    public void setVerticalDimension(int top, int bottom) {
        this.f23mY = top;
        int i = bottom - top;
        this.mHeight = i;
        int i2 = this.mMinHeight;
        if (i < i2) {
            this.mHeight = i2;
        }
    }

    /* access modifiers changed from: 0000 */
    public int getRelativePositioning(int orientation) {
        if (orientation == 0) {
            return this.mRelX;
        }
        if (orientation == 1) {
            return this.mRelY;
        }
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public void setRelativePositioning(int offset, int orientation) {
        if (orientation == 0) {
            this.mRelX = offset;
        } else if (orientation == 1) {
            this.mRelY = offset;
        }
    }

    public void setBaselineDistance(int baseline) {
        this.mBaselineDistance = baseline;
    }

    public void setCompanionWidget(Object companion) {
        this.mCompanionWidget = companion;
    }

    public void setContainerItemSkip(int skip) {
        if (skip >= 0) {
            this.mContainerItemSkip = skip;
        } else {
            this.mContainerItemSkip = 0;
        }
    }

    public int getContainerItemSkip() {
        return this.mContainerItemSkip;
    }

    public void setHorizontalWeight(float horizontalWeight) {
        this.mWeight[0] = horizontalWeight;
    }

    public void setVerticalWeight(float verticalWeight) {
        this.mWeight[1] = verticalWeight;
    }

    public void setHorizontalChainStyle(int horizontalChainStyle) {
        this.mHorizontalChainStyle = horizontalChainStyle;
    }

    public int getHorizontalChainStyle() {
        return this.mHorizontalChainStyle;
    }

    public void setVerticalChainStyle(int verticalChainStyle) {
        this.mVerticalChainStyle = verticalChainStyle;
    }

    public int getVerticalChainStyle() {
        return this.mVerticalChainStyle;
    }

    public boolean allowedInBarrier() {
        return this.mVisibility != 8;
    }

    public void connectedTo(ConstraintWidget source) {
    }

    public void immediateConnect(Type startType, ConstraintWidget target, Type endType, int margin, int goneMargin) {
        ConstraintAnchor startAnchor = getAnchor(startType);
        startAnchor.connect(target.getAnchor(endType), margin, goneMargin, Strength.STRONG, 0, true);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin, int creator) {
        connect(from, to, margin, Strength.STRONG, creator);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin) {
        connect(from, to, margin, Strength.STRONG, 0);
    }

    public void connect(ConstraintAnchor from, ConstraintAnchor to, int margin, Strength strength, int creator) {
        if (from.getOwner() == this) {
            connect(from.getType(), to.getOwner(), to.getType(), margin, strength, creator);
        }
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin) {
        connect(constraintFrom, target, constraintTo, margin, Strength.STRONG);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo) {
        connect(constraintFrom, target, constraintTo, 0, Strength.STRONG);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin, Strength strength) {
        connect(constraintFrom, target, constraintTo, margin, strength, 0);
    }

    public void connect(Type constraintFrom, ConstraintWidget target, Type constraintTo, int margin, Strength strength, int creator) {
        int margin2;
        Type type = constraintFrom;
        ConstraintWidget constraintWidget = target;
        Type type2 = constraintTo;
        int i = creator;
        if (type == Type.CENTER) {
            if (type2 == Type.CENTER) {
                ConstraintAnchor left = getAnchor(Type.LEFT);
                ConstraintAnchor right = getAnchor(Type.RIGHT);
                ConstraintAnchor top = getAnchor(Type.TOP);
                ConstraintAnchor bottom = getAnchor(Type.BOTTOM);
                boolean centerX = false;
                boolean centerY = false;
                if ((left == null || !left.isConnected()) && (right == null || !right.isConnected())) {
                    ConstraintWidget constraintWidget2 = target;
                    Strength strength2 = strength;
                    int i2 = creator;
                    connect(Type.LEFT, constraintWidget2, Type.LEFT, 0, strength2, i2);
                    connect(Type.RIGHT, constraintWidget2, Type.RIGHT, 0, strength2, i2);
                    centerX = true;
                }
                if ((top == null || !top.isConnected()) && (bottom == null || !bottom.isConnected())) {
                    ConstraintWidget constraintWidget3 = target;
                    Strength strength3 = strength;
                    int i3 = creator;
                    connect(Type.TOP, constraintWidget3, Type.TOP, 0, strength3, i3);
                    connect(Type.BOTTOM, constraintWidget3, Type.BOTTOM, 0, strength3, i3);
                    centerY = true;
                }
                if (centerX && centerY) {
                    getAnchor(Type.CENTER).connect(constraintWidget.getAnchor(Type.CENTER), 0, i);
                } else if (centerX) {
                    getAnchor(Type.CENTER_X).connect(constraintWidget.getAnchor(Type.CENTER_X), 0, i);
                } else if (centerY) {
                    getAnchor(Type.CENTER_Y).connect(constraintWidget.getAnchor(Type.CENTER_Y), 0, i);
                }
                Strength strength4 = strength;
            } else {
                if (type2 == Type.LEFT || type2 == Type.RIGHT) {
                    ConstraintWidget constraintWidget4 = target;
                    Type type3 = constraintTo;
                    Strength strength5 = strength;
                    int i4 = creator;
                    connect(Type.LEFT, constraintWidget4, type3, 0, strength5, i4);
                    connect(Type.RIGHT, constraintWidget4, type3, 0, strength5, i4);
                    getAnchor(Type.CENTER).connect(target.getAnchor(constraintTo), 0, i);
                } else if (type2 == Type.TOP || type2 == Type.BOTTOM) {
                    ConstraintWidget constraintWidget5 = target;
                    Type type4 = constraintTo;
                    Strength strength6 = strength;
                    int i5 = creator;
                    connect(Type.TOP, constraintWidget5, type4, 0, strength6, i5);
                    connect(Type.BOTTOM, constraintWidget5, type4, 0, strength6, i5);
                    getAnchor(Type.CENTER).connect(target.getAnchor(constraintTo), 0, i);
                    Strength strength7 = strength;
                }
                Strength strength8 = strength;
            }
        } else if (type == Type.CENTER_X && (type2 == Type.LEFT || type2 == Type.RIGHT)) {
            ConstraintAnchor left2 = getAnchor(Type.LEFT);
            ConstraintAnchor targetAnchor = target.getAnchor(constraintTo);
            ConstraintAnchor right2 = getAnchor(Type.RIGHT);
            left2.connect(targetAnchor, 0, i);
            right2.connect(targetAnchor, 0, i);
            getAnchor(Type.CENTER_X).connect(targetAnchor, 0, i);
            Strength strength9 = strength;
        } else if (type == Type.CENTER_Y && (type2 == Type.TOP || type2 == Type.BOTTOM)) {
            ConstraintAnchor targetAnchor2 = target.getAnchor(constraintTo);
            getAnchor(Type.TOP).connect(targetAnchor2, 0, i);
            getAnchor(Type.BOTTOM).connect(targetAnchor2, 0, i);
            getAnchor(Type.CENTER_Y).connect(targetAnchor2, 0, i);
            Strength strength10 = strength;
        } else if (type == Type.CENTER_X && type2 == Type.CENTER_X) {
            getAnchor(Type.LEFT).connect(constraintWidget.getAnchor(Type.LEFT), 0, i);
            getAnchor(Type.RIGHT).connect(constraintWidget.getAnchor(Type.RIGHT), 0, i);
            getAnchor(Type.CENTER_X).connect(target.getAnchor(constraintTo), 0, i);
            Strength strength11 = strength;
        } else if (type == Type.CENTER_Y && type2 == Type.CENTER_Y) {
            getAnchor(Type.TOP).connect(constraintWidget.getAnchor(Type.TOP), 0, i);
            getAnchor(Type.BOTTOM).connect(constraintWidget.getAnchor(Type.BOTTOM), 0, i);
            getAnchor(Type.CENTER_Y).connect(target.getAnchor(constraintTo), 0, i);
            Strength strength12 = strength;
        } else {
            ConstraintAnchor fromAnchor = getAnchor(constraintFrom);
            ConstraintAnchor toAnchor = target.getAnchor(constraintTo);
            if (fromAnchor.isValidConnection(toAnchor)) {
                if (type == Type.BASELINE) {
                    ConstraintAnchor top2 = getAnchor(Type.TOP);
                    ConstraintAnchor bottom2 = getAnchor(Type.BOTTOM);
                    if (top2 != null) {
                        top2.reset();
                    }
                    if (bottom2 != null) {
                        bottom2.reset();
                    }
                    margin2 = 0;
                } else {
                    if (type == Type.TOP || type == Type.BOTTOM) {
                        ConstraintAnchor baseline = getAnchor(Type.BASELINE);
                        if (baseline != null) {
                            baseline.reset();
                        }
                        ConstraintAnchor center = getAnchor(Type.CENTER);
                        if (center.getTarget() != toAnchor) {
                            center.reset();
                        }
                        ConstraintAnchor opposite = getAnchor(constraintFrom).getOpposite();
                        ConstraintAnchor centerY2 = getAnchor(Type.CENTER_Y);
                        if (centerY2.isConnected()) {
                            opposite.reset();
                            centerY2.reset();
                        }
                    } else if (type == Type.LEFT || type == Type.RIGHT) {
                        ConstraintAnchor center2 = getAnchor(Type.CENTER);
                        if (center2.getTarget() != toAnchor) {
                            center2.reset();
                        }
                        ConstraintAnchor opposite2 = getAnchor(constraintFrom).getOpposite();
                        ConstraintAnchor centerX2 = getAnchor(Type.CENTER_X);
                        if (centerX2.isConnected()) {
                            opposite2.reset();
                            centerX2.reset();
                        }
                    }
                    margin2 = margin;
                }
                fromAnchor.connect(toAnchor, margin2, strength, i);
                toAnchor.getOwner().connectedTo(fromAnchor.getOwner());
                return;
            }
            Strength strength13 = strength;
        }
        int i6 = margin;
    }

    public void resetAllConstraints() {
        resetAnchors();
        setVerticalBiasPercent(DEFAULT_BIAS);
        setHorizontalBiasPercent(DEFAULT_BIAS);
        if (!(this instanceof ConstraintWidgetContainer)) {
            if (getHorizontalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
                if (getWidth() == getWrapWidth()) {
                    setHorizontalDimensionBehaviour(DimensionBehaviour.WRAP_CONTENT);
                } else if (getWidth() > getMinWidth()) {
                    setHorizontalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
            }
            if (getVerticalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
                if (getHeight() == getWrapHeight()) {
                    setVerticalDimensionBehaviour(DimensionBehaviour.WRAP_CONTENT);
                } else if (getHeight() > getMinHeight()) {
                    setVerticalDimensionBehaviour(DimensionBehaviour.FIXED);
                }
            }
        }
    }

    public void resetAnchor(ConstraintAnchor anchor) {
        if (getParent() == null || !(getParent() instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            ConstraintAnchor left = getAnchor(Type.LEFT);
            ConstraintAnchor right = getAnchor(Type.RIGHT);
            ConstraintAnchor top = getAnchor(Type.TOP);
            ConstraintAnchor bottom = getAnchor(Type.BOTTOM);
            ConstraintAnchor center = getAnchor(Type.CENTER);
            ConstraintAnchor centerX = getAnchor(Type.CENTER_X);
            ConstraintAnchor centerY = getAnchor(Type.CENTER_Y);
            if (anchor == center) {
                if (left.isConnected() && right.isConnected() && left.getTarget() == right.getTarget()) {
                    left.reset();
                    right.reset();
                }
                if (top.isConnected() && bottom.isConnected() && top.getTarget() == bottom.getTarget()) {
                    top.reset();
                    bottom.reset();
                }
                this.mHorizontalBiasPercent = 0.5f;
                this.mVerticalBiasPercent = 0.5f;
            } else if (anchor == centerX) {
                if (left.isConnected() && right.isConnected() && left.getTarget().getOwner() == right.getTarget().getOwner()) {
                    left.reset();
                    right.reset();
                }
                this.mHorizontalBiasPercent = 0.5f;
            } else if (anchor == centerY) {
                if (top.isConnected() && bottom.isConnected() && top.getTarget().getOwner() == bottom.getTarget().getOwner()) {
                    top.reset();
                    bottom.reset();
                }
                this.mVerticalBiasPercent = 0.5f;
            } else if (anchor == left || anchor == right) {
                if (left.isConnected() && left.getTarget() == right.getTarget()) {
                    center.reset();
                }
            } else if ((anchor == top || anchor == bottom) && top.isConnected() && top.getTarget() == bottom.getTarget()) {
                center.reset();
            }
            anchor.reset();
        }
    }

    public void resetAnchors() {
        ConstraintWidget parent = getParent();
        if (parent == null || !(parent instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            int mAnchorsSize = this.mAnchors.size();
            for (int i = 0; i < mAnchorsSize; i++) {
                ((ConstraintAnchor) this.mAnchors.get(i)).reset();
            }
        }
    }

    public void resetAnchors(int connectionCreator) {
        ConstraintWidget parent = getParent();
        if (parent == null || !(parent instanceof ConstraintWidgetContainer) || !((ConstraintWidgetContainer) getParent()).handlesInternalConstraints()) {
            int mAnchorsSize = this.mAnchors.size();
            for (int i = 0; i < mAnchorsSize; i++) {
                ConstraintAnchor anchor = (ConstraintAnchor) this.mAnchors.get(i);
                if (connectionCreator == anchor.getConnectionCreator()) {
                    if (anchor.isVerticalAnchor()) {
                        setVerticalBiasPercent(DEFAULT_BIAS);
                    } else {
                        setHorizontalBiasPercent(DEFAULT_BIAS);
                    }
                    anchor.reset();
                }
            }
        }
    }

    public void disconnectWidget(ConstraintWidget widget) {
        ArrayList<ConstraintAnchor> anchors = getAnchors();
        int anchorsSize = anchors.size();
        for (int i = 0; i < anchorsSize; i++) {
            ConstraintAnchor anchor = (ConstraintAnchor) anchors.get(i);
            if (anchor.isConnected() && anchor.getTarget().getOwner() == widget) {
                anchor.reset();
            }
        }
    }

    public void disconnectUnlockedWidget(ConstraintWidget widget) {
        ArrayList<ConstraintAnchor> anchors = getAnchors();
        int anchorsSize = anchors.size();
        for (int i = 0; i < anchorsSize; i++) {
            ConstraintAnchor anchor = (ConstraintAnchor) anchors.get(i);
            if (anchor.isConnected() && anchor.getTarget().getOwner() == widget && anchor.getConnectionCreator() == 2) {
                anchor.reset();
            }
        }
    }

    public ConstraintAnchor getAnchor(Type anchorType) {
        switch (C01971.f24x4c44d048[anchorType.ordinal()]) {
            case 1:
                return this.mLeft;
            case 2:
                return this.mTop;
            case 3:
                return this.mRight;
            case 4:
                return this.mBottom;
            case 5:
                return this.mBaseline;
            case 6:
                return this.mCenter;
            case 7:
                return this.mCenterX;
            case 8:
                return this.mCenterY;
            case 9:
                return null;
            default:
                throw new AssertionError(anchorType.name());
        }
    }

    public DimensionBehaviour getHorizontalDimensionBehaviour() {
        return this.mListDimensionBehaviors[0];
    }

    public DimensionBehaviour getVerticalDimensionBehaviour() {
        return this.mListDimensionBehaviors[1];
    }

    public DimensionBehaviour getDimensionBehaviour(int orientation) {
        if (orientation == 0) {
            return getHorizontalDimensionBehaviour();
        }
        if (orientation == 1) {
            return getVerticalDimensionBehaviour();
        }
        return null;
    }

    public void setHorizontalDimensionBehaviour(DimensionBehaviour behaviour) {
        this.mListDimensionBehaviors[0] = behaviour;
        if (behaviour == DimensionBehaviour.WRAP_CONTENT) {
            setWidth(this.mWrapWidth);
        }
    }

    public void setVerticalDimensionBehaviour(DimensionBehaviour behaviour) {
        this.mListDimensionBehaviors[1] = behaviour;
        if (behaviour == DimensionBehaviour.WRAP_CONTENT) {
            setHeight(this.mWrapHeight);
        }
    }

    public boolean isInHorizontalChain() {
        if ((this.mLeft.mTarget == null || this.mLeft.mTarget.mTarget != this.mLeft) && (this.mRight.mTarget == null || this.mRight.mTarget.mTarget != this.mRight)) {
            return false;
        }
        return true;
    }

    public ConstraintWidget getHorizontalChainControlWidget() {
        ConstraintWidget found = null;
        if (!isInHorizontalChain()) {
            return null;
        }
        ConstraintWidget tmp = this;
        while (found == null && tmp != null) {
            ConstraintAnchor anchor = tmp.getAnchor(Type.LEFT);
            ConstraintAnchor targetAnchor = null;
            ConstraintAnchor targetOwner = anchor == null ? null : anchor.getTarget();
            ConstraintWidget target = targetOwner == null ? null : targetOwner.getOwner();
            if (target == getParent()) {
                return tmp;
            }
            if (target != null) {
                targetAnchor = target.getAnchor(Type.RIGHT).getTarget();
            }
            if (targetAnchor == null || targetAnchor.getOwner() == tmp) {
                tmp = target;
            } else {
                found = tmp;
            }
        }
        return found;
    }

    public boolean isInVerticalChain() {
        if ((this.mTop.mTarget == null || this.mTop.mTarget.mTarget != this.mTop) && (this.mBottom.mTarget == null || this.mBottom.mTarget.mTarget != this.mBottom)) {
            return false;
        }
        return true;
    }

    public ConstraintWidget getVerticalChainControlWidget() {
        ConstraintWidget found = null;
        if (!isInVerticalChain()) {
            return null;
        }
        ConstraintWidget tmp = this;
        while (found == null && tmp != null) {
            ConstraintAnchor anchor = tmp.getAnchor(Type.TOP);
            ConstraintAnchor targetAnchor = null;
            ConstraintAnchor targetOwner = anchor == null ? null : anchor.getTarget();
            ConstraintWidget target = targetOwner == null ? null : targetOwner.getOwner();
            if (target == getParent()) {
                return tmp;
            }
            if (target != null) {
                targetAnchor = target.getAnchor(Type.BOTTOM).getTarget();
            }
            if (targetAnchor == null || targetAnchor.getOwner() == tmp) {
                tmp = target;
            } else {
                found = tmp;
            }
        }
        return found;
    }

    private boolean isChainHead(int orientation) {
        int offset = orientation * 2;
        if (this.mListAnchors[offset].mTarget != null) {
            ConstraintAnchor constraintAnchor = this.mListAnchors[offset].mTarget.mTarget;
            ConstraintAnchor[] constraintAnchorArr = this.mListAnchors;
            if (!(constraintAnchor == constraintAnchorArr[offset] || constraintAnchorArr[offset + 1].mTarget == null || this.mListAnchors[offset + 1].mTarget.mTarget != this.mListAnchors[offset + 1])) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:98:0x01c8, code lost:
        if (r0 == -1) goto L_0x01cc;
     */
    /* JADX WARNING: Removed duplicated region for block: B:101:0x01ce  */
    /* JADX WARNING: Removed duplicated region for block: B:105:0x01d9  */
    /* JADX WARNING: Removed duplicated region for block: B:111:0x01ec  */
    /* JADX WARNING: Removed duplicated region for block: B:112:0x01f0  */
    /* JADX WARNING: Removed duplicated region for block: B:115:0x01f9  */
    /* JADX WARNING: Removed duplicated region for block: B:124:0x0260  */
    /* JADX WARNING: Removed duplicated region for block: B:127:0x0277 A[RETURN] */
    /* JADX WARNING: Removed duplicated region for block: B:128:0x0278  */
    /* JADX WARNING: Removed duplicated region for block: B:143:0x029c  */
    /* JADX WARNING: Removed duplicated region for block: B:149:0x02db  */
    /* JADX WARNING: Removed duplicated region for block: B:153:0x02e7  */
    /* JADX WARNING: Removed duplicated region for block: B:154:0x02f0  */
    /* JADX WARNING: Removed duplicated region for block: B:157:0x02f6  */
    /* JADX WARNING: Removed duplicated region for block: B:158:0x02ff  */
    /* JADX WARNING: Removed duplicated region for block: B:161:0x033c  */
    /* JADX WARNING: Removed duplicated region for block: B:167:0x0368  */
    /* JADX WARNING: Removed duplicated region for block: B:95:0x01c3  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void addToSolver(androidx.constraintlayout.solver.LinearSystem r53) {
        /*
            r52 = this;
            r15 = r52
            r10 = r53
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r15.mLeft
            androidx.constraintlayout.solver.SolverVariable r36 = r10.createObjectVariable(r0)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r15.mRight
            androidx.constraintlayout.solver.SolverVariable r2 = r10.createObjectVariable(r0)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r15.mTop
            androidx.constraintlayout.solver.SolverVariable r1 = r10.createObjectVariable(r0)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r15.mBottom
            androidx.constraintlayout.solver.SolverVariable r0 = r10.createObjectVariable(r0)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r3 = r15.mBaseline
            androidx.constraintlayout.solver.SolverVariable r13 = r10.createObjectVariable(r3)
            r3 = 0
            r4 = 0
            r5 = 0
            r6 = 0
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            r8 = 8
            r12 = 0
            r11 = 1
            if (r7 == 0) goto L_0x00b7
            if (r7 == 0) goto L_0x003a
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r7 = r7.mListDimensionBehaviors
            r7 = r7[r12]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r7 != r9) goto L_0x003a
            r7 = r11
            goto L_0x003b
        L_0x003a:
            r7 = r12
        L_0x003b:
            r5 = r7
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            if (r7 == 0) goto L_0x004a
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r7 = r7.mListDimensionBehaviors
            r7 = r7[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r9 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r7 != r9) goto L_0x004a
            r7 = r11
            goto L_0x004b
        L_0x004a:
            r7 = r12
        L_0x004b:
            r6 = r7
            boolean r7 = r15.isChainHead(r12)
            if (r7 == 0) goto L_0x005b
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer r7 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer) r7
            r7.addChain(r15, r12)
            r3 = 1
            goto L_0x005f
        L_0x005b:
            boolean r3 = r52.isInHorizontalChain()
        L_0x005f:
            boolean r7 = r15.isChainHead(r11)
            if (r7 == 0) goto L_0x006e
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer r7 = (androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer) r7
            r7.addChain(r15, r11)
            r4 = 1
            goto L_0x0072
        L_0x006e:
            boolean r4 = r52.isInVerticalChain()
        L_0x0072:
            if (r5 == 0) goto L_0x008f
            int r7 = r15.mVisibility
            if (r7 == r8) goto L_0x008f
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r15.mLeft
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mTarget
            if (r7 != 0) goto L_0x008f
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r15.mRight
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mTarget
            if (r7 != 0) goto L_0x008f
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mRight
            androidx.constraintlayout.solver.SolverVariable r7 = r10.createObjectVariable(r7)
            r10.addGreaterThan(r7, r2, r12, r11)
        L_0x008f:
            if (r6 == 0) goto L_0x00b0
            int r7 = r15.mVisibility
            if (r7 == r8) goto L_0x00b0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r15.mTop
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mTarget
            if (r7 != 0) goto L_0x00b0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r15.mBottom
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mTarget
            if (r7 != 0) goto L_0x00b0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r15.mBaseline
            if (r7 != 0) goto L_0x00b0
            androidx.constraintlayout.solver.widgets.ConstraintWidget r7 = r15.mParent
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r7 = r7.mBottom
            androidx.constraintlayout.solver.SolverVariable r7 = r10.createObjectVariable(r7)
            r10.addGreaterThan(r7, r0, r12, r11)
        L_0x00b0:
            r37 = r3
            r38 = r4
            r9 = r5
            r7 = r6
            goto L_0x00bd
        L_0x00b7:
            r37 = r3
            r38 = r4
            r9 = r5
            r7 = r6
        L_0x00bd:
            int r3 = r15.mWidth
            int r4 = r15.mMinWidth
            if (r3 >= r4) goto L_0x00c5
            int r3 = r15.mMinWidth
        L_0x00c5:
            int r4 = r15.mHeight
            int r5 = r15.mMinHeight
            if (r4 >= r5) goto L_0x00cd
            int r4 = r15.mMinHeight
        L_0x00cd:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r5 = r15.mListDimensionBehaviors
            r5 = r5[r12]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r6 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r5 == r6) goto L_0x00d7
            r5 = r11
            goto L_0x00d8
        L_0x00d7:
            r5 = r12
        L_0x00d8:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r6 = r15.mListDimensionBehaviors
            r6 = r6[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r14 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r6 == r14) goto L_0x00e2
            r6 = r11
            goto L_0x00e3
        L_0x00e2:
            r6 = r12
        L_0x00e3:
            r14 = 0
            int r11 = r15.mDimensionRatioSide
            r15.mResolvedDimensionRatioSide = r11
            float r11 = r15.mDimensionRatio
            r15.mResolvedDimensionRatio = r11
            int r12 = r15.mMatchConstraintDefaultWidth
            int r8 = r15.mMatchConstraintDefaultHeight
            r19 = 0
            int r11 = (r11 > r19 ? 1 : (r11 == r19 ? 0 : -1))
            r20 = r2
            if (r11 <= 0) goto L_0x01ad
            int r11 = r15.mVisibility
            r2 = 8
            if (r11 == r2) goto L_0x01ad
            r14 = 1
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 0
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r2 != r11) goto L_0x010b
            if (r12 != 0) goto L_0x010b
            r12 = 3
        L_0x010b:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 1
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r2 != r11) goto L_0x0117
            if (r8 != 0) goto L_0x0117
            r8 = 3
        L_0x0117:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 0
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            r22 = r0
            r0 = 3
            if (r2 != r11) goto L_0x0135
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 1
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r2 != r11) goto L_0x0135
            if (r12 != r0) goto L_0x0135
            if (r8 != r0) goto L_0x0135
            r15.setupDimensionRatio(r9, r7, r5, r6)
            goto L_0x01af
        L_0x0135:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 0
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r2 != r11) goto L_0x016b
            if (r12 != r0) goto L_0x016b
            r0 = 0
            r15.mResolvedDimensionRatioSide = r0
            float r0 = r15.mResolvedDimensionRatio
            int r2 = r15.mHeight
            float r2 = (float) r2
            float r0 = r0 * r2
            int r3 = (int) r0
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r15.mListDimensionBehaviors
            r2 = 1
            r0 = r0[r2]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r2 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r0 == r2) goto L_0x0160
            r12 = 4
            r14 = 0
            r39 = r3
            r40 = r4
            r41 = r8
            r42 = r12
            r43 = r14
            goto L_0x01b9
        L_0x0160:
            r39 = r3
            r40 = r4
            r41 = r8
            r42 = r12
            r43 = r14
            goto L_0x01b9
        L_0x016b:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r2 = r15.mListDimensionBehaviors
            r11 = 1
            r2 = r2[r11]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r11 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r2 != r11) goto L_0x01af
            if (r8 != r0) goto L_0x01af
            r0 = 1
            r15.mResolvedDimensionRatioSide = r0
            int r0 = r15.mDimensionRatioSide
            r2 = -1
            if (r0 != r2) goto L_0x0185
            r0 = 1065353216(0x3f800000, float:1.0)
            float r2 = r15.mResolvedDimensionRatio
            float r0 = r0 / r2
            r15.mResolvedDimensionRatio = r0
        L_0x0185:
            float r0 = r15.mResolvedDimensionRatio
            int r2 = r15.mWidth
            float r2 = (float) r2
            float r0 = r0 * r2
            int r4 = (int) r0
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r15.mListDimensionBehaviors
            r2 = 0
            r0 = r0[r2]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r2 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT
            if (r0 == r2) goto L_0x01a2
            r8 = 4
            r14 = 0
            r39 = r3
            r40 = r4
            r41 = r8
            r42 = r12
            r43 = r14
            goto L_0x01b9
        L_0x01a2:
            r39 = r3
            r40 = r4
            r41 = r8
            r42 = r12
            r43 = r14
            goto L_0x01b9
        L_0x01ad:
            r22 = r0
        L_0x01af:
            r39 = r3
            r40 = r4
            r41 = r8
            r42 = r12
            r43 = r14
        L_0x01b9:
            int[] r0 = r15.mResolvedMatchConstraintDefault
            r2 = 0
            r0[r2] = r42
            r2 = 1
            r0[r2] = r41
            if (r43 == 0) goto L_0x01ce
            int r0 = r15.mResolvedDimensionRatioSide
            if (r0 == 0) goto L_0x01cb
            r12 = -1
            if (r0 != r12) goto L_0x01cf
            goto L_0x01cc
        L_0x01cb:
            r12 = -1
        L_0x01cc:
            r14 = r2
            goto L_0x01d0
        L_0x01ce:
            r12 = -1
        L_0x01cf:
            r14 = 0
        L_0x01d0:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r15.mListDimensionBehaviors
            r3 = 0
            r0 = r0[r3]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r3 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r0 != r3) goto L_0x01df
            boolean r0 = r15 instanceof androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer
            if (r0 == 0) goto L_0x01df
            r0 = r2
            goto L_0x01e0
        L_0x01df:
            r0 = 0
        L_0x01e0:
            r44 = r6
            r6 = r0
            r0 = 1
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r3 = r15.mCenter
            boolean r3 = r3.isConnected()
            if (r3 == 0) goto L_0x01f0
            r0 = 0
            r23 = r0
            goto L_0x01f2
        L_0x01f0:
            r23 = r0
        L_0x01f2:
            int r0 = r15.mHorizontalResolution
            r11 = 2
            r24 = 0
            if (r0 == r11) goto L_0x0260
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r15.mParent
            if (r0 == 0) goto L_0x0205
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mRight
            androidx.constraintlayout.solver.SolverVariable r0 = r10.createObjectVariable(r0)
            r4 = r0
            goto L_0x0207
        L_0x0205:
            r4 = r24
        L_0x0207:
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r15.mParent
            if (r0 == 0) goto L_0x0213
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mLeft
            androidx.constraintlayout.solver.SolverVariable r0 = r10.createObjectVariable(r0)
            r3 = r0
            goto L_0x0215
        L_0x0213:
            r3 = r24
        L_0x0215:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r15.mListDimensionBehaviors
            r16 = 0
            r0 = r0[r16]
            r45 = r5
            r5 = r0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r15.mLeft
            r46 = r7
            r7 = r0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r8 = r15.mRight
            int r0 = r15.f22mX
            r47 = r9
            r9 = r0
            int r0 = r15.mMinWidth
            r2 = r11
            r11 = r0
            int[] r0 = r15.mMaxDimension
            r0 = r0[r16]
            r25 = r16
            r16 = r12
            r12 = r0
            float r0 = r15.mHorizontalBiasPercent
            r48 = r13
            r13 = r0
            int r0 = r15.mMatchConstraintMinWidth
            r17 = r0
            int r0 = r15.mMatchConstraintMaxWidth
            r18 = r0
            float r0 = r15.mMatchConstraintPercentWidth
            r19 = r0
            r49 = r22
            r0 = r52
            r50 = r1
            r1 = r53
            r51 = r20
            r2 = r47
            r10 = r39
            r15 = r37
            r16 = r42
            r20 = r23
            r0.applyConstraints(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20)
            goto L_0x0270
        L_0x0260:
            r50 = r1
            r45 = r5
            r46 = r7
            r47 = r9
            r48 = r13
            r51 = r20
            r49 = r22
            r25 = 0
        L_0x0270:
            r7 = r52
            int r0 = r7.mVerticalResolution
            r1 = 2
            if (r0 != r1) goto L_0x0278
            return
        L_0x0278:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r7.mListDimensionBehaviors
            r1 = 1
            r0 = r0[r1]
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour r2 = androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour.WRAP_CONTENT
            if (r0 != r2) goto L_0x0288
            boolean r0 = r7 instanceof androidx.constraintlayout.solver.widgets.ConstraintWidgetContainer
            if (r0 == 0) goto L_0x0288
            r21 = r1
            goto L_0x028a
        L_0x0288:
            r21 = r25
        L_0x028a:
            if (r43 == 0) goto L_0x0296
            int r0 = r7.mResolvedDimensionRatioSide
            if (r0 == r1) goto L_0x0293
            r2 = -1
            if (r0 != r2) goto L_0x0296
        L_0x0293:
            r29 = r1
            goto L_0x0298
        L_0x0296:
            r29 = r25
        L_0x0298:
            int r0 = r7.mBaselineDistance
            if (r0 <= 0) goto L_0x02db
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mBaseline
            androidx.constraintlayout.solver.widgets.ResolutionAnchor r0 = r0.getResolutionNode()
            int r0 = r0.state
            if (r0 != r1) goto L_0x02b6
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mBaseline
            androidx.constraintlayout.solver.widgets.ResolutionAnchor r0 = r0.getResolutionNode()
            r8 = r53
            r0.addResolvedValue(r8)
            r10 = r48
            r9 = r50
            goto L_0x02e1
        L_0x02b6:
            r8 = r53
            int r0 = r52.getBaselineDistance()
            r2 = 6
            r10 = r48
            r9 = r50
            r8.addEquality(r10, r9, r0, r2)
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mBaseline
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mTarget
            if (r0 == 0) goto L_0x02e1
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mBaseline
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mTarget
            androidx.constraintlayout.solver.SolverVariable r0 = r8.createObjectVariable(r0)
            r3 = 0
            r8.addEquality(r10, r0, r3, r2)
            r23 = 0
            r11 = r23
            goto L_0x02e3
        L_0x02db:
            r8 = r53
            r10 = r48
            r9 = r50
        L_0x02e1:
            r11 = r23
        L_0x02e3:
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r7.mParent
            if (r0 == 0) goto L_0x02f0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mBottom
            androidx.constraintlayout.solver.SolverVariable r0 = r8.createObjectVariable(r0)
            r19 = r0
            goto L_0x02f2
        L_0x02f0:
            r19 = r24
        L_0x02f2:
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r7.mParent
            if (r0 == 0) goto L_0x02ff
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.mTop
            androidx.constraintlayout.solver.SolverVariable r0 = r8.createObjectVariable(r0)
            r18 = r0
            goto L_0x0301
        L_0x02ff:
            r18 = r24
        L_0x0301:
            androidx.constraintlayout.solver.widgets.ConstraintWidget$DimensionBehaviour[] r0 = r7.mListDimensionBehaviors
            r20 = r0[r1]
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mTop
            r22 = r0
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mBottom
            r23 = r0
            int r0 = r7.f23mY
            r24 = r0
            int r0 = r7.mMinHeight
            r26 = r0
            int[] r0 = r7.mMaxDimension
            r27 = r0[r1]
            float r0 = r7.mVerticalBiasPercent
            r28 = r0
            int r0 = r7.mMatchConstraintMinHeight
            r32 = r0
            int r0 = r7.mMatchConstraintMaxHeight
            r33 = r0
            float r0 = r7.mMatchConstraintPercentHeight
            r34 = r0
            r15 = r52
            r16 = r53
            r17 = r46
            r25 = r40
            r30 = r38
            r31 = r41
            r35 = r11
            r15.applyConstraints(r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30, r31, r32, r33, r34, r35)
            if (r43 == 0) goto L_0x0360
            r12 = 6
            int r0 = r7.mResolvedDimensionRatioSide
            if (r0 != r1) goto L_0x0351
            float r5 = r7.mResolvedDimensionRatio
            r0 = r53
            r1 = r49
            r2 = r9
            r3 = r51
            r4 = r36
            r6 = r12
            r0.addRatio(r1, r2, r3, r4, r5, r6)
            goto L_0x0360
        L_0x0351:
            float r5 = r7.mResolvedDimensionRatio
            r0 = r53
            r1 = r51
            r2 = r36
            r3 = r49
            r4 = r9
            r6 = r12
            r0.addRatio(r1, r2, r3, r4, r5, r6)
        L_0x0360:
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mCenter
            boolean r0 = r0.isConnected()
            if (r0 == 0) goto L_0x0386
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r7.mCenter
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r0 = r0.getTarget()
            androidx.constraintlayout.solver.widgets.ConstraintWidget r0 = r0.getOwner()
            float r1 = r7.mCircleConstraintAngle
            r2 = 1119092736(0x42b40000, float:90.0)
            float r1 = r1 + r2
            double r1 = (double) r1
            double r1 = java.lang.Math.toRadians(r1)
            float r1 = (float) r1
            androidx.constraintlayout.solver.widgets.ConstraintAnchor r2 = r7.mCenter
            int r2 = r2.getMargin()
            r8.addCenterPoint(r7, r0, r1, r2)
        L_0x0386:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.solver.widgets.ConstraintWidget.addToSolver(androidx.constraintlayout.solver.LinearSystem):void");
    }

    public void setupDimensionRatio(boolean hparentWrapContent, boolean vparentWrapContent, boolean horizontalDimensionFixed, boolean verticalDimensionFixed) {
        if (this.mResolvedDimensionRatioSide == -1) {
            if (horizontalDimensionFixed && !verticalDimensionFixed) {
                this.mResolvedDimensionRatioSide = 0;
            } else if (!horizontalDimensionFixed && verticalDimensionFixed) {
                this.mResolvedDimensionRatioSide = 1;
                if (this.mDimensionRatioSide == -1) {
                    this.mResolvedDimensionRatio = 1.0f / this.mResolvedDimensionRatio;
                }
            }
        }
        if (this.mResolvedDimensionRatioSide == 0 && (!this.mTop.isConnected() || !this.mBottom.isConnected())) {
            this.mResolvedDimensionRatioSide = 1;
        } else if (this.mResolvedDimensionRatioSide == 1 && (!this.mLeft.isConnected() || !this.mRight.isConnected())) {
            this.mResolvedDimensionRatioSide = 0;
        }
        if (this.mResolvedDimensionRatioSide == -1 && (!this.mTop.isConnected() || !this.mBottom.isConnected() || !this.mLeft.isConnected() || !this.mRight.isConnected())) {
            if (this.mTop.isConnected() && this.mBottom.isConnected()) {
                this.mResolvedDimensionRatioSide = 0;
            } else if (this.mLeft.isConnected() && this.mRight.isConnected()) {
                this.mResolvedDimensionRatio = 1.0f / this.mResolvedDimensionRatio;
                this.mResolvedDimensionRatioSide = 1;
            }
        }
        if (this.mResolvedDimensionRatioSide == -1) {
            if (hparentWrapContent && !vparentWrapContent) {
                this.mResolvedDimensionRatioSide = 0;
            } else if (!hparentWrapContent && vparentWrapContent) {
                this.mResolvedDimensionRatio = 1.0f / this.mResolvedDimensionRatio;
                this.mResolvedDimensionRatioSide = 1;
            }
        }
        if (this.mResolvedDimensionRatioSide == -1) {
            if (this.mMatchConstraintMinWidth > 0 && this.mMatchConstraintMinHeight == 0) {
                this.mResolvedDimensionRatioSide = 0;
            } else if (this.mMatchConstraintMinWidth == 0 && this.mMatchConstraintMinHeight > 0) {
                this.mResolvedDimensionRatio = 1.0f / this.mResolvedDimensionRatio;
                this.mResolvedDimensionRatioSide = 1;
            }
        }
        if (this.mResolvedDimensionRatioSide == -1 && hparentWrapContent && vparentWrapContent) {
            this.mResolvedDimensionRatio = 1.0f / this.mResolvedDimensionRatio;
            this.mResolvedDimensionRatioSide = 1;
        }
    }

    private void applyConstraints(LinearSystem system, boolean parentWrapContent, SolverVariable parentMin, SolverVariable parentMax, DimensionBehaviour dimensionBehaviour, boolean wrapContent, ConstraintAnchor beginAnchor, ConstraintAnchor endAnchor, int beginPosition, int dimension, int minDimension, int maxDimension, float bias, boolean useRatio, boolean inChain, int matchConstraintDefault, int matchMinDimension, int matchMaxDimension, float matchPercentDimension, boolean applyPosition) {
        int matchConstraintDefault2;
        boolean variableSize;
        boolean variableSize2;
        int dimension2;
        SolverVariable beginTarget;
        int matchConstraintDefault3;
        int matchMinDimension2;
        SolverVariable endTarget;
        int numConnections;
        int matchMaxDimension2;
        int matchMinDimension3;
        int i;
        SolverVariable begin;
        int i2;
        int matchConstraintDefault4;
        int centeringStrength;
        boolean applyCentering;
        boolean applyBoundsCheck;
        SolverVariable beginTarget2;
        int matchConstraintDefault5;
        SolverVariable end;
        SolverVariable begin2;
        int endStrength;
        int startStrength;
        boolean applyCentering2;
        boolean applyBoundsCheck2;
        int strength;
        int i3;
        int dimension3;
        SolverVariable percentEnd;
        SolverVariable percentEnd2;
        int i4;
        LinearSystem linearSystem = system;
        SolverVariable solverVariable = parentMin;
        SolverVariable solverVariable2 = parentMax;
        ConstraintAnchor constraintAnchor = endAnchor;
        int i5 = minDimension;
        int i6 = maxDimension;
        SolverVariable begin3 = linearSystem.createObjectVariable(beginAnchor);
        SolverVariable end2 = linearSystem.createObjectVariable(constraintAnchor);
        SolverVariable beginTarget3 = linearSystem.createObjectVariable(beginAnchor.getTarget());
        SolverVariable endTarget2 = linearSystem.createObjectVariable(endAnchor.getTarget());
        if (linearSystem.graphOptimizer && beginAnchor.getResolutionNode().state == 1 && endAnchor.getResolutionNode().state == 1) {
            if (LinearSystem.getMetrics() != null) {
                Metrics metrics = LinearSystem.getMetrics();
                metrics.resolvedWidgets++;
            }
            beginAnchor.getResolutionNode().addResolvedValue(linearSystem);
            endAnchor.getResolutionNode().addResolvedValue(linearSystem);
            if (!inChain && parentWrapContent) {
                linearSystem.addGreaterThan(solverVariable2, end2, 0, 6);
            }
            return;
        }
        if (LinearSystem.getMetrics() != null) {
            Metrics metrics2 = LinearSystem.getMetrics();
            metrics2.nonresolvedWidgets++;
        }
        boolean isBeginConnected = beginAnchor.isConnected();
        boolean isEndConnected = endAnchor.isConnected();
        boolean isCenterConnected = this.mCenter.isConnected();
        int numConnections2 = 0;
        if (isBeginConnected) {
            numConnections2 = 0 + 1;
        }
        if (isEndConnected) {
            numConnections2++;
        }
        if (isCenterConnected) {
            numConnections2++;
        }
        int numConnections3 = numConnections2;
        if (useRatio) {
            matchConstraintDefault2 = 3;
        } else {
            matchConstraintDefault2 = matchConstraintDefault;
        }
        int i7 = C01971.f25xdde91696[dimensionBehaviour.ordinal()];
        int numConnections4 = numConnections3;
        if (i7 == 1) {
            variableSize = false;
        } else if (i7 == 2) {
            variableSize = false;
        } else if (i7 == 3) {
            variableSize = false;
        } else if (i7 != 4) {
            variableSize = false;
        } else if (matchConstraintDefault2 == 4) {
            variableSize = false;
        } else {
            variableSize = true;
        }
        if (this.mVisibility == 8) {
            dimension2 = 0;
            variableSize2 = false;
        } else {
            dimension2 = dimension;
            variableSize2 = variableSize;
        }
        if (applyPosition) {
            if (isBeginConnected || isEndConnected || isCenterConnected) {
                int i8 = beginPosition;
                if (isBeginConnected && !isEndConnected) {
                    linearSystem.addEquality(begin3, beginTarget3, beginAnchor.getMargin(), 6);
                }
            } else {
                linearSystem.addEquality(begin3, beginPosition);
            }
        }
        if (!variableSize2) {
            if (wrapContent) {
                linearSystem.addEquality(end2, begin3, 0, 3);
                if (i5 > 0) {
                    i4 = 6;
                    linearSystem.addGreaterThan(end2, begin3, i5, 6);
                } else {
                    i4 = 6;
                }
                if (i6 < Integer.MAX_VALUE) {
                    linearSystem.addLowerThan(end2, begin3, i6, i4);
                }
            } else {
                linearSystem.addEquality(end2, begin3, dimension2, 6);
            }
            matchMinDimension2 = matchMinDimension;
            matchMaxDimension2 = matchMaxDimension;
            int i9 = dimension2;
            matchConstraintDefault3 = matchConstraintDefault2;
            endTarget = endTarget2;
            beginTarget = beginTarget3;
            numConnections = numConnections4;
        } else {
            int matchMinDimension4 = matchMinDimension;
            if (matchMinDimension4 == -2) {
                matchMinDimension4 = dimension2;
            }
            SolverVariable endTarget3 = endTarget2;
            int matchMaxDimension3 = matchMaxDimension;
            if (matchMaxDimension3 == -2) {
                matchMaxDimension3 = dimension2;
            }
            if (matchMinDimension4 > 0) {
                i3 = 6;
                linearSystem.addGreaterThan(end2, begin3, matchMinDimension4, 6);
                dimension2 = Math.max(dimension2, matchMinDimension4);
            } else {
                i3 = 6;
            }
            if (matchMaxDimension3 > 0) {
                linearSystem.addLowerThan(end2, begin3, matchMaxDimension3, i3);
                dimension2 = Math.min(dimension2, matchMaxDimension3);
            }
            if (matchConstraintDefault2 == 1) {
                if (parentWrapContent) {
                    linearSystem.addEquality(end2, begin3, dimension2, 6);
                    dimension3 = dimension2;
                    matchConstraintDefault3 = matchConstraintDefault2;
                    matchMinDimension2 = matchMinDimension4;
                    matchMaxDimension2 = matchMaxDimension3;
                    beginTarget = beginTarget3;
                    numConnections = numConnections4;
                    endTarget = endTarget3;
                } else if (inChain) {
                    linearSystem.addEquality(end2, begin3, dimension2, 4);
                    dimension3 = dimension2;
                    matchConstraintDefault3 = matchConstraintDefault2;
                    matchMinDimension2 = matchMinDimension4;
                    matchMaxDimension2 = matchMaxDimension3;
                    beginTarget = beginTarget3;
                    numConnections = numConnections4;
                    endTarget = endTarget3;
                } else {
                    linearSystem.addEquality(end2, begin3, dimension2, 1);
                    dimension3 = dimension2;
                    matchConstraintDefault3 = matchConstraintDefault2;
                    matchMinDimension2 = matchMinDimension4;
                    matchMaxDimension2 = matchMaxDimension3;
                    beginTarget = beginTarget3;
                    numConnections = numConnections4;
                    endTarget = endTarget3;
                }
            } else if (matchConstraintDefault2 == 2) {
                int dimension4 = dimension2;
                if (beginAnchor.getType() == Type.TOP || beginAnchor.getType() == Type.BOTTOM) {
                    percentEnd = linearSystem.createObjectVariable(this.mParent.getAnchor(Type.TOP));
                    percentEnd2 = linearSystem.createObjectVariable(this.mParent.getAnchor(Type.BOTTOM));
                } else {
                    percentEnd = linearSystem.createObjectVariable(this.mParent.getAnchor(Type.LEFT));
                    percentEnd2 = linearSystem.createObjectVariable(this.mParent.getAnchor(Type.RIGHT));
                }
                matchConstraintDefault3 = matchConstraintDefault2;
                dimension3 = dimension4;
                numConnections = numConnections4;
                matchMinDimension2 = matchMinDimension4;
                matchMaxDimension2 = matchMaxDimension3;
                endTarget = endTarget3;
                beginTarget = beginTarget3;
                linearSystem.addConstraint(system.createRow().createRowDimensionRatio(end2, begin3, percentEnd2, percentEnd, matchPercentDimension));
                variableSize2 = false;
            } else {
                dimension3 = dimension2;
                matchConstraintDefault3 = matchConstraintDefault2;
                matchMinDimension2 = matchMinDimension4;
                matchMaxDimension2 = matchMaxDimension3;
                beginTarget = beginTarget3;
                numConnections = numConnections4;
                endTarget = endTarget3;
            }
            if (!variableSize2 || numConnections == 2 || useRatio) {
                int i10 = dimension3;
            } else {
                variableSize2 = false;
                int dimension5 = dimension3;
                int d = Math.max(matchMinDimension2, dimension5);
                if (matchMaxDimension2 > 0) {
                    d = Math.min(matchMaxDimension2, d);
                }
                linearSystem.addEquality(end2, begin3, d, 6);
                int i11 = dimension5;
            }
        }
        if (!applyPosition) {
            ConstraintAnchor constraintAnchor2 = beginAnchor;
            ConstraintAnchor constraintAnchor3 = endAnchor;
            int i12 = matchMaxDimension2;
            begin = begin3;
            int i13 = matchMinDimension2;
            SolverVariable solverVariable3 = beginTarget;
            i = 6;
            matchMinDimension3 = numConnections;
            int i14 = matchConstraintDefault3;
        } else if (inChain) {
            ConstraintAnchor constraintAnchor4 = beginAnchor;
            ConstraintAnchor constraintAnchor5 = endAnchor;
            int i15 = matchMaxDimension2;
            begin = begin3;
            int i16 = matchMinDimension2;
            SolverVariable solverVariable4 = beginTarget;
            i = 6;
            matchMinDimension3 = numConnections;
            int i17 = matchConstraintDefault3;
        } else {
            if (isBeginConnected || isEndConnected || isCenterConnected) {
                i2 = 0;
                if (!isBeginConnected || isEndConnected) {
                    if (!isBeginConnected && isEndConnected) {
                        linearSystem.addEquality(end2, endTarget, -endAnchor.getMargin(), 6);
                        if (parentWrapContent) {
                            linearSystem.addGreaterThan(begin3, solverVariable, 0, 5);
                            ConstraintAnchor constraintAnchor6 = beginAnchor;
                            ConstraintAnchor constraintAnchor7 = endAnchor;
                            int i18 = matchMaxDimension2;
                            SolverVariable solverVariable5 = begin3;
                            int i19 = matchMinDimension2;
                            SolverVariable solverVariable6 = beginTarget;
                            matchConstraintDefault4 = 6;
                            int matchMinDimension5 = numConnections;
                            int i20 = matchConstraintDefault3;
                        } else {
                            ConstraintAnchor constraintAnchor8 = beginAnchor;
                            ConstraintAnchor constraintAnchor9 = endAnchor;
                            int i21 = matchMaxDimension2;
                            SolverVariable solverVariable7 = begin3;
                            int i22 = matchMinDimension2;
                            SolverVariable solverVariable8 = beginTarget;
                            matchConstraintDefault4 = 6;
                            int matchMinDimension6 = numConnections;
                            int i23 = matchConstraintDefault3;
                        }
                    } else if (!isBeginConnected || !isEndConnected) {
                        ConstraintAnchor constraintAnchor10 = beginAnchor;
                        ConstraintAnchor constraintAnchor11 = endAnchor;
                        int i24 = matchMaxDimension2;
                        SolverVariable solverVariable9 = begin3;
                        int i25 = matchMinDimension2;
                        SolverVariable solverVariable10 = beginTarget;
                        matchConstraintDefault4 = 6;
                        int matchMinDimension7 = numConnections;
                        int i26 = matchConstraintDefault3;
                    } else {
                        boolean applyBoundsCheck3 = false;
                        boolean applyCentering3 = false;
                        if (variableSize2) {
                            if (parentWrapContent && i5 == 0) {
                                linearSystem.addGreaterThan(end2, begin3, 0, 6);
                            }
                            matchConstraintDefault5 = matchConstraintDefault3;
                            if (matchConstraintDefault5 == 0) {
                                if (matchMaxDimension2 > 0 || matchMinDimension2 > 0) {
                                    applyBoundsCheck3 = true;
                                    strength = 4;
                                } else {
                                    strength = 6;
                                }
                                beginTarget2 = beginTarget;
                                linearSystem.addEquality(begin3, beginTarget2, beginAnchor.getMargin(), strength);
                                linearSystem.addEquality(end2, endTarget, -endAnchor.getMargin(), strength);
                                if (matchMaxDimension2 > 0 || matchMinDimension2 > 0) {
                                    applyCentering3 = true;
                                }
                                applyBoundsCheck = applyBoundsCheck3;
                                applyCentering = applyCentering3;
                                centeringStrength = 5;
                            } else {
                                beginTarget2 = beginTarget;
                                if (matchConstraintDefault5 == 1) {
                                    applyBoundsCheck = true;
                                    applyCentering = true;
                                    centeringStrength = 6;
                                } else if (matchConstraintDefault5 == 3) {
                                    int strength2 = 4;
                                    if (!useRatio) {
                                        applyBoundsCheck2 = true;
                                        applyCentering2 = true;
                                        if (this.mResolvedDimensionRatioSide != -1 && matchMaxDimension2 <= 0) {
                                            strength2 = 6;
                                        }
                                    } else {
                                        applyBoundsCheck2 = true;
                                        applyCentering2 = true;
                                    }
                                    linearSystem.addEquality(begin3, beginTarget2, beginAnchor.getMargin(), strength2);
                                    linearSystem.addEquality(end2, endTarget, -endAnchor.getMargin(), strength2);
                                    applyBoundsCheck = applyBoundsCheck2;
                                    applyCentering = applyCentering2;
                                    centeringStrength = 5;
                                } else {
                                    applyBoundsCheck = false;
                                    applyCentering = false;
                                    centeringStrength = 5;
                                }
                            }
                        } else {
                            matchConstraintDefault5 = matchConstraintDefault3;
                            beginTarget2 = beginTarget;
                            applyBoundsCheck = false;
                            applyCentering = true;
                            centeringStrength = 5;
                        }
                        int startStrength2 = 5;
                        int endStrength2 = 5;
                        boolean applyStartConstraint = parentWrapContent;
                        boolean applyEndConstraint = parentWrapContent;
                        if (applyCentering) {
                            int i27 = matchConstraintDefault5;
                            int i28 = matchMaxDimension2;
                            end = end2;
                            begin2 = begin3;
                            int i29 = matchMinDimension2;
                            int matchMinDimension8 = numConnections;
                            system.addCentering(begin3, beginTarget2, beginAnchor.getMargin(), bias, endTarget, end2, endAnchor.getMargin(), centeringStrength);
                            boolean isBeginAnchorBarrier = beginAnchor.mTarget.mOwner instanceof Barrier;
                            matchConstraintDefault4 = 6;
                            boolean isEndAnchorBarrier = endAnchor.mTarget.mOwner instanceof Barrier;
                            if (isBeginAnchorBarrier && !isEndAnchorBarrier) {
                                endStrength2 = 6;
                                applyEndConstraint = true;
                            } else if (!isBeginAnchorBarrier && isEndAnchorBarrier) {
                                startStrength2 = 6;
                                applyStartConstraint = true;
                            }
                        } else {
                            ConstraintAnchor constraintAnchor12 = beginAnchor;
                            ConstraintAnchor constraintAnchor13 = endAnchor;
                            int i30 = matchMaxDimension2;
                            int i31 = matchConstraintDefault5;
                            end = end2;
                            begin2 = begin3;
                            int i32 = matchMinDimension2;
                            matchConstraintDefault4 = 6;
                            int matchMinDimension9 = numConnections;
                        }
                        if (applyBoundsCheck) {
                            startStrength = 6;
                            endStrength = 6;
                        } else {
                            startStrength = startStrength2;
                            endStrength = endStrength2;
                        }
                        if ((!variableSize2 && applyStartConstraint) || applyBoundsCheck) {
                            linearSystem.addGreaterThan(begin2, beginTarget2, beginAnchor.getMargin(), startStrength);
                        }
                        if ((variableSize2 || !applyEndConstraint) && !applyBoundsCheck) {
                            end2 = end;
                        } else {
                            end2 = end;
                            linearSystem.addLowerThan(end2, endTarget, -endAnchor.getMargin(), endStrength);
                        }
                        if (parentWrapContent) {
                            i2 = 0;
                            linearSystem.addGreaterThan(begin2, solverVariable, 0, matchConstraintDefault4);
                        } else {
                            i2 = 0;
                        }
                    }
                } else if (parentWrapContent) {
                    linearSystem.addGreaterThan(solverVariable2, end2, 0, 5);
                    ConstraintAnchor constraintAnchor14 = beginAnchor;
                    ConstraintAnchor constraintAnchor15 = endAnchor;
                    int i33 = matchMaxDimension2;
                    SolverVariable solverVariable11 = begin3;
                    int i34 = matchMinDimension2;
                    SolverVariable solverVariable12 = beginTarget;
                    matchConstraintDefault4 = 6;
                    int matchMinDimension10 = numConnections;
                    int i35 = matchConstraintDefault3;
                } else {
                    ConstraintAnchor constraintAnchor16 = beginAnchor;
                    ConstraintAnchor constraintAnchor17 = endAnchor;
                    int i36 = matchMaxDimension2;
                    SolverVariable solverVariable13 = begin3;
                    int i37 = matchMinDimension2;
                    SolverVariable solverVariable14 = beginTarget;
                    matchConstraintDefault4 = 6;
                    int matchMinDimension11 = numConnections;
                    int i38 = matchConstraintDefault3;
                }
            } else if (parentWrapContent) {
                i2 = 0;
                linearSystem.addGreaterThan(solverVariable2, end2, 0, 5);
                ConstraintAnchor constraintAnchor18 = beginAnchor;
                ConstraintAnchor constraintAnchor19 = endAnchor;
                int i39 = matchMaxDimension2;
                SolverVariable solverVariable15 = begin3;
                int i40 = matchMinDimension2;
                SolverVariable solverVariable16 = beginTarget;
                matchConstraintDefault4 = 6;
                int matchMinDimension12 = numConnections;
                int i41 = matchConstraintDefault3;
            } else {
                i2 = 0;
                ConstraintAnchor constraintAnchor20 = beginAnchor;
                ConstraintAnchor constraintAnchor21 = endAnchor;
                int i42 = matchMaxDimension2;
                SolverVariable solverVariable17 = begin3;
                int i43 = matchMinDimension2;
                SolverVariable solverVariable18 = beginTarget;
                matchConstraintDefault4 = 6;
                int matchMinDimension13 = numConnections;
                int i44 = matchConstraintDefault3;
            }
            if (parentWrapContent) {
                linearSystem.addGreaterThan(solverVariable2, end2, i2, matchConstraintDefault4);
            }
            return;
        }
        if (matchMinDimension3 < 2 && parentWrapContent) {
            linearSystem.addGreaterThan(begin, solverVariable, 0, i);
            linearSystem.addGreaterThan(solverVariable2, end2, 0, i);
        }
    }

    public void updateFromSolver(LinearSystem system) {
        int left = system.getObjectVariableValue(this.mLeft);
        int top = system.getObjectVariableValue(this.mTop);
        int right = system.getObjectVariableValue(this.mRight);
        int bottom = system.getObjectVariableValue(this.mBottom);
        int h = bottom - top;
        if (right - left < 0 || h < 0 || left == Integer.MIN_VALUE || left == Integer.MAX_VALUE || top == Integer.MIN_VALUE || top == Integer.MAX_VALUE || right == Integer.MIN_VALUE || right == Integer.MAX_VALUE || bottom == Integer.MIN_VALUE || bottom == Integer.MAX_VALUE) {
            left = 0;
            top = 0;
            right = 0;
            bottom = 0;
        }
        setFrame(left, top, right, bottom);
    }
}
