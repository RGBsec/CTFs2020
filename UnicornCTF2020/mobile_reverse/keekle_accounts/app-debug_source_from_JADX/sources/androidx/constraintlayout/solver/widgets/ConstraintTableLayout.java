package androidx.constraintlayout.solver.widgets;

import androidx.constraintlayout.solver.LinearSystem;
import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Strength;
import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type;
import androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour;
import java.util.ArrayList;

public class ConstraintTableLayout extends ConstraintWidgetContainer {
    public static final int ALIGN_CENTER = 0;
    private static final int ALIGN_FULL = 3;
    public static final int ALIGN_LEFT = 1;
    public static final int ALIGN_RIGHT = 2;
    private ArrayList<Guideline> mHorizontalGuidelines = new ArrayList<>();
    private ArrayList<HorizontalSlice> mHorizontalSlices = new ArrayList<>();
    private int mNumCols = 0;
    private int mNumRows = 0;
    private int mPadding = 8;
    private boolean mVerticalGrowth = true;
    private ArrayList<Guideline> mVerticalGuidelines = new ArrayList<>();
    private ArrayList<VerticalSlice> mVerticalSlices = new ArrayList<>();
    private LinearSystem system = null;

    class HorizontalSlice {
        ConstraintWidget bottom;
        int padding;
        ConstraintWidget top;

        HorizontalSlice() {
        }
    }

    class VerticalSlice {
        int alignment = 1;
        ConstraintWidget left;
        int padding;
        ConstraintWidget right;

        VerticalSlice() {
        }
    }

    public ConstraintTableLayout() {
    }

    public ConstraintTableLayout(int x, int y, int width, int height) {
        super(x, y, width, height);
    }

    public ConstraintTableLayout(int width, int height) {
        super(width, height);
    }

    public String getType() {
        return "ConstraintTableLayout";
    }

    public int getNumRows() {
        return this.mNumRows;
    }

    public int getNumCols() {
        return this.mNumCols;
    }

    public int getPadding() {
        return this.mPadding;
    }

    public String getColumnsAlignmentRepresentation() {
        int numSlices = this.mVerticalSlices.size();
        String result = "";
        for (int i = 0; i < numSlices; i++) {
            VerticalSlice slice = (VerticalSlice) this.mVerticalSlices.get(i);
            if (slice.alignment == 1) {
                StringBuilder sb = new StringBuilder();
                sb.append(result);
                sb.append("L");
                result = sb.toString();
            } else if (slice.alignment == 0) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append(result);
                sb2.append("C");
                result = sb2.toString();
            } else if (slice.alignment == 3) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append(result);
                sb3.append("F");
                result = sb3.toString();
            } else if (slice.alignment == 2) {
                StringBuilder sb4 = new StringBuilder();
                sb4.append(result);
                sb4.append("R");
                result = sb4.toString();
            }
        }
        return result;
    }

    public String getColumnAlignmentRepresentation(int column) {
        VerticalSlice slice = (VerticalSlice) this.mVerticalSlices.get(column);
        if (slice.alignment == 1) {
            return "L";
        }
        if (slice.alignment == 0) {
            return "C";
        }
        if (slice.alignment == 3) {
            return "F";
        }
        if (slice.alignment == 2) {
            return "R";
        }
        return "!";
    }

    public void setNumCols(int num) {
        if (this.mVerticalGrowth && this.mNumCols != num) {
            this.mNumCols = num;
            setVerticalSlices();
            setTableDimensions();
        }
    }

    public void setNumRows(int num) {
        if (!this.mVerticalGrowth && this.mNumCols != num) {
            this.mNumRows = num;
            setHorizontalSlices();
            setTableDimensions();
        }
    }

    public boolean isVerticalGrowth() {
        return this.mVerticalGrowth;
    }

    public void setVerticalGrowth(boolean value) {
        this.mVerticalGrowth = value;
    }

    public void setPadding(int padding) {
        if (padding > 1) {
            this.mPadding = padding;
        }
    }

    public void setColumnAlignment(int column, int alignment) {
        if (column < this.mVerticalSlices.size()) {
            ((VerticalSlice) this.mVerticalSlices.get(column)).alignment = alignment;
            setChildrenConnections();
        }
    }

    public void cycleColumnAlignment(int column) {
        VerticalSlice slice = (VerticalSlice) this.mVerticalSlices.get(column);
        int i = slice.alignment;
        if (i == 0) {
            slice.alignment = 2;
        } else if (i == 1) {
            slice.alignment = 0;
        } else if (i == 2) {
            slice.alignment = 1;
        }
        setChildrenConnections();
    }

    public void setColumnAlignment(String alignment) {
        int n = alignment.length();
        for (int i = 0; i < n; i++) {
            char c = alignment.charAt(i);
            if (c == 'L') {
                setColumnAlignment(i, 1);
            } else if (c == 'C') {
                setColumnAlignment(i, 0);
            } else if (c == 'F') {
                setColumnAlignment(i, 3);
            } else if (c == 'R') {
                setColumnAlignment(i, 2);
            } else {
                setColumnAlignment(i, 0);
            }
        }
    }

    public ArrayList<Guideline> getVerticalGuidelines() {
        return this.mVerticalGuidelines;
    }

    public ArrayList<Guideline> getHorizontalGuidelines() {
        return this.mHorizontalGuidelines;
    }

    public void addToSolver(LinearSystem system2) {
        super.addToSolver(system2);
        int count = this.mChildren.size();
        if (count != 0) {
            setTableDimensions();
            if (system2 == this.mSystem) {
                int num = this.mVerticalGuidelines.size();
                int i = 0;
                while (true) {
                    boolean z = false;
                    if (i >= num) {
                        break;
                    }
                    Guideline guideline = (Guideline) this.mVerticalGuidelines.get(i);
                    if (getHorizontalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT) {
                        z = true;
                    }
                    guideline.setPositionRelaxed(z);
                    guideline.addToSolver(system2);
                    i++;
                }
                int num2 = this.mHorizontalGuidelines.size();
                for (int i2 = 0; i2 < num2; i2++) {
                    Guideline guideline2 = (Guideline) this.mHorizontalGuidelines.get(i2);
                    guideline2.setPositionRelaxed(getVerticalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT);
                    guideline2.addToSolver(system2);
                }
                for (int i3 = 0; i3 < count; i3++) {
                    ((ConstraintWidget) this.mChildren.get(i3)).addToSolver(system2);
                }
            }
        }
    }

    public void setTableDimensions() {
        int extra = 0;
        int count = this.mChildren.size();
        for (int i = 0; i < count; i++) {
            extra += ((ConstraintWidget) this.mChildren.get(i)).getContainerItemSkip();
        }
        int count2 = count + extra;
        if (this.mVerticalGrowth) {
            if (this.mNumCols == 0) {
                setNumCols(1);
            }
            int i2 = this.mNumCols;
            int rows = count2 / i2;
            if (i2 * rows < count2) {
                rows++;
            }
            if (this.mNumRows != rows || this.mVerticalGuidelines.size() != this.mNumCols - 1) {
                this.mNumRows = rows;
                setHorizontalSlices();
            } else {
                return;
            }
        } else {
            if (this.mNumRows == 0) {
                setNumRows(1);
            }
            int i3 = this.mNumRows;
            int cols = count2 / i3;
            if (i3 * cols < count2) {
                cols++;
            }
            if (this.mNumCols != cols || this.mHorizontalGuidelines.size() != this.mNumRows - 1) {
                this.mNumCols = cols;
                setVerticalSlices();
            } else {
                return;
            }
        }
        setChildrenConnections();
    }

    public void setDebugSolverName(LinearSystem s, String name) {
        this.system = s;
        super.setDebugSolverName(s, name);
        updateDebugSolverNames();
    }

    private void updateDebugSolverNames() {
        if (this.system != null) {
            int num = this.mVerticalGuidelines.size();
            for (int i = 0; i < num; i++) {
                Guideline guideline = (Guideline) this.mVerticalGuidelines.get(i);
                LinearSystem linearSystem = this.system;
                StringBuilder sb = new StringBuilder();
                sb.append(getDebugName());
                sb.append(".VG");
                sb.append(i);
                guideline.setDebugSolverName(linearSystem, sb.toString());
            }
            int num2 = this.mHorizontalGuidelines.size();
            for (int i2 = 0; i2 < num2; i2++) {
                Guideline guideline2 = (Guideline) this.mHorizontalGuidelines.get(i2);
                LinearSystem linearSystem2 = this.system;
                StringBuilder sb2 = new StringBuilder();
                sb2.append(getDebugName());
                sb2.append(".HG");
                sb2.append(i2);
                guideline2.setDebugSolverName(linearSystem2, sb2.toString());
            }
        }
    }

    private void setVerticalSlices() {
        this.mVerticalSlices.clear();
        ConstraintWidget previous = this;
        float increment = 100.0f / ((float) this.mNumCols);
        float percent = increment;
        int i = 0;
        while (i < this.mNumCols) {
            VerticalSlice slice = new VerticalSlice();
            slice.left = previous;
            if (i < this.mNumCols - 1) {
                Guideline guideline = new Guideline();
                guideline.setOrientation(1);
                guideline.setParent(this);
                guideline.setGuidePercent((int) percent);
                percent += increment;
                slice.right = guideline;
                this.mVerticalGuidelines.add(guideline);
            } else {
                slice.right = this;
            }
            ConstraintWidget previous2 = slice.right;
            this.mVerticalSlices.add(slice);
            i++;
            previous = previous2;
        }
        updateDebugSolverNames();
    }

    private void setHorizontalSlices() {
        this.mHorizontalSlices.clear();
        float increment = 100.0f / ((float) this.mNumRows);
        float percent = increment;
        ConstraintWidget previous = this;
        int i = 0;
        while (i < this.mNumRows) {
            HorizontalSlice slice = new HorizontalSlice();
            slice.top = previous;
            if (i < this.mNumRows - 1) {
                Guideline guideline = new Guideline();
                guideline.setOrientation(0);
                guideline.setParent(this);
                guideline.setGuidePercent((int) percent);
                percent += increment;
                slice.bottom = guideline;
                this.mHorizontalGuidelines.add(guideline);
            } else {
                slice.bottom = this;
            }
            ConstraintWidget previous2 = slice.bottom;
            this.mHorizontalSlices.add(slice);
            i++;
            previous = previous2;
        }
        updateDebugSolverNames();
    }

    private void setChildrenConnections() {
        int count = this.mChildren.size();
        int index = 0;
        for (int i = 0; i < count; i++) {
            ConstraintWidget target = (ConstraintWidget) this.mChildren.get(i);
            int index2 = index + target.getContainerItemSkip();
            int i2 = this.mNumCols;
            int col = index2 % i2;
            HorizontalSlice horizontalSlice = (HorizontalSlice) this.mHorizontalSlices.get(index2 / i2);
            VerticalSlice verticalSlice = (VerticalSlice) this.mVerticalSlices.get(col);
            ConstraintWidget targetLeft = verticalSlice.left;
            ConstraintWidget targetRight = verticalSlice.right;
            ConstraintWidget targetTop = horizontalSlice.top;
            ConstraintWidget targetBottom = horizontalSlice.bottom;
            target.getAnchor(Type.LEFT).connect(targetLeft.getAnchor(Type.LEFT), this.mPadding);
            if (targetRight instanceof Guideline) {
                target.getAnchor(Type.RIGHT).connect(targetRight.getAnchor(Type.LEFT), this.mPadding);
            } else {
                target.getAnchor(Type.RIGHT).connect(targetRight.getAnchor(Type.RIGHT), this.mPadding);
            }
            int i3 = verticalSlice.alignment;
            if (i3 == 1) {
                target.getAnchor(Type.LEFT).setStrength(Strength.STRONG);
                target.getAnchor(Type.RIGHT).setStrength(Strength.WEAK);
            } else if (i3 == 2) {
                target.getAnchor(Type.LEFT).setStrength(Strength.WEAK);
                target.getAnchor(Type.RIGHT).setStrength(Strength.STRONG);
            } else if (i3 == 3) {
                target.setHorizontalDimensionBehaviour(DimensionBehaviour.MATCH_CONSTRAINT);
            }
            target.getAnchor(Type.TOP).connect(targetTop.getAnchor(Type.TOP), this.mPadding);
            if (targetBottom instanceof Guideline) {
                target.getAnchor(Type.BOTTOM).connect(targetBottom.getAnchor(Type.TOP), this.mPadding);
            } else {
                target.getAnchor(Type.BOTTOM).connect(targetBottom.getAnchor(Type.BOTTOM), this.mPadding);
            }
            index = index2 + 1;
        }
    }

    public void updateFromSolver(LinearSystem system2) {
        super.updateFromSolver(system2);
        if (system2 == this.mSystem) {
            int num = this.mVerticalGuidelines.size();
            for (int i = 0; i < num; i++) {
                ((Guideline) this.mVerticalGuidelines.get(i)).updateFromSolver(system2);
            }
            int num2 = this.mHorizontalGuidelines.size();
            for (int i2 = 0; i2 < num2; i2++) {
                ((Guideline) this.mHorizontalGuidelines.get(i2)).updateFromSolver(system2);
            }
        }
    }

    public boolean handlesInternalConstraints() {
        return true;
    }

    public void computeGuidelinesPercentPositions() {
        int num = this.mVerticalGuidelines.size();
        for (int i = 0; i < num; i++) {
            ((Guideline) this.mVerticalGuidelines.get(i)).inferRelativePercentPosition();
        }
        int num2 = this.mHorizontalGuidelines.size();
        for (int i2 = 0; i2 < num2; i2++) {
            ((Guideline) this.mHorizontalGuidelines.get(i2)).inferRelativePercentPosition();
        }
    }
}
