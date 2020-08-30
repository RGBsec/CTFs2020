package androidx.constraintlayout.solver.widgets;

import androidx.constraintlayout.solver.widgets.ConstraintAnchor.Type;
import androidx.constraintlayout.solver.widgets.ConstraintWidget.DimensionBehaviour;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class Analyzer {
    private Analyzer() {
    }

    public static void determineGroups(ConstraintWidgetContainer layoutWidget) {
        if ((layoutWidget.getOptimizationLevel() & 32) != 32) {
            singleGroup(layoutWidget);
            return;
        }
        layoutWidget.mSkipSolver = true;
        layoutWidget.mGroupsWrapOptimized = false;
        layoutWidget.mHorizontalWrapOptimized = false;
        layoutWidget.mVerticalWrapOptimized = false;
        List<ConstraintWidget> widgets = layoutWidget.mChildren;
        List<ConstraintWidgetGroup> widgetGroups = layoutWidget.mWidgetGroups;
        boolean horizontalWrapContent = layoutWidget.getHorizontalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT;
        boolean verticalWrapContent = layoutWidget.getVerticalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT;
        boolean hasWrapContent = horizontalWrapContent || verticalWrapContent;
        widgetGroups.clear();
        for (ConstraintWidget widget : widgets) {
            widget.mBelongingGroup = null;
            widget.mGroupsToSolver = false;
            widget.resetResolutionNodes();
        }
        for (ConstraintWidget widget2 : widgets) {
            if (widget2.mBelongingGroup == null && !determineGroups(widget2, widgetGroups, hasWrapContent)) {
                singleGroup(layoutWidget);
                layoutWidget.mSkipSolver = false;
                return;
            }
        }
        int measuredWidth = 0;
        int measuredHeight = 0;
        for (ConstraintWidgetGroup group : widgetGroups) {
            measuredWidth = Math.max(measuredWidth, getMaxDimension(group, 0));
            measuredHeight = Math.max(measuredHeight, getMaxDimension(group, 1));
        }
        if (horizontalWrapContent) {
            layoutWidget.setHorizontalDimensionBehaviour(DimensionBehaviour.FIXED);
            layoutWidget.setWidth(measuredWidth);
            layoutWidget.mGroupsWrapOptimized = true;
            layoutWidget.mHorizontalWrapOptimized = true;
            layoutWidget.mWrapFixedWidth = measuredWidth;
        }
        if (verticalWrapContent) {
            layoutWidget.setVerticalDimensionBehaviour(DimensionBehaviour.FIXED);
            layoutWidget.setHeight(measuredHeight);
            layoutWidget.mGroupsWrapOptimized = true;
            layoutWidget.mVerticalWrapOptimized = true;
            layoutWidget.mWrapFixedHeight = measuredHeight;
        }
        setPosition(widgetGroups, 0, layoutWidget.getWidth());
        setPosition(widgetGroups, 1, layoutWidget.getHeight());
    }

    private static boolean determineGroups(ConstraintWidget widget, List<ConstraintWidgetGroup> widgetGroups, boolean hasWrapContent) {
        ConstraintWidgetGroup traverseList = new ConstraintWidgetGroup(new ArrayList(), true);
        widgetGroups.add(traverseList);
        return traverse(widget, traverseList, widgetGroups, hasWrapContent);
    }

    private static boolean traverse(ConstraintWidget widget, ConstraintWidgetGroup upperGroup, List<ConstraintWidgetGroup> widgetGroups, boolean hasWrapContent) {
        if (widget == null) {
            return true;
        }
        widget.mOptimizerMeasured = false;
        ConstraintWidgetContainer layoutWidget = (ConstraintWidgetContainer) widget.getParent();
        if (widget.mBelongingGroup == null) {
            widget.mOptimizerMeasurable = true;
            upperGroup.mConstrainedGroup.add(widget);
            widget.mBelongingGroup = upperGroup;
            if (widget.mLeft.mTarget == null && widget.mRight.mTarget == null && widget.mTop.mTarget == null && widget.mBottom.mTarget == null && widget.mBaseline.mTarget == null && widget.mCenter.mTarget == null) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
            }
            if (!(widget.mTop.mTarget == null || widget.mBottom.mTarget == null)) {
                if (layoutWidget.getVerticalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT) {
                }
                if (hasWrapContent) {
                    invalidate(layoutWidget, widget, upperGroup);
                    return false;
                } else if (!(widget.mTop.mTarget.mOwner == widget.getParent() && widget.mBottom.mTarget.mOwner == widget.getParent())) {
                    invalidate(layoutWidget, widget, upperGroup);
                }
            }
            if (!(widget.mLeft.mTarget == null || widget.mRight.mTarget == null)) {
                if (layoutWidget.getHorizontalDimensionBehaviour() == DimensionBehaviour.WRAP_CONTENT) {
                }
                if (hasWrapContent) {
                    invalidate(layoutWidget, widget, upperGroup);
                    return false;
                } else if (!(widget.mLeft.mTarget.mOwner == widget.getParent() && widget.mRight.mTarget.mOwner == widget.getParent())) {
                    invalidate(layoutWidget, widget, upperGroup);
                }
            }
            if (((widget.getHorizontalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) ^ (widget.getVerticalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT)) && widget.mDimensionRatio != 0.0f) {
                resolveDimensionRatio(widget);
            } else if (widget.getHorizontalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT || widget.getVerticalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
            }
            if (((widget.mLeft.mTarget == null && widget.mRight.mTarget == null) || ((widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner == widget.mParent && widget.mRight.mTarget == null) || ((widget.mRight.mTarget != null && widget.mRight.mTarget.mOwner == widget.mParent && widget.mLeft.mTarget == null) || (widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner == widget.mParent && widget.mRight.mTarget != null && widget.mRight.mTarget.mOwner == widget.mParent)))) && widget.mCenter.mTarget == null && !(widget instanceof Guideline) && !(widget instanceof Helper)) {
                upperGroup.mStartHorizontalWidgets.add(widget);
            }
            if (((widget.mTop.mTarget == null && widget.mBottom.mTarget == null) || ((widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner == widget.mParent && widget.mBottom.mTarget == null) || ((widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner == widget.mParent && widget.mTop.mTarget == null) || (widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner == widget.mParent && widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner == widget.mParent)))) && widget.mCenter.mTarget == null && widget.mBaseline.mTarget == null && !(widget instanceof Guideline) && !(widget instanceof Helper)) {
                upperGroup.mStartVerticalWidgets.add(widget);
            }
            if (widget instanceof Helper) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
                Helper hWidget = (Helper) widget;
                for (int widgetsCount = 0; widgetsCount < hWidget.mWidgetsCount; widgetsCount++) {
                    if (!traverse(hWidget.mWidgets[widgetsCount], upperGroup, widgetGroups, hasWrapContent)) {
                        return false;
                    }
                }
            }
            for (ConstraintAnchor anchor : widget.mListAnchors) {
                if (!(anchor.mTarget == null || anchor.mTarget.mOwner == widget.getParent())) {
                    if (anchor.mType == Type.CENTER) {
                        invalidate(layoutWidget, widget, upperGroup);
                        if (hasWrapContent) {
                            return false;
                        }
                    } else {
                        setConnection(anchor);
                    }
                    if (!traverse(anchor.mTarget.mOwner, upperGroup, widgetGroups, hasWrapContent)) {
                        return false;
                    }
                }
            }
            return true;
        }
        if (widget.mBelongingGroup != upperGroup) {
            upperGroup.mConstrainedGroup.addAll(widget.mBelongingGroup.mConstrainedGroup);
            upperGroup.mStartHorizontalWidgets.addAll(widget.mBelongingGroup.mStartHorizontalWidgets);
            upperGroup.mStartVerticalWidgets.addAll(widget.mBelongingGroup.mStartVerticalWidgets);
            if (!widget.mBelongingGroup.mSkipSolver) {
                upperGroup.mSkipSolver = false;
            }
            widgetGroups.remove(widget.mBelongingGroup);
            for (ConstraintWidget auxWidget : widget.mBelongingGroup.mConstrainedGroup) {
                auxWidget.mBelongingGroup = upperGroup;
            }
        }
        return true;
    }

    private static void invalidate(ConstraintWidgetContainer layoutWidget, ConstraintWidget widget, ConstraintWidgetGroup group) {
        group.mSkipSolver = false;
        layoutWidget.mSkipSolver = false;
        widget.mOptimizerMeasurable = false;
    }

    private static int getMaxDimension(ConstraintWidgetGroup group, int orientation) {
        int dimension = 0;
        int offset = orientation * 2;
        List<ConstraintWidget> startWidgets = group.getStartWidgets(orientation);
        int size = startWidgets.size();
        for (int i = 0; i < size; i++) {
            ConstraintWidget widget = (ConstraintWidget) startWidgets.get(i);
            dimension = Math.max(dimension, getMaxDimensionTraversal(widget, orientation, widget.mListAnchors[offset + 1].mTarget == null || !(widget.mListAnchors[offset].mTarget == null || widget.mListAnchors[offset + 1].mTarget == null), 0));
        }
        group.mGroupDimensions[orientation] = dimension;
        return dimension;
    }

    private static int getMaxDimensionTraversal(ConstraintWidget widget, int orientation, boolean topLeftFlow, int depth) {
        int endOffset;
        int startOffset;
        int baselinePostDistance;
        int baselinePreDistance;
        int flow;
        int depth2;
        int dimensionPost;
        int postTemp;
        int startOffset2;
        int postTemp2;
        ConstraintWidget constraintWidget = widget;
        int i = orientation;
        boolean z = topLeftFlow;
        boolean hasBaseline = false;
        if (!constraintWidget.mOptimizerMeasurable) {
            return 0;
        }
        int dimensionPre = 0;
        int dimensionPost2 = 0;
        if (constraintWidget.mBaseline.mTarget != null && i == 1) {
            hasBaseline = true;
        }
        if (z) {
            baselinePreDistance = widget.getBaselineDistance();
            baselinePostDistance = widget.getHeight() - widget.getBaselineDistance();
            startOffset = i * 2;
            endOffset = startOffset + 1;
        } else {
            baselinePreDistance = widget.getHeight() - widget.getBaselineDistance();
            baselinePostDistance = widget.getBaselineDistance();
            endOffset = i * 2;
            startOffset = endOffset + 1;
        }
        if (constraintWidget.mListAnchors[endOffset].mTarget == null || constraintWidget.mListAnchors[startOffset].mTarget != null) {
            flow = 1;
        } else {
            flow = -1;
            int aux = startOffset;
            startOffset = endOffset;
            endOffset = aux;
        }
        if (hasBaseline) {
            depth2 = depth - baselinePreDistance;
        } else {
            depth2 = depth;
        }
        int dimension = (constraintWidget.mListAnchors[startOffset].getMargin() * flow) + getParentBiasOffset(widget, orientation);
        int downDepth = dimension + depth2;
        int postTemp3 = (i == 0 ? widget.getWidth() : widget.getHeight()) * flow;
        Iterator it = constraintWidget.mListAnchors[startOffset].getResolutionNode().dependents.iterator();
        while (it.hasNext()) {
            int dimensionPost3 = dimensionPost2;
            Iterator it2 = it;
            dimensionPre = Math.max(dimensionPre, getMaxDimensionTraversal(((ResolutionAnchor) ((ResolutionNode) it.next())).myAnchor.mOwner, i, z, downDepth));
            it = it2;
            dimensionPost2 = dimensionPost3;
        }
        int dimensionPost4 = dimensionPost2;
        Iterator it3 = constraintWidget.mListAnchors[endOffset].getResolutionNode().dependents.iterator();
        int dimensionPost5 = dimensionPost4;
        while (it3.hasNext()) {
            Iterator it4 = it3;
            ResolutionAnchor anchor = (ResolutionAnchor) ((ResolutionNode) it3.next());
            int endOffset2 = endOffset;
            ResolutionAnchor resolutionAnchor = anchor;
            dimensionPost5 = Math.max(dimensionPost5, getMaxDimensionTraversal(anchor.myAnchor.mOwner, i, z, postTemp3 + downDepth));
            it3 = it4;
            endOffset = endOffset2;
        }
        int endOffset3 = endOffset;
        if (hasBaseline) {
            dimensionPre -= baselinePreDistance;
            dimensionPost = dimensionPost5 + baselinePostDistance;
        } else {
            dimensionPost = dimensionPost5 + ((i == 0 ? widget.getWidth() : widget.getHeight()) * flow);
        }
        int dimensionBaseline = 0;
        if (i == 1) {
            Iterator it5 = constraintWidget.mBaseline.getResolutionNode().dependents.iterator();
            while (it5.hasNext()) {
                Iterator it6 = it5;
                ResolutionAnchor anchor2 = (ResolutionAnchor) ((ResolutionNode) it5.next());
                int startOffset3 = startOffset;
                if (flow == 1) {
                    postTemp2 = postTemp3;
                    dimensionBaseline = Math.max(dimensionBaseline, getMaxDimensionTraversal(anchor2.myAnchor.mOwner, i, z, baselinePreDistance + downDepth));
                } else {
                    postTemp2 = postTemp3;
                    dimensionBaseline = Math.max(dimensionBaseline, getMaxDimensionTraversal(anchor2.myAnchor.mOwner, i, z, (baselinePostDistance * flow) + downDepth));
                }
                it5 = it6;
                startOffset = startOffset3;
                postTemp3 = postTemp2;
            }
            startOffset2 = startOffset;
            postTemp = postTemp3;
            if (constraintWidget.mBaseline.getResolutionNode().dependents.size() > 0 && !hasBaseline) {
                if (flow == 1) {
                    dimensionBaseline += baselinePreDistance;
                } else {
                    dimensionBaseline -= baselinePostDistance;
                }
            }
        } else {
            startOffset2 = startOffset;
            postTemp = postTemp3;
        }
        int startOffset4 = dimension;
        int dimension2 = dimension + Math.max(dimensionPre, Math.max(dimensionPost, dimensionBaseline));
        int leftTop = depth2 + startOffset4;
        int end = leftTop + postTemp;
        int i2 = downDepth;
        if (flow == -1) {
            int aux2 = end;
            end = leftTop;
            leftTop = aux2;
        }
        if (z) {
            Optimizer.setOptimizedWidget(constraintWidget, i, leftTop);
            constraintWidget.setFrame(leftTop, end, i);
        } else {
            constraintWidget.mBelongingGroup.addWidgetsToSet(constraintWidget, i);
            constraintWidget.setRelativePositioning(leftTop, i);
        }
        if (widget.getDimensionBehaviour(orientation) == DimensionBehaviour.MATCH_CONSTRAINT && constraintWidget.mDimensionRatio != 0.0f) {
            constraintWidget.mBelongingGroup.addWidgetsToSet(constraintWidget, i);
        }
        if (!(constraintWidget.mListAnchors[startOffset2].mTarget == null || constraintWidget.mListAnchors[endOffset3].mTarget == null)) {
            ConstraintWidget parent = widget.getParent();
            if (constraintWidget.mListAnchors[startOffset2].mTarget.mOwner == parent && constraintWidget.mListAnchors[endOffset3].mTarget.mOwner == parent) {
                constraintWidget.mBelongingGroup.addWidgetsToSet(constraintWidget, i);
            }
        }
        return dimension2;
    }

    private static void setConnection(ConstraintAnchor originAnchor) {
        ResolutionNode originNode = originAnchor.getResolutionNode();
        if (originAnchor.mTarget != null && originAnchor.mTarget.mTarget != originAnchor) {
            originAnchor.mTarget.getResolutionNode().addDependent(originNode);
        }
    }

    private static void singleGroup(ConstraintWidgetContainer layoutWidget) {
        layoutWidget.mWidgetGroups.clear();
        layoutWidget.mWidgetGroups.add(0, new ConstraintWidgetGroup(layoutWidget.mChildren));
    }

    public static void setPosition(List<ConstraintWidgetGroup> groups, int orientation, int containerLength) {
        int groupsSize = groups.size();
        for (int i = 0; i < groupsSize; i++) {
            for (ConstraintWidget widget : ((ConstraintWidgetGroup) groups.get(i)).getWidgetsToSet(orientation)) {
                if (widget.mOptimizerMeasurable) {
                    updateSizeDependentWidgets(widget, orientation, containerLength);
                }
            }
        }
    }

    private static void updateSizeDependentWidgets(ConstraintWidget widget, int orientation, int containerLength) {
        int offset = orientation * 2;
        ConstraintAnchor startAnchor = widget.mListAnchors[offset];
        ConstraintAnchor endAnchor = widget.mListAnchors[offset + 1];
        if ((startAnchor.mTarget == null || endAnchor.mTarget == null) ? false : true) {
            Optimizer.setOptimizedWidget(widget, orientation, getParentBiasOffset(widget, orientation) + startAnchor.getMargin());
        } else if (widget.mDimensionRatio == 0.0f || widget.getDimensionBehaviour(orientation) != DimensionBehaviour.MATCH_CONSTRAINT) {
            int end = containerLength - widget.getRelativePositioning(orientation);
            int start = end - widget.getLength(orientation);
            widget.setFrame(start, end, orientation);
            Optimizer.setOptimizedWidget(widget, orientation, start);
        } else {
            int length = resolveDimensionRatio(widget);
            int start2 = (int) widget.mListAnchors[offset].getResolutionNode().resolvedOffset;
            int end2 = start2 + length;
            endAnchor.getResolutionNode().resolvedTarget = startAnchor.getResolutionNode();
            endAnchor.getResolutionNode().resolvedOffset = (float) length;
            endAnchor.getResolutionNode().state = 1;
            widget.setFrame(start2, end2, orientation);
        }
    }

    private static int getParentBiasOffset(ConstraintWidget widget, int orientation) {
        int offset = orientation * 2;
        ConstraintAnchor startAnchor = widget.mListAnchors[offset];
        ConstraintAnchor endAnchor = widget.mListAnchors[offset + 1];
        if (startAnchor.mTarget == null || startAnchor.mTarget.mOwner != widget.mParent || endAnchor.mTarget == null || endAnchor.mTarget.mOwner != widget.mParent) {
            return 0;
        }
        return (int) (((float) (((widget.mParent.getLength(orientation) - startAnchor.getMargin()) - endAnchor.getMargin()) - widget.getLength(orientation))) * (orientation == 0 ? widget.mHorizontalBiasPercent : widget.mVerticalBiasPercent));
    }

    private static int resolveDimensionRatio(ConstraintWidget widget) {
        int length;
        int length2 = -1;
        if (widget.getHorizontalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
            if (widget.mDimensionRatioSide == 0) {
                length2 = (int) (((float) widget.getHeight()) * widget.mDimensionRatio);
            } else {
                length2 = (int) (((float) widget.getHeight()) / widget.mDimensionRatio);
            }
            widget.setWidth(length2);
        } else if (widget.getVerticalDimensionBehaviour() == DimensionBehaviour.MATCH_CONSTRAINT) {
            if (widget.mDimensionRatioSide == 1) {
                length = (int) (((float) widget.getWidth()) * widget.mDimensionRatio);
            } else {
                length = (int) (((float) widget.getWidth()) / widget.mDimensionRatio);
            }
            widget.setHeight(length2);
        }
        return length2;
    }
}
