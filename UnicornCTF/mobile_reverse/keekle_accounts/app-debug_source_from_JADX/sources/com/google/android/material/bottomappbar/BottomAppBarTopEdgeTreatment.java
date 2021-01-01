package com.google.android.material.bottomappbar;

import com.google.android.material.shape.EdgeTreatment;
import com.google.android.material.shape.ShapePath;

public class BottomAppBarTopEdgeTreatment extends EdgeTreatment {
    private static final int ANGLE_LEFT = 180;
    private static final int ANGLE_UP = 270;
    private static final int ARC_HALF = 180;
    private static final int ARC_QUARTER = 90;
    private float cradleVerticalOffset;
    private float fabDiameter;
    private float fabMargin;
    private float horizontalOffset;
    private float roundedCornerRadius;

    public BottomAppBarTopEdgeTreatment(float fabMargin2, float roundedCornerRadius2, float cradleVerticalOffset2) {
        this.fabMargin = fabMargin2;
        this.roundedCornerRadius = roundedCornerRadius2;
        this.cradleVerticalOffset = cradleVerticalOffset2;
        if (cradleVerticalOffset2 >= 0.0f) {
            this.horizontalOffset = 0.0f;
            return;
        }
        throw new IllegalArgumentException("cradleVerticalOffset must be positive.");
    }

    public void getEdgePath(float length, float interpolation, ShapePath shapePath) {
        float f = length;
        ShapePath shapePath2 = shapePath;
        float f2 = this.fabDiameter;
        if (f2 == 0.0f) {
            shapePath2.lineTo(f, 0.0f);
            return;
        }
        float cradleRadius = ((this.fabMargin * 2.0f) + f2) / 2.0f;
        float roundedCornerOffset = interpolation * this.roundedCornerRadius;
        float middle = (f / 2.0f) + this.horizontalOffset;
        float verticalOffset = (this.cradleVerticalOffset * interpolation) + ((1.0f - interpolation) * cradleRadius);
        if (verticalOffset / cradleRadius >= 1.0f) {
            shapePath2.lineTo(f, 0.0f);
            return;
        }
        float distanceBetweenCenters = cradleRadius + roundedCornerOffset;
        float distanceY = verticalOffset + roundedCornerOffset;
        float distanceX = (float) Math.sqrt((double) ((distanceBetweenCenters * distanceBetweenCenters) - (distanceY * distanceY)));
        float leftRoundedCornerCircleX = middle - distanceX;
        float rightRoundedCornerCircleX = middle + distanceX;
        float cornerRadiusArcLength = (float) Math.toDegrees(Math.atan((double) (distanceX / distanceY)));
        float cutoutArcOffset = 90.0f - cornerRadiusArcLength;
        shapePath2.lineTo(leftRoundedCornerCircleX - roundedCornerOffset, 0.0f);
        float cornerRadiusArcLength2 = cornerRadiusArcLength;
        float f3 = distanceX;
        shapePath.addArc(leftRoundedCornerCircleX - roundedCornerOffset, 0.0f, leftRoundedCornerCircleX + roundedCornerOffset, roundedCornerOffset * 2.0f, 270.0f, cornerRadiusArcLength2);
        shapePath.addArc(middle - cradleRadius, (-cradleRadius) - verticalOffset, middle + cradleRadius, cradleRadius - verticalOffset, 180.0f - cutoutArcOffset, (cutoutArcOffset * 2.0f) - 180.0f);
        shapePath.addArc(rightRoundedCornerCircleX - roundedCornerOffset, 0.0f, rightRoundedCornerCircleX + roundedCornerOffset, roundedCornerOffset * 2.0f, 270.0f - cornerRadiusArcLength2, cornerRadiusArcLength2);
        shapePath2.lineTo(f, 0.0f);
    }

    /* access modifiers changed from: 0000 */
    public void setHorizontalOffset(float horizontalOffset2) {
        this.horizontalOffset = horizontalOffset2;
    }

    /* access modifiers changed from: 0000 */
    public float getHorizontalOffset() {
        return this.horizontalOffset;
    }

    /* access modifiers changed from: 0000 */
    public float getCradleVerticalOffset() {
        return this.cradleVerticalOffset;
    }

    /* access modifiers changed from: 0000 */
    public void setCradleVerticalOffset(float cradleVerticalOffset2) {
        this.cradleVerticalOffset = cradleVerticalOffset2;
    }

    /* access modifiers changed from: 0000 */
    public float getFabDiameter() {
        return this.fabDiameter;
    }

    /* access modifiers changed from: 0000 */
    public void setFabDiameter(float fabDiameter2) {
        this.fabDiameter = fabDiameter2;
    }

    /* access modifiers changed from: 0000 */
    public float getFabCradleMargin() {
        return this.fabMargin;
    }

    /* access modifiers changed from: 0000 */
    public void setFabCradleMargin(float fabMargin2) {
        this.fabMargin = fabMargin2;
    }

    /* access modifiers changed from: 0000 */
    public float getFabCradleRoundedCornerRadius() {
        return this.roundedCornerRadius;
    }

    /* access modifiers changed from: 0000 */
    public void setFabCradleRoundedCornerRadius(float roundedCornerRadius2) {
        this.roundedCornerRadius = roundedCornerRadius2;
    }
}
