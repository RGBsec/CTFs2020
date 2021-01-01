package com.google.android.material.shape;

public class TriangleEdgeTreatment extends EdgeTreatment {
    private final boolean inside;
    private final float size;

    public TriangleEdgeTreatment(float size2, boolean inside2) {
        this.size = size2;
        this.inside = inside2;
    }

    public void getEdgePath(float length, float interpolation, ShapePath shapePath) {
        shapePath.lineTo((length / 2.0f) - (this.size * interpolation), 0.0f);
        shapePath.lineTo(length / 2.0f, (this.inside ? this.size : -this.size) * interpolation);
        shapePath.lineTo((length / 2.0f) + (this.size * interpolation), 0.0f);
        shapePath.lineTo(length, 0.0f);
    }
}
