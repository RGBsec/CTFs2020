package com.google.android.material.shape;

import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.RectF;
import java.util.ArrayList;
import java.util.List;

public class ShapePath {
    public float endX;
    public float endY;
    private final List<PathOperation> operations = new ArrayList();
    public float startX;
    public float startY;

    public static class PathArcOperation extends PathOperation {
        private static final RectF rectF = new RectF();
        public float bottom;
        public float left;
        public float right;
        public float startAngle;
        public float sweepAngle;
        public float top;

        public PathArcOperation(float left2, float top2, float right2, float bottom2) {
            this.left = left2;
            this.top = top2;
            this.right = right2;
            this.bottom = bottom2;
        }

        public void applyToPath(Matrix transform, Path path) {
            Matrix inverse = this.matrix;
            transform.invert(inverse);
            path.transform(inverse);
            rectF.set(this.left, this.top, this.right, this.bottom);
            path.arcTo(rectF, this.startAngle, this.sweepAngle, false);
            path.transform(transform);
        }
    }

    public static class PathLineOperation extends PathOperation {
        /* access modifiers changed from: private */

        /* renamed from: x */
        public float f51x;
        /* access modifiers changed from: private */

        /* renamed from: y */
        public float f52y;

        public void applyToPath(Matrix transform, Path path) {
            Matrix inverse = this.matrix;
            transform.invert(inverse);
            path.transform(inverse);
            path.lineTo(this.f51x, this.f52y);
            path.transform(transform);
        }
    }

    public static abstract class PathOperation {
        protected final Matrix matrix = new Matrix();

        public abstract void applyToPath(Matrix matrix2, Path path);
    }

    public static class PathQuadOperation extends PathOperation {
        public float controlX;
        public float controlY;
        public float endX;
        public float endY;

        public void applyToPath(Matrix transform, Path path) {
            Matrix inverse = this.matrix;
            transform.invert(inverse);
            path.transform(inverse);
            path.quadTo(this.controlX, this.controlY, this.endX, this.endY);
            path.transform(transform);
        }
    }

    public ShapePath() {
        reset(0.0f, 0.0f);
    }

    public ShapePath(float startX2, float startY2) {
        reset(startX2, startY2);
    }

    public void reset(float startX2, float startY2) {
        this.startX = startX2;
        this.startY = startY2;
        this.endX = startX2;
        this.endY = startY2;
        this.operations.clear();
    }

    public void lineTo(float x, float y) {
        PathLineOperation operation = new PathLineOperation();
        operation.f51x = x;
        operation.f52y = y;
        this.operations.add(operation);
        this.endX = x;
        this.endY = y;
    }

    public void quadToPoint(float controlX, float controlY, float toX, float toY) {
        PathQuadOperation operation = new PathQuadOperation();
        operation.controlX = controlX;
        operation.controlY = controlY;
        operation.endX = toX;
        operation.endY = toY;
        this.operations.add(operation);
        this.endX = toX;
        this.endY = toY;
    }

    public void addArc(float left, float top, float right, float bottom, float startAngle, float sweepAngle) {
        PathArcOperation operation = new PathArcOperation(left, top, right, bottom);
        operation.startAngle = startAngle;
        operation.sweepAngle = sweepAngle;
        this.operations.add(operation);
        this.endX = ((left + right) * 0.5f) + (((right - left) / 2.0f) * ((float) Math.cos(Math.toRadians((double) (startAngle + sweepAngle)))));
        this.endY = ((top + bottom) * 0.5f) + (((bottom - top) / 2.0f) * ((float) Math.sin(Math.toRadians((double) (startAngle + sweepAngle)))));
    }

    public void applyToPath(Matrix transform, Path path) {
        int size = this.operations.size();
        for (int i = 0; i < size; i++) {
            ((PathOperation) this.operations.get(i)).applyToPath(transform, path);
        }
    }
}
