package androidx.core.view.animation;

import android.graphics.Path;
import android.graphics.PathMeasure;
import android.view.animation.Interpolator;

class PathInterpolatorApi14 implements Interpolator {
    private static final float PRECISION = 0.002f;

    /* renamed from: mX */
    private final float[] f36mX;

    /* renamed from: mY */
    private final float[] f37mY;

    PathInterpolatorApi14(Path path) {
        PathMeasure pathMeasure = new PathMeasure(path, false);
        float pathLength = pathMeasure.getLength();
        int numPoints = ((int) (pathLength / PRECISION)) + 1;
        this.f36mX = new float[numPoints];
        this.f37mY = new float[numPoints];
        float[] position = new float[2];
        for (int i = 0; i < numPoints; i++) {
            pathMeasure.getPosTan((((float) i) * pathLength) / ((float) (numPoints - 1)), position, null);
            this.f36mX[i] = position[0];
            this.f37mY[i] = position[1];
        }
    }

    PathInterpolatorApi14(float controlX, float controlY) {
        this(createQuad(controlX, controlY));
    }

    PathInterpolatorApi14(float controlX1, float controlY1, float controlX2, float controlY2) {
        this(createCubic(controlX1, controlY1, controlX2, controlY2));
    }

    public float getInterpolation(float t) {
        if (t <= 0.0f) {
            return 0.0f;
        }
        if (t >= 1.0f) {
            return 1.0f;
        }
        int startIndex = 0;
        int endIndex = this.f36mX.length - 1;
        while (endIndex - startIndex > 1) {
            int midIndex = (startIndex + endIndex) / 2;
            if (t < this.f36mX[midIndex]) {
                endIndex = midIndex;
            } else {
                startIndex = midIndex;
            }
        }
        float[] fArr = this.f36mX;
        float xRange = fArr[endIndex] - fArr[startIndex];
        if (xRange == 0.0f) {
            return this.f37mY[startIndex];
        }
        float fraction = (t - fArr[startIndex]) / xRange;
        float[] fArr2 = this.f37mY;
        float startY = fArr2[startIndex];
        return ((fArr2[endIndex] - startY) * fraction) + startY;
    }

    private static Path createQuad(float controlX, float controlY) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.quadTo(controlX, controlY, 1.0f, 1.0f);
        return path;
    }

    private static Path createCubic(float controlX1, float controlY1, float controlX2, float controlY2) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.cubicTo(controlX1, controlY1, controlX2, controlY2, 1.0f, 1.0f);
        return path;
    }
}
