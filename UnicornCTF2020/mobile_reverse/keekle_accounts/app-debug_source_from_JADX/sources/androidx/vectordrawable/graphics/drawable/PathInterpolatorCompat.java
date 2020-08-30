package androidx.vectordrawable.graphics.drawable;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.util.AttributeSet;
import android.view.InflateException;
import android.view.animation.Interpolator;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.graphics.PathParser;
import org.xmlpull.v1.XmlPullParser;

public class PathInterpolatorCompat implements Interpolator {
    public static final double EPSILON = 1.0E-5d;
    public static final int MAX_NUM_POINTS = 3000;
    private static final float PRECISION = 0.002f;

    /* renamed from: mX */
    private float[] f47mX;

    /* renamed from: mY */
    private float[] f48mY;

    public PathInterpolatorCompat(Context context, AttributeSet attrs, XmlPullParser parser) {
        this(context.getResources(), context.getTheme(), attrs, parser);
    }

    public PathInterpolatorCompat(Resources res, Theme theme, AttributeSet attrs, XmlPullParser parser) {
        TypedArray a = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_PATH_INTERPOLATOR);
        parseInterpolatorFromTypeArray(a, parser);
        a.recycle();
    }

    private void parseInterpolatorFromTypeArray(TypedArray a, XmlPullParser parser) {
        String str = "pathData";
        if (TypedArrayUtils.hasAttribute(parser, str)) {
            String pathData = TypedArrayUtils.getNamedString(a, parser, str, 4);
            Path path = PathParser.createPathFromPathData(pathData);
            if (path != null) {
                initPath(path);
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("The path is null, which is created from ");
            sb.append(pathData);
            throw new InflateException(sb.toString());
        }
        String pathData2 = "controlX1";
        if (TypedArrayUtils.hasAttribute(parser, pathData2)) {
            String str2 = "controlY1";
            if (TypedArrayUtils.hasAttribute(parser, str2)) {
                float x1 = TypedArrayUtils.getNamedFloat(a, parser, pathData2, 0, 0.0f);
                float y1 = TypedArrayUtils.getNamedFloat(a, parser, str2, 1, 0.0f);
                String str3 = "controlX2";
                boolean hasX2 = TypedArrayUtils.hasAttribute(parser, str3);
                String str4 = "controlY2";
                if (hasX2 != TypedArrayUtils.hasAttribute(parser, str4)) {
                    throw new InflateException("pathInterpolator requires both controlX2 and controlY2 for cubic Beziers.");
                } else if (!hasX2) {
                    initQuad(x1, y1);
                } else {
                    initCubic(x1, y1, TypedArrayUtils.getNamedFloat(a, parser, str3, 2, 0.0f), TypedArrayUtils.getNamedFloat(a, parser, str4, 3, 0.0f));
                }
            } else {
                throw new InflateException("pathInterpolator requires the controlY1 attribute");
            }
        } else {
            throw new InflateException("pathInterpolator requires the controlX1 attribute");
        }
    }

    private void initQuad(float controlX, float controlY) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.quadTo(controlX, controlY, 1.0f, 1.0f);
        initPath(path);
    }

    private void initCubic(float x1, float y1, float x2, float y2) {
        Path path = new Path();
        path.moveTo(0.0f, 0.0f);
        path.cubicTo(x1, y1, x2, y2, 1.0f, 1.0f);
        initPath(path);
    }

    private void initPath(Path path) {
        PathMeasure pathMeasure = new PathMeasure(path, false);
        float pathLength = pathMeasure.getLength();
        int numPoints = Math.min(MAX_NUM_POINTS, ((int) (pathLength / PRECISION)) + 1);
        if (numPoints > 0) {
            this.f47mX = new float[numPoints];
            this.f48mY = new float[numPoints];
            float[] position = new float[2];
            for (int i = 0; i < numPoints; i++) {
                pathMeasure.getPosTan((((float) i) * pathLength) / ((float) (numPoints - 1)), position, null);
                this.f47mX[i] = position[0];
                this.f48mY[i] = position[1];
            }
            if (((double) Math.abs(this.f47mX[0])) > 1.0E-5d || ((double) Math.abs(this.f48mY[0])) > 1.0E-5d || ((double) Math.abs(this.f47mX[numPoints - 1] - 1.0f)) > 1.0E-5d || ((double) Math.abs(this.f48mY[numPoints - 1] - 1.0f)) > 1.0E-5d) {
                StringBuilder sb = new StringBuilder();
                sb.append("The Path must start at (0,0) and end at (1,1) start: ");
                sb.append(this.f47mX[0]);
                String str = ",";
                sb.append(str);
                sb.append(this.f48mY[0]);
                sb.append(" end:");
                sb.append(this.f47mX[numPoints - 1]);
                sb.append(str);
                sb.append(this.f48mY[numPoints - 1]);
                throw new IllegalArgumentException(sb.toString());
            }
            float prevX = 0.0f;
            int componentIndex = 0;
            int i2 = 0;
            while (i2 < numPoints) {
                float[] fArr = this.f47mX;
                int componentIndex2 = componentIndex + 1;
                float x = fArr[componentIndex];
                if (x >= prevX) {
                    fArr[i2] = x;
                    prevX = x;
                    i2++;
                    componentIndex = componentIndex2;
                } else {
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("The Path cannot loop back on itself, x :");
                    sb2.append(x);
                    throw new IllegalArgumentException(sb2.toString());
                }
            }
            if (pathMeasure.nextContour() != 0) {
                throw new IllegalArgumentException("The Path should be continuous, can't have 2+ contours");
            }
            return;
        }
        StringBuilder sb3 = new StringBuilder();
        sb3.append("The Path has a invalid length ");
        sb3.append(pathLength);
        throw new IllegalArgumentException(sb3.toString());
    }

    public float getInterpolation(float t) {
        if (t <= 0.0f) {
            return 0.0f;
        }
        if (t >= 1.0f) {
            return 1.0f;
        }
        int startIndex = 0;
        int endIndex = this.f47mX.length - 1;
        while (endIndex - startIndex > 1) {
            int midIndex = (startIndex + endIndex) / 2;
            if (t < this.f47mX[midIndex]) {
                endIndex = midIndex;
            } else {
                startIndex = midIndex;
            }
        }
        float[] fArr = this.f47mX;
        float xRange = fArr[endIndex] - fArr[startIndex];
        if (xRange == 0.0f) {
            return this.f48mY[startIndex];
        }
        float fraction = (t - fArr[startIndex]) / xRange;
        float[] fArr2 = this.f48mY;
        float startY = fArr2[startIndex];
        return ((fArr2[endIndex] - startY) * fraction) + startY;
    }
}
