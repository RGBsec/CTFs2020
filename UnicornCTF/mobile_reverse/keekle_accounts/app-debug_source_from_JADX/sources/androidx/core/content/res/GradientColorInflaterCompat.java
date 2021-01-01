package androidx.core.content.res;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.LinearGradient;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.Shader.TileMode;
import android.graphics.SweepGradient;
import android.util.AttributeSet;
import android.util.Xml;
import androidx.core.C0020R;
import java.io.IOException;
import java.util.List;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

final class GradientColorInflaterCompat {
    private static final int TILE_MODE_CLAMP = 0;
    private static final int TILE_MODE_MIRROR = 2;
    private static final int TILE_MODE_REPEAT = 1;

    static final class ColorStops {
        final int[] mColors;
        final float[] mOffsets;

        ColorStops(List<Integer> colorsList, List<Float> offsetsList) {
            int size = colorsList.size();
            this.mColors = new int[size];
            this.mOffsets = new float[size];
            for (int i = 0; i < size; i++) {
                this.mColors[i] = ((Integer) colorsList.get(i)).intValue();
                this.mOffsets[i] = ((Float) offsetsList.get(i)).floatValue();
            }
        }

        ColorStops(int startColor, int endColor) {
            this.mColors = new int[]{startColor, endColor};
            this.mOffsets = new float[]{0.0f, 1.0f};
        }

        ColorStops(int startColor, int centerColor, int endColor) {
            this.mColors = new int[]{startColor, centerColor, endColor};
            this.mOffsets = new float[]{0.0f, 0.5f, 1.0f};
        }
    }

    private GradientColorInflaterCompat() {
    }

    static Shader createFromXml(Resources resources, XmlPullParser parser, Theme theme) throws XmlPullParserException, IOException {
        int type;
        AttributeSet attrs = Xml.asAttributeSet(parser);
        do {
            int next = parser.next();
            type = next;
            if (next == 2) {
                break;
            }
        } while (type != 1);
        if (type == 2) {
            return createFromXmlInner(resources, parser, attrs, theme);
        }
        throw new XmlPullParserException("No start tag found");
    }

    static Shader createFromXmlInner(Resources resources, XmlPullParser parser, AttributeSet attrs, Theme theme) throws IOException, XmlPullParserException {
        XmlPullParser xmlPullParser = parser;
        String name = parser.getName();
        if (name.equals("gradient")) {
            Theme theme2 = theme;
            TypedArray a = TypedArrayUtils.obtainAttributes(resources, theme2, attrs, C0020R.styleable.GradientColor);
            float startX = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "startX", C0020R.styleable.GradientColor_android_startX, 0.0f);
            float startY = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "startY", C0020R.styleable.GradientColor_android_startY, 0.0f);
            float endX = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "endX", C0020R.styleable.GradientColor_android_endX, 0.0f);
            float endY = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "endY", C0020R.styleable.GradientColor_android_endY, 0.0f);
            float centerX = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "centerX", C0020R.styleable.GradientColor_android_centerX, 0.0f);
            float centerY = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "centerY", C0020R.styleable.GradientColor_android_centerY, 0.0f);
            int type = TypedArrayUtils.getNamedInt(a, xmlPullParser, "type", C0020R.styleable.GradientColor_android_type, 0);
            int startColor = TypedArrayUtils.getNamedColor(a, xmlPullParser, "startColor", C0020R.styleable.GradientColor_android_startColor, 0);
            String str = "centerColor";
            boolean hasCenterColor = TypedArrayUtils.hasAttribute(xmlPullParser, str);
            int centerColor = TypedArrayUtils.getNamedColor(a, xmlPullParser, str, C0020R.styleable.GradientColor_android_centerColor, 0);
            int endColor = TypedArrayUtils.getNamedColor(a, xmlPullParser, "endColor", C0020R.styleable.GradientColor_android_endColor, 0);
            int tileMode = TypedArrayUtils.getNamedInt(a, xmlPullParser, "tileMode", C0020R.styleable.GradientColor_android_tileMode, 0);
            float gradientRadius = TypedArrayUtils.getNamedFloat(a, xmlPullParser, "gradientRadius", C0020R.styleable.GradientColor_android_gradientRadius, 0.0f);
            a.recycle();
            ColorStops colorStops = checkColors(inflateChildElements(resources, parser, attrs, theme), startColor, endColor, hasCenterColor, centerColor);
            if (type == 1) {
                boolean z = hasCenterColor;
                int i = startColor;
                int i2 = type;
                float centerY2 = centerY;
                float centerX2 = centerX;
                if (gradientRadius > 0.0f) {
                    int[] iArr = colorStops.mColors;
                    RadialGradient radialGradient = new RadialGradient(centerX2, centerY2, gradientRadius, iArr, colorStops.mOffsets, parseTileMode(tileMode));
                    return radialGradient;
                }
                throw new XmlPullParserException("<gradient> tag requires 'gradientRadius' attribute with radial type");
            } else if (type != 2) {
                int[] iArr2 = colorStops.mColors;
                boolean z2 = hasCenterColor;
                int[] iArr3 = iArr2;
                int i3 = startColor;
                int i4 = type;
                float f = centerY;
                TypedArray typedArray = a;
                float f2 = centerX;
                LinearGradient linearGradient = new LinearGradient(startX, startY, endX, endY, iArr3, colorStops.mOffsets, parseTileMode(tileMode));
                return linearGradient;
            } else {
                boolean z3 = hasCenterColor;
                return new SweepGradient(centerX, centerY, colorStops.mColors, colorStops.mOffsets);
            }
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(parser.getPositionDescription());
            sb.append(": invalid gradient color tag ");
            sb.append(name);
            throw new XmlPullParserException(sb.toString());
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0087, code lost:
        throw new org.xmlpull.v1.XmlPullParserException(r9.toString());
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static androidx.core.content.res.GradientColorInflaterCompat.ColorStops inflateChildElements(android.content.res.Resources r12, org.xmlpull.v1.XmlPullParser r13, android.util.AttributeSet r14, android.content.res.Resources.Theme r15) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException {
        /*
            int r0 = r13.getDepth()
            r1 = 1
            int r0 = r0 + r1
            java.util.ArrayList r2 = new java.util.ArrayList
            r3 = 20
            r2.<init>(r3)
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>(r3)
            r3 = r4
        L_0x0013:
            int r4 = r13.next()
            r5 = r4
            if (r4 == r1) goto L_0x0088
            int r4 = r13.getDepth()
            r6 = r4
            if (r4 >= r0) goto L_0x0024
            r4 = 3
            if (r5 == r4) goto L_0x0088
        L_0x0024:
            r4 = 2
            if (r5 == r4) goto L_0x0028
            goto L_0x0013
        L_0x0028:
            if (r6 > r0) goto L_0x0013
            java.lang.String r4 = r13.getName()
            java.lang.String r7 = "item"
            boolean r4 = r4.equals(r7)
            if (r4 != 0) goto L_0x0037
            goto L_0x0013
        L_0x0037:
            int[] r4 = androidx.core.C0020R.styleable.GradientColorItem
            android.content.res.TypedArray r4 = androidx.core.content.res.TypedArrayUtils.obtainAttributes(r12, r15, r14, r4)
            int r7 = androidx.core.C0020R.styleable.GradientColorItem_android_color
            boolean r7 = r4.hasValue(r7)
            int r8 = androidx.core.C0020R.styleable.GradientColorItem_android_offset
            boolean r8 = r4.hasValue(r8)
            if (r7 == 0) goto L_0x006d
            if (r8 == 0) goto L_0x006d
            int r9 = androidx.core.C0020R.styleable.GradientColorItem_android_color
            r10 = 0
            int r9 = r4.getColor(r9, r10)
            int r10 = androidx.core.C0020R.styleable.GradientColorItem_android_offset
            r11 = 0
            float r10 = r4.getFloat(r10, r11)
            r4.recycle()
            java.lang.Integer r11 = java.lang.Integer.valueOf(r9)
            r3.add(r11)
            java.lang.Float r11 = java.lang.Float.valueOf(r10)
            r2.add(r11)
            goto L_0x0013
        L_0x006d:
            org.xmlpull.v1.XmlPullParserException r1 = new org.xmlpull.v1.XmlPullParserException
            java.lang.StringBuilder r9 = new java.lang.StringBuilder
            r9.<init>()
            java.lang.String r10 = r13.getPositionDescription()
            r9.append(r10)
            java.lang.String r10 = ": <item> tag requires a 'color' attribute and a 'offset' attribute!"
            r9.append(r10)
            java.lang.String r9 = r9.toString()
            r1.<init>(r9)
            throw r1
        L_0x0088:
            int r1 = r3.size()
            if (r1 <= 0) goto L_0x0094
            androidx.core.content.res.GradientColorInflaterCompat$ColorStops r1 = new androidx.core.content.res.GradientColorInflaterCompat$ColorStops
            r1.<init>(r3, r2)
            return r1
        L_0x0094:
            r1 = 0
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.content.res.GradientColorInflaterCompat.inflateChildElements(android.content.res.Resources, org.xmlpull.v1.XmlPullParser, android.util.AttributeSet, android.content.res.Resources$Theme):androidx.core.content.res.GradientColorInflaterCompat$ColorStops");
    }

    private static ColorStops checkColors(ColorStops colorItems, int startColor, int endColor, boolean hasCenterColor, int centerColor) {
        if (colorItems != null) {
            return colorItems;
        }
        if (hasCenterColor) {
            return new ColorStops(startColor, centerColor, endColor);
        }
        return new ColorStops(startColor, endColor);
    }

    private static TileMode parseTileMode(int tileMode) {
        if (tileMode == 1) {
            return TileMode.REPEAT;
        }
        if (tileMode != 2) {
            return TileMode.CLAMP;
        }
        return TileMode.MIRROR;
    }
}
