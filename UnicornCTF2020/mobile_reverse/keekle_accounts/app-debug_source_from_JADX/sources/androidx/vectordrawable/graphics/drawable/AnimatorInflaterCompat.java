package androidx.vectordrawable.graphics.drawable;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorSet;
import android.animation.Keyframe;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.TypeEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.util.Xml;
import android.view.InflateException;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.graphics.PathParser;
import androidx.core.graphics.PathParser.PathDataNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class AnimatorInflaterCompat {
    private static final boolean DBG_ANIMATOR_INFLATER = false;
    private static final int MAX_NUM_POINTS = 100;
    private static final String TAG = "AnimatorInflater";
    private static final int TOGETHER = 0;
    private static final int VALUE_TYPE_COLOR = 3;
    private static final int VALUE_TYPE_FLOAT = 0;
    private static final int VALUE_TYPE_INT = 1;
    private static final int VALUE_TYPE_PATH = 2;
    private static final int VALUE_TYPE_UNDEFINED = 4;

    private static class PathDataEvaluator implements TypeEvaluator<PathDataNode[]> {
        private PathDataNode[] mNodeArray;

        PathDataEvaluator() {
        }

        PathDataEvaluator(PathDataNode[] nodeArray) {
            this.mNodeArray = nodeArray;
        }

        public PathDataNode[] evaluate(float fraction, PathDataNode[] startPathData, PathDataNode[] endPathData) {
            if (PathParser.canMorph(startPathData, endPathData)) {
                if (!PathParser.canMorph(this.mNodeArray, startPathData)) {
                    this.mNodeArray = PathParser.deepCopyNodes(startPathData);
                }
                for (int i = 0; i < startPathData.length; i++) {
                    this.mNodeArray[i].interpolatePathDataNode(startPathData[i], endPathData[i], fraction);
                }
                return this.mNodeArray;
            }
            throw new IllegalArgumentException("Can't interpolate between two incompatible pathData");
        }
    }

    public static Animator loadAnimator(Context context, int id) throws NotFoundException {
        if (VERSION.SDK_INT >= 24) {
            return AnimatorInflater.loadAnimator(context, id);
        }
        return loadAnimator(context, context.getResources(), context.getTheme(), id);
    }

    public static Animator loadAnimator(Context context, Resources resources, Theme theme, int id) throws NotFoundException {
        return loadAnimator(context, resources, theme, id, 1.0f);
    }

    public static Animator loadAnimator(Context context, Resources resources, Theme theme, int id, float pathErrorScale) throws NotFoundException {
        String str = "Can't load animation resource ID #0x";
        XmlResourceParser parser = null;
        try {
            XmlResourceParser parser2 = resources.getAnimation(id);
            Animator animator = createAnimatorFromXml(context, resources, theme, parser2, pathErrorScale);
            if (parser2 != null) {
                parser2.close();
            }
            return animator;
        } catch (XmlPullParserException ex) {
            StringBuilder sb = new StringBuilder();
            sb.append(str);
            sb.append(Integer.toHexString(id));
            NotFoundException rnf = new NotFoundException(sb.toString());
            rnf.initCause(ex);
            throw rnf;
        } catch (IOException ex2) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(str);
            sb2.append(Integer.toHexString(id));
            NotFoundException rnf2 = new NotFoundException(sb2.toString());
            rnf2.initCause(ex2);
            throw rnf2;
        } catch (Throwable th) {
            if (parser != null) {
                parser.close();
            }
            throw th;
        }
    }

    private static PropertyValuesHolder getPVH(TypedArray styledAttributes, int valueType, int valueFromId, int valueToId, String propertyName) {
        int valueType2;
        PropertyValuesHolder returnValue;
        PropertyValuesHolder returnValue2;
        int valueTo;
        char c;
        int valueFrom;
        int valueTo2;
        char c2;
        float valueTo3;
        float valueFrom2;
        float valueTo4;
        int toType;
        PropertyValuesHolder propertyValuesHolder;
        TypedArray typedArray = styledAttributes;
        int i = valueFromId;
        int i2 = valueToId;
        String str = propertyName;
        TypedValue tvFrom = typedArray.peekValue(i);
        boolean hasFrom = tvFrom != null;
        int fromType = hasFrom ? tvFrom.type : 0;
        TypedValue tvTo = typedArray.peekValue(i2);
        boolean hasTo = tvTo != null;
        int toType2 = hasTo ? tvTo.type : 0;
        int i3 = valueType;
        if (i3 != 4) {
            valueType2 = i3;
        } else if ((!hasFrom || !isColorType(fromType)) && (!hasTo || !isColorType(toType2))) {
            valueType2 = 0;
        } else {
            valueType2 = 3;
        }
        boolean getFloats = valueType2 == 0;
        if (valueType2 == 2) {
            String fromString = typedArray.getString(i);
            String toString = typedArray.getString(i2);
            PathDataNode[] nodesFrom = PathParser.createNodesFromPathData(fromString);
            TypedValue typedValue = tvFrom;
            PathDataNode[] nodesTo = PathParser.createNodesFromPathData(toString);
            if (nodesFrom == null && nodesTo == null) {
                TypedValue typedValue2 = tvTo;
                toType = toType2;
                propertyValuesHolder = null;
            } else {
                if (nodesFrom != null) {
                    TypeEvaluator pathDataEvaluator = new PathDataEvaluator();
                    if (nodesTo == null) {
                        TypeEvaluator evaluator = pathDataEvaluator;
                        toType = toType2;
                        returnValue = PropertyValuesHolder.ofObject(str, evaluator, new Object[]{nodesFrom});
                    } else if (PathParser.canMorph(nodesFrom, nodesTo)) {
                        TypedValue typedValue3 = tvTo;
                        returnValue = PropertyValuesHolder.ofObject(str, pathDataEvaluator, new Object[]{nodesFrom, nodesTo});
                        toType = toType2;
                    } else {
                        PathDataEvaluator pathDataEvaluator2 = pathDataEvaluator;
                        StringBuilder sb = new StringBuilder();
                        int i4 = toType2;
                        sb.append(" Can't morph from ");
                        sb.append(fromString);
                        sb.append(" to ");
                        sb.append(toString);
                        throw new InflateException(sb.toString());
                    }
                } else {
                    toType = toType2;
                    propertyValuesHolder = null;
                    if (nodesTo != null) {
                        returnValue = PropertyValuesHolder.ofObject(str, new PathDataEvaluator(), new Object[]{nodesTo});
                    }
                }
                int toType3 = valueToId;
                int i5 = toType;
            }
            returnValue = propertyValuesHolder;
            int toType32 = valueToId;
            int i52 = toType;
        } else {
            TypedValue typedValue4 = tvTo;
            int toType4 = toType2;
            TypeEvaluator evaluator2 = null;
            if (valueType2 == 3) {
                evaluator2 = ArgbEvaluator.getInstance();
            }
            if (!getFloats) {
                int i6 = valueToId;
                int toType5 = toType4;
                if (hasFrom) {
                    if (fromType == 5) {
                        valueFrom = (int) typedArray.getDimension(i, 0.0f);
                    } else if (isColorType(fromType) != 0) {
                        valueFrom = typedArray.getColor(i, 0);
                    } else {
                        valueFrom = typedArray.getInt(i, 0);
                    }
                    if (hasTo) {
                        if (toType5 == 5) {
                            valueTo2 = (int) typedArray.getDimension(i6, 0.0f);
                            c2 = 0;
                        } else if (isColorType(toType5) != 0) {
                            c2 = 0;
                            valueTo2 = typedArray.getColor(i6, 0);
                        } else {
                            c2 = 0;
                            valueTo2 = typedArray.getInt(i6, 0);
                        }
                        int[] iArr = new int[2];
                        iArr[c2] = valueFrom;
                        iArr[1] = valueTo2;
                        returnValue2 = PropertyValuesHolder.ofInt(str, iArr);
                    } else {
                        returnValue2 = PropertyValuesHolder.ofInt(str, new int[]{valueFrom});
                    }
                } else if (hasTo) {
                    if (toType5 == 5) {
                        valueTo = (int) typedArray.getDimension(i6, 0.0f);
                        c = 0;
                    } else if (isColorType(toType5) != 0) {
                        c = 0;
                        valueTo = typedArray.getColor(i6, 0);
                    } else {
                        c = 0;
                        valueTo = typedArray.getInt(i6, 0);
                    }
                    int[] iArr2 = new int[1];
                    iArr2[c] = valueTo;
                    returnValue2 = PropertyValuesHolder.ofInt(str, iArr2);
                } else {
                    returnValue2 = null;
                }
            } else if (hasFrom) {
                if (fromType == 5) {
                    valueFrom2 = typedArray.getDimension(i, 0.0f);
                } else {
                    valueFrom2 = typedArray.getFloat(i, 0.0f);
                }
                if (hasTo) {
                    if (toType4 == 5) {
                        valueTo4 = typedArray.getDimension(valueToId, 0.0f);
                    } else {
                        valueTo4 = typedArray.getFloat(valueToId, 0.0f);
                    }
                    returnValue2 = PropertyValuesHolder.ofFloat(str, new float[]{valueFrom2, valueTo4});
                } else {
                    int i7 = valueToId;
                    int i8 = toType4;
                    returnValue2 = PropertyValuesHolder.ofFloat(str, new float[]{valueFrom2});
                }
            } else {
                int i9 = valueToId;
                if (toType4 == 5) {
                    valueTo3 = typedArray.getDimension(i9, 0.0f);
                } else {
                    valueTo3 = typedArray.getFloat(i9, 0.0f);
                }
                returnValue2 = PropertyValuesHolder.ofFloat(str, new float[]{valueTo3});
            }
            if (!(returnValue == null || evaluator2 == null)) {
                returnValue.setEvaluator(evaluator2);
            }
        }
        return returnValue;
    }

    private static void parseAnimatorFromTypeArray(ValueAnimator anim, TypedArray arrayAnimator, TypedArray arrayObjectAnimator, float pixelSize, XmlPullParser parser) {
        long duration = (long) TypedArrayUtils.getNamedInt(arrayAnimator, parser, "duration", 1, 300);
        long startDelay = (long) TypedArrayUtils.getNamedInt(arrayAnimator, parser, "startOffset", 2, 0);
        int valueType = TypedArrayUtils.getNamedInt(arrayAnimator, parser, "valueType", 7, 4);
        if (TypedArrayUtils.hasAttribute(parser, "valueFrom") && TypedArrayUtils.hasAttribute(parser, "valueTo")) {
            if (valueType == 4) {
                valueType = inferValueTypeFromValues(arrayAnimator, 5, 6);
            }
            PropertyValuesHolder pvh = getPVH(arrayAnimator, valueType, 5, 6, "");
            if (pvh != null) {
                anim.setValues(new PropertyValuesHolder[]{pvh});
            }
        }
        anim.setDuration(duration);
        anim.setStartDelay(startDelay);
        anim.setRepeatCount(TypedArrayUtils.getNamedInt(arrayAnimator, parser, "repeatCount", 3, 0));
        anim.setRepeatMode(TypedArrayUtils.getNamedInt(arrayAnimator, parser, "repeatMode", 4, 1));
        if (arrayObjectAnimator != null) {
            setupObjectAnimator(anim, arrayObjectAnimator, valueType, pixelSize, parser);
        }
    }

    private static void setupObjectAnimator(ValueAnimator anim, TypedArray arrayObjectAnimator, int valueType, float pixelSize, XmlPullParser parser) {
        ObjectAnimator oa = (ObjectAnimator) anim;
        String pathData = TypedArrayUtils.getNamedString(arrayObjectAnimator, parser, "pathData", 1);
        if (pathData != null) {
            String propertyXName = TypedArrayUtils.getNamedString(arrayObjectAnimator, parser, "propertyXName", 2);
            String propertyYName = TypedArrayUtils.getNamedString(arrayObjectAnimator, parser, "propertyYName", 3);
            if (valueType == 2 || valueType == 4) {
            }
            if (propertyXName == null && propertyYName == null) {
                StringBuilder sb = new StringBuilder();
                sb.append(arrayObjectAnimator.getPositionDescription());
                sb.append(" propertyXName or propertyYName is needed for PathData");
                throw new InflateException(sb.toString());
            }
            setupPathMotion(PathParser.createPathFromPathData(pathData), oa, 0.5f * pixelSize, propertyXName, propertyYName);
            return;
        }
        oa.setPropertyName(TypedArrayUtils.getNamedString(arrayObjectAnimator, parser, "propertyName", 0));
    }

    private static void setupPathMotion(Path path, ObjectAnimator oa, float precision, String propertyXName, String propertyYName) {
        Path path2 = path;
        ObjectAnimator objectAnimator = oa;
        String str = propertyXName;
        String str2 = propertyYName;
        PathMeasure measureForTotalLength = new PathMeasure(path2, false);
        float totalLength = 0.0f;
        ArrayList<Float> contourLengths = new ArrayList<>();
        contourLengths.add(Float.valueOf(0.0f));
        while (true) {
            totalLength += measureForTotalLength.getLength();
            contourLengths.add(Float.valueOf(totalLength));
            if (!measureForTotalLength.nextContour()) {
                break;
            }
            path2 = path;
        }
        PathMeasure pathMeasure = new PathMeasure(path2, false);
        int numPoints = Math.min(100, ((int) (totalLength / precision)) + 1);
        float[] mX = new float[numPoints];
        float[] mY = new float[numPoints];
        float[] position = new float[2];
        int contourIndex = 0;
        float step = totalLength / ((float) (numPoints - 1));
        float currentDistance = 0.0f;
        int i = 0;
        while (i < numPoints) {
            pathMeasure.getPosTan(currentDistance - ((Float) contourLengths.get(contourIndex)).floatValue(), position, null);
            mX[i] = position[0];
            mY[i] = position[1];
            currentDistance += step;
            if (contourIndex + 1 < contourLengths.size() && currentDistance > ((Float) contourLengths.get(contourIndex + 1)).floatValue()) {
                contourIndex++;
                pathMeasure.nextContour();
            }
            i++;
            Path path3 = path;
        }
        PropertyValuesHolder x = null;
        PropertyValuesHolder y = null;
        if (str != null) {
            x = PropertyValuesHolder.ofFloat(str, mX);
        }
        if (str2 != null) {
            y = PropertyValuesHolder.ofFloat(str2, mY);
        }
        if (x == null) {
            objectAnimator.setValues(new PropertyValuesHolder[]{y});
        } else if (y == null) {
            objectAnimator.setValues(new PropertyValuesHolder[]{x});
        } else {
            objectAnimator.setValues(new PropertyValuesHolder[]{x, y});
        }
    }

    private static Animator createAnimatorFromXml(Context context, Resources res, Theme theme, XmlPullParser parser, float pixelSize) throws XmlPullParserException, IOException {
        return createAnimatorFromXml(context, res, theme, parser, Xml.asAttributeSet(parser), null, 0, pixelSize);
    }

    private static Animator createAnimatorFromXml(Context context, Resources res, Theme theme, XmlPullParser parser, AttributeSet attrs, AnimatorSet parent, int sequenceOrdering, float pixelSize) throws XmlPullParserException, IOException {
        Resources resources = res;
        Theme theme2 = theme;
        XmlPullParser xmlPullParser = parser;
        AnimatorSet animatorSet = parent;
        int depth = parser.getDepth();
        Animator anim = null;
        ArrayList arrayList = null;
        while (true) {
            int next = parser.next();
            int type = next;
            if (next != 3 || parser.getDepth() > depth) {
                if (type == 1) {
                    Context context2 = context;
                    break;
                } else if (type == 2) {
                    String name = parser.getName();
                    boolean gotValues = false;
                    if (name.equals("objectAnimator")) {
                        Context context3 = context;
                        anim = loadObjectAnimator(context, res, theme, attrs, pixelSize, parser);
                    } else if (name.equals("animator")) {
                        Context context4 = context;
                        anim = loadAnimator(context, res, theme, attrs, null, pixelSize, parser);
                    } else if (name.equals("set")) {
                        Animator anim2 = new AnimatorSet();
                        TypedArray a = TypedArrayUtils.obtainAttributes(resources, theme2, attrs, AndroidResources.STYLEABLE_ANIMATOR_SET);
                        Context context5 = context;
                        Resources resources2 = res;
                        Theme theme3 = theme;
                        XmlPullParser xmlPullParser2 = parser;
                        AttributeSet attributeSet = attrs;
                        TypedArray a2 = a;
                        createAnimatorFromXml(context5, resources2, theme3, xmlPullParser2, attributeSet, (AnimatorSet) anim2, TypedArrayUtils.getNamedInt(a, xmlPullParser, "ordering", 0, 0), pixelSize);
                        a2.recycle();
                        Context context6 = context;
                        anim = anim2;
                    } else if (name.equals("propertyValuesHolder")) {
                        PropertyValuesHolder[] values = loadValues(context, resources, theme2, xmlPullParser, Xml.asAttributeSet(parser));
                        if (values != null && (anim instanceof ValueAnimator)) {
                            ((ValueAnimator) anim).setValues(values);
                        }
                        gotValues = true;
                    } else {
                        Context context7 = context;
                        StringBuilder sb = new StringBuilder();
                        sb.append("Unknown animator name: ");
                        sb.append(parser.getName());
                        throw new RuntimeException(sb.toString());
                    }
                    if (animatorSet != null && !gotValues) {
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.add(anim);
                    }
                }
            } else {
                Context context8 = context;
                break;
            }
        }
        if (!(animatorSet == null || arrayList == null)) {
            Animator[] animsArray = new Animator[arrayList.size()];
            int index = 0;
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                int index2 = index + 1;
                animsArray[index] = (Animator) it.next();
                index = index2;
            }
            if (sequenceOrdering == 0) {
                animatorSet.playTogether(animsArray);
            } else {
                animatorSet.playSequentially(animsArray);
            }
        }
        return anim;
    }

    private static PropertyValuesHolder[] loadValues(Context context, Resources res, Theme theme, XmlPullParser parser, AttributeSet attrs) throws XmlPullParserException, IOException {
        XmlPullParser xmlPullParser = parser;
        ArrayList arrayList = null;
        while (true) {
            int eventType = parser.getEventType();
            int type = eventType;
            if (eventType == 3 || type == 1) {
                Resources resources = res;
                Theme theme2 = theme;
                AttributeSet attributeSet = attrs;
                PropertyValuesHolder[] valuesArray = null;
            } else if (type != 2) {
                parser.next();
            } else {
                if (parser.getName().equals("propertyValuesHolder")) {
                    TypedArray a = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_PROPERTY_VALUES_HOLDER);
                    String propertyName = TypedArrayUtils.getNamedString(a, xmlPullParser, "propertyName", 3);
                    int valueType = TypedArrayUtils.getNamedInt(a, xmlPullParser, "valueType", 2, 4);
                    int valueType2 = valueType;
                    PropertyValuesHolder pvh = loadPvh(context, res, theme, parser, propertyName, valueType);
                    if (pvh == null) {
                        pvh = getPVH(a, valueType2, 0, 1, propertyName);
                    }
                    if (pvh != null) {
                        if (arrayList == null) {
                            arrayList = new ArrayList();
                        }
                        arrayList.add(pvh);
                    }
                    a.recycle();
                } else {
                    Resources resources2 = res;
                    Theme theme3 = theme;
                    AttributeSet attributeSet2 = attrs;
                }
                parser.next();
            }
        }
        Resources resources3 = res;
        Theme theme22 = theme;
        AttributeSet attributeSet3 = attrs;
        PropertyValuesHolder[] valuesArray2 = null;
        if (arrayList != null) {
            int count = arrayList.size();
            valuesArray2 = new PropertyValuesHolder[count];
            for (int i = 0; i < count; i++) {
                valuesArray2[i] = (PropertyValuesHolder) arrayList.get(i);
            }
        }
        return valuesArray2;
    }

    private static int inferValueTypeOfKeyframe(Resources res, Theme theme, AttributeSet attrs, XmlPullParser parser) {
        int valueType;
        TypedArray a = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_KEYFRAME);
        boolean hasValue = false;
        TypedValue keyframeValue = TypedArrayUtils.peekNamedValue(a, parser, "value", 0);
        if (keyframeValue != null) {
            hasValue = true;
        }
        if (!hasValue || !isColorType(keyframeValue.type)) {
            valueType = 0;
        } else {
            valueType = 3;
        }
        a.recycle();
        return valueType;
    }

    private static int inferValueTypeFromValues(TypedArray styledAttributes, int valueFromId, int valueToId) {
        TypedValue tvFrom = styledAttributes.peekValue(valueFromId);
        boolean hasTo = true;
        int toType = 0;
        boolean hasFrom = tvFrom != null;
        int fromType = hasFrom ? tvFrom.type : 0;
        TypedValue tvTo = styledAttributes.peekValue(valueToId);
        if (tvTo == null) {
            hasTo = false;
        }
        if (hasTo) {
            toType = tvTo.type;
        }
        if ((!hasFrom || !isColorType(fromType)) && (!hasTo || !isColorType(toType))) {
            return 0;
        }
        return 3;
    }

    private static void dumpKeyframes(Object[] keyframes, String header) {
        if (keyframes != null && keyframes.length != 0) {
            String str = TAG;
            Log.d(str, header);
            int count = keyframes.length;
            for (int i = 0; i < count; i++) {
                Keyframe keyframe = keyframes[i];
                StringBuilder sb = new StringBuilder();
                sb.append("Keyframe ");
                sb.append(i);
                sb.append(": fraction ");
                Object obj = "null";
                sb.append(keyframe.getFraction() < 0.0f ? obj : Float.valueOf(keyframe.getFraction()));
                sb.append(", , value : ");
                if (keyframe.hasValue()) {
                    obj = keyframe.getValue();
                }
                sb.append(obj);
                Log.d(str, sb.toString());
            }
        }
    }

    private static PropertyValuesHolder loadPvh(Context context, Resources res, Theme theme, XmlPullParser parser, String propertyName, int valueType) throws XmlPullParserException, IOException {
        int type;
        PropertyValuesHolder value;
        Object obj;
        int type2;
        float f;
        ArrayList arrayList;
        Object obj2 = null;
        ArrayList arrayList2 = null;
        int valueType2 = valueType;
        while (true) {
            int next = parser.next();
            type = next;
            if (next == 3 || type == 1) {
                Resources resources = res;
                Theme theme2 = theme;
                XmlPullParser xmlPullParser = parser;
            } else if (parser.getName().equals("keyframe")) {
                if (valueType2 == 4) {
                    valueType2 = inferValueTypeOfKeyframe(res, theme, Xml.asAttributeSet(parser), parser);
                } else {
                    Resources resources2 = res;
                    Theme theme3 = theme;
                    XmlPullParser xmlPullParser2 = parser;
                }
                Keyframe keyframe = loadKeyframe(context, res, theme, Xml.asAttributeSet(parser), valueType2, parser);
                if (keyframe != null) {
                    if (arrayList2 == null) {
                        arrayList2 = new ArrayList();
                    }
                    arrayList2.add(keyframe);
                }
                parser.next();
            } else {
                Resources resources3 = res;
                Theme theme4 = theme;
                XmlPullParser xmlPullParser3 = parser;
            }
        }
        Resources resources4 = res;
        Theme theme22 = theme;
        XmlPullParser xmlPullParser4 = parser;
        if (arrayList2 != null) {
            int size = arrayList2.size();
            int count = size;
            if (size > 0) {
                Keyframe firstKeyframe = (Keyframe) arrayList2.get(0);
                Keyframe lastKeyframe = (Keyframe) arrayList2.get(count - 1);
                float endFraction = lastKeyframe.getFraction();
                float f2 = 0.0f;
                if (endFraction < 1.0f) {
                    if (endFraction < 0.0f) {
                        lastKeyframe.setFraction(1.0f);
                    } else {
                        arrayList2.add(arrayList2.size(), createNewKeyframe(lastKeyframe, 1.0f));
                        count++;
                    }
                }
                float startFraction = firstKeyframe.getFraction();
                if (startFraction != 0.0f) {
                    if (startFraction < 0.0f) {
                        firstKeyframe.setFraction(0.0f);
                    } else {
                        arrayList2.add(0, createNewKeyframe(firstKeyframe, 0.0f));
                        count++;
                    }
                }
                Keyframe[] keyframeArray = new Keyframe[count];
                arrayList2.toArray(keyframeArray);
                int i = 0;
                while (i < count) {
                    Keyframe keyframe2 = keyframeArray[i];
                    if (keyframe2.getFraction() >= f2) {
                        obj = obj2;
                        arrayList = arrayList2;
                        type2 = type;
                        f = f2;
                    } else if (i == 0) {
                        keyframe2.setFraction(f2);
                        obj = obj2;
                        arrayList = arrayList2;
                        type2 = type;
                        f = f2;
                    } else if (i == count - 1) {
                        keyframe2.setFraction(1.0f);
                        obj = obj2;
                        arrayList = arrayList2;
                        type2 = type;
                        f = 0.0f;
                    } else {
                        int startIndex = i;
                        obj = obj2;
                        int j = startIndex + 1;
                        arrayList = arrayList2;
                        int endIndex = i;
                        while (true) {
                            type2 = type;
                            if (j >= count - 1) {
                                f = 0.0f;
                                break;
                            }
                            f = 0.0f;
                            if (keyframeArray[j].getFraction() >= 0.0f) {
                                break;
                            }
                            endIndex = j;
                            j++;
                            type = type2;
                        }
                        distributeKeyframes(keyframeArray, keyframeArray[endIndex + 1].getFraction() - keyframeArray[startIndex - 1].getFraction(), startIndex, endIndex);
                    }
                    i++;
                    arrayList2 = arrayList;
                    f2 = f;
                    type = type2;
                    obj2 = obj;
                }
                Object obj3 = obj2;
                ArrayList arrayList3 = arrayList2;
                int i2 = type;
                PropertyValuesHolder value2 = PropertyValuesHolder.ofKeyframe(propertyName, keyframeArray);
                if (valueType2 != 3) {
                    return value2;
                }
                value2.setEvaluator(ArgbEvaluator.getInstance());
                return value2;
            }
            value = null;
            ArrayList arrayList4 = arrayList2;
            int i3 = type;
            String str = propertyName;
        } else {
            value = null;
            ArrayList arrayList5 = arrayList2;
            int i4 = type;
            String str2 = propertyName;
        }
        return value;
    }

    private static Keyframe createNewKeyframe(Keyframe sampleKeyframe, float fraction) {
        if (sampleKeyframe.getType() == Float.TYPE) {
            return Keyframe.ofFloat(fraction);
        }
        if (sampleKeyframe.getType() == Integer.TYPE) {
            return Keyframe.ofInt(fraction);
        }
        return Keyframe.ofObject(fraction);
    }

    private static void distributeKeyframes(Keyframe[] keyframes, float gap, int startIndex, int endIndex) {
        float increment = gap / ((float) ((endIndex - startIndex) + 2));
        for (int i = startIndex; i <= endIndex; i++) {
            keyframes[i].setFraction(keyframes[i - 1].getFraction() + increment);
        }
    }

    private static Keyframe loadKeyframe(Context context, Resources res, Theme theme, AttributeSet attrs, int valueType, XmlPullParser parser) throws XmlPullParserException, IOException {
        Keyframe keyframe;
        TypedArray a = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_KEYFRAME);
        Keyframe keyframe2 = null;
        float fraction = TypedArrayUtils.getNamedFloat(a, parser, "fraction", 3, -1.0f);
        String str = "value";
        TypedValue keyframeValue = TypedArrayUtils.peekNamedValue(a, parser, str, 0);
        boolean hasValue = keyframeValue != null;
        if (valueType == 4) {
            if (!hasValue || !isColorType(keyframeValue.type)) {
                valueType = 0;
            } else {
                valueType = 3;
            }
        }
        if (!hasValue) {
            if (valueType == 0) {
                keyframe = Keyframe.ofFloat(fraction);
            } else {
                keyframe = Keyframe.ofInt(fraction);
            }
            keyframe2 = keyframe;
        } else if (valueType == 0) {
            keyframe2 = Keyframe.ofFloat(fraction, TypedArrayUtils.getNamedFloat(a, parser, str, 0, 0.0f));
        } else if (valueType == 1 || valueType == 3) {
            keyframe2 = Keyframe.ofInt(fraction, TypedArrayUtils.getNamedInt(a, parser, str, 0, 0));
        }
        int resID = TypedArrayUtils.getNamedResourceId(a, parser, "interpolator", 1, 0);
        if (resID > 0) {
            keyframe2.setInterpolator(AnimationUtilsCompat.loadInterpolator(context, resID));
        }
        a.recycle();
        return keyframe2;
    }

    private static ObjectAnimator loadObjectAnimator(Context context, Resources res, Theme theme, AttributeSet attrs, float pathErrorScale, XmlPullParser parser) throws NotFoundException {
        ObjectAnimator anim = new ObjectAnimator();
        loadAnimator(context, res, theme, attrs, anim, pathErrorScale, parser);
        return anim;
    }

    private static ValueAnimator loadAnimator(Context context, Resources res, Theme theme, AttributeSet attrs, ValueAnimator anim, float pathErrorScale, XmlPullParser parser) throws NotFoundException {
        TypedArray arrayAnimator = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_ANIMATOR);
        TypedArray arrayObjectAnimator = TypedArrayUtils.obtainAttributes(res, theme, attrs, AndroidResources.STYLEABLE_PROPERTY_ANIMATOR);
        if (anim == null) {
            anim = new ValueAnimator();
        }
        parseAnimatorFromTypeArray(anim, arrayAnimator, arrayObjectAnimator, pathErrorScale, parser);
        int resID = TypedArrayUtils.getNamedResourceId(arrayAnimator, parser, "interpolator", 0, 0);
        if (resID > 0) {
            anim.setInterpolator(AnimationUtilsCompat.loadInterpolator(context, resID));
        }
        arrayAnimator.recycle();
        if (arrayObjectAnimator != null) {
            arrayObjectAnimator.recycle();
        }
        return anim;
    }

    private static boolean isColorType(int type) {
        return type >= 28 && type <= 31;
    }

    private AnimatorInflaterCompat() {
    }
}
