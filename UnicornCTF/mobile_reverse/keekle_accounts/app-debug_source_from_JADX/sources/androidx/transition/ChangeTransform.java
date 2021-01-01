package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PointF;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Property;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.view.ViewCompat;
import java.util.Map;
import org.xmlpull.v1.XmlPullParser;

public class ChangeTransform extends Transition {
    private static final Property<PathAnimatorMatrix, float[]> NON_TRANSLATIONS_PROPERTY = new Property<PathAnimatorMatrix, float[]>(float[].class, "nonTranslations") {
        public float[] get(PathAnimatorMatrix object) {
            return null;
        }

        public void set(PathAnimatorMatrix object, float[] value) {
            object.setValues(value);
        }
    };
    private static final String PROPNAME_INTERMEDIATE_MATRIX = "android:changeTransform:intermediateMatrix";
    private static final String PROPNAME_INTERMEDIATE_PARENT_MATRIX = "android:changeTransform:intermediateParentMatrix";
    private static final String PROPNAME_MATRIX = "android:changeTransform:matrix";
    private static final String PROPNAME_PARENT = "android:changeTransform:parent";
    private static final String PROPNAME_PARENT_MATRIX = "android:changeTransform:parentMatrix";
    private static final String PROPNAME_TRANSFORMS = "android:changeTransform:transforms";
    private static final boolean SUPPORTS_VIEW_REMOVAL_SUPPRESSION = (VERSION.SDK_INT >= 21);
    private static final Property<PathAnimatorMatrix, PointF> TRANSLATIONS_PROPERTY = new Property<PathAnimatorMatrix, PointF>(PointF.class, "translations") {
        public PointF get(PathAnimatorMatrix object) {
            return null;
        }

        public void set(PathAnimatorMatrix object, PointF value) {
            object.setTranslation(value);
        }
    };
    private static final String[] sTransitionProperties = {PROPNAME_MATRIX, PROPNAME_TRANSFORMS, PROPNAME_PARENT_MATRIX};
    private boolean mReparent = true;
    private Matrix mTempMatrix = new Matrix();
    boolean mUseOverlay = true;

    private static class GhostListener extends TransitionListenerAdapter {
        private GhostViewImpl mGhostView;
        private View mView;

        GhostListener(View view, GhostViewImpl ghostView) {
            this.mView = view;
            this.mGhostView = ghostView;
        }

        public void onTransitionEnd(Transition transition) {
            transition.removeListener(this);
            GhostViewUtils.removeGhost(this.mView);
            this.mView.setTag(C0065R.C0067id.transition_transform, null);
            this.mView.setTag(C0065R.C0067id.parent_matrix, null);
        }

        public void onTransitionPause(Transition transition) {
            this.mGhostView.setVisibility(4);
        }

        public void onTransitionResume(Transition transition) {
            this.mGhostView.setVisibility(0);
        }
    }

    private static class PathAnimatorMatrix {
        private final Matrix mMatrix = new Matrix();
        private float mTranslationX;
        private float mTranslationY;
        private final float[] mValues;
        private final View mView;

        PathAnimatorMatrix(View view, float[] values) {
            this.mView = view;
            float[] fArr = (float[]) values.clone();
            this.mValues = fArr;
            this.mTranslationX = fArr[2];
            this.mTranslationY = fArr[5];
            setAnimationMatrix();
        }

        /* access modifiers changed from: 0000 */
        public void setValues(float[] values) {
            System.arraycopy(values, 0, this.mValues, 0, values.length);
            setAnimationMatrix();
        }

        /* access modifiers changed from: 0000 */
        public void setTranslation(PointF translation) {
            this.mTranslationX = translation.x;
            this.mTranslationY = translation.y;
            setAnimationMatrix();
        }

        private void setAnimationMatrix() {
            float[] fArr = this.mValues;
            fArr[2] = this.mTranslationX;
            fArr[5] = this.mTranslationY;
            this.mMatrix.setValues(fArr);
            ViewUtils.setAnimationMatrix(this.mView, this.mMatrix);
        }

        /* access modifiers changed from: 0000 */
        public Matrix getMatrix() {
            return this.mMatrix;
        }
    }

    private static class Transforms {
        final float mRotationX;
        final float mRotationY;
        final float mRotationZ;
        final float mScaleX;
        final float mScaleY;
        final float mTranslationX;
        final float mTranslationY;
        final float mTranslationZ;

        Transforms(View view) {
            this.mTranslationX = view.getTranslationX();
            this.mTranslationY = view.getTranslationY();
            this.mTranslationZ = ViewCompat.getTranslationZ(view);
            this.mScaleX = view.getScaleX();
            this.mScaleY = view.getScaleY();
            this.mRotationX = view.getRotationX();
            this.mRotationY = view.getRotationY();
            this.mRotationZ = view.getRotation();
        }

        public void restore(View view) {
            ChangeTransform.setTransforms(view, this.mTranslationX, this.mTranslationY, this.mTranslationZ, this.mScaleX, this.mScaleY, this.mRotationX, this.mRotationY, this.mRotationZ);
        }

        public boolean equals(Object that) {
            boolean z = false;
            if (!(that instanceof Transforms)) {
                return false;
            }
            Transforms thatTransform = (Transforms) that;
            if (thatTransform.mTranslationX == this.mTranslationX && thatTransform.mTranslationY == this.mTranslationY && thatTransform.mTranslationZ == this.mTranslationZ && thatTransform.mScaleX == this.mScaleX && thatTransform.mScaleY == this.mScaleY && thatTransform.mRotationX == this.mRotationX && thatTransform.mRotationY == this.mRotationY && thatTransform.mRotationZ == this.mRotationZ) {
                z = true;
            }
            return z;
        }

        public int hashCode() {
            float f = this.mTranslationX;
            int i = 0;
            int floatToIntBits = (f != 0.0f ? Float.floatToIntBits(f) : 0) * 31;
            float f2 = this.mTranslationY;
            int code = (floatToIntBits + (f2 != 0.0f ? Float.floatToIntBits(f2) : 0)) * 31;
            float f3 = this.mTranslationZ;
            int code2 = (code + (f3 != 0.0f ? Float.floatToIntBits(f3) : 0)) * 31;
            float f4 = this.mScaleX;
            int code3 = (code2 + (f4 != 0.0f ? Float.floatToIntBits(f4) : 0)) * 31;
            float f5 = this.mScaleY;
            int code4 = (code3 + (f5 != 0.0f ? Float.floatToIntBits(f5) : 0)) * 31;
            float f6 = this.mRotationX;
            int code5 = (code4 + (f6 != 0.0f ? Float.floatToIntBits(f6) : 0)) * 31;
            float f7 = this.mRotationY;
            int code6 = (code5 + (f7 != 0.0f ? Float.floatToIntBits(f7) : 0)) * 31;
            float f8 = this.mRotationZ;
            if (f8 != 0.0f) {
                i = Float.floatToIntBits(f8);
            }
            return code6 + i;
        }
    }

    public ChangeTransform() {
    }

    public ChangeTransform(Context context, AttributeSet attrs) {
        super(context, attrs);
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.CHANGE_TRANSFORM);
        this.mUseOverlay = TypedArrayUtils.getNamedBoolean(a, (XmlPullParser) attrs, "reparentWithOverlay", 1, true);
        this.mReparent = TypedArrayUtils.getNamedBoolean(a, (XmlPullParser) attrs, "reparent", 0, true);
        a.recycle();
    }

    public boolean getReparentWithOverlay() {
        return this.mUseOverlay;
    }

    public void setReparentWithOverlay(boolean reparentWithOverlay) {
        this.mUseOverlay = reparentWithOverlay;
    }

    public boolean getReparent() {
        return this.mReparent;
    }

    public void setReparent(boolean reparent) {
        this.mReparent = reparent;
    }

    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    private void captureValues(TransitionValues transitionValues) {
        Matrix matrix;
        View view = transitionValues.view;
        if (view.getVisibility() != 8) {
            transitionValues.values.put(PROPNAME_PARENT, view.getParent());
            transitionValues.values.put(PROPNAME_TRANSFORMS, new Transforms(view));
            Matrix matrix2 = view.getMatrix();
            if (matrix2 == null || matrix2.isIdentity()) {
                matrix = null;
            } else {
                matrix = new Matrix(matrix2);
            }
            transitionValues.values.put(PROPNAME_MATRIX, matrix);
            if (this.mReparent) {
                Matrix parentMatrix = new Matrix();
                ViewGroup parent = (ViewGroup) view.getParent();
                ViewUtils.transformMatrixToGlobal(parent, parentMatrix);
                parentMatrix.preTranslate((float) (-parent.getScrollX()), (float) (-parent.getScrollY()));
                transitionValues.values.put(PROPNAME_PARENT_MATRIX, parentMatrix);
                transitionValues.values.put(PROPNAME_INTERMEDIATE_MATRIX, view.getTag(C0065R.C0067id.transition_transform));
                transitionValues.values.put(PROPNAME_INTERMEDIATE_PARENT_MATRIX, view.getTag(C0065R.C0067id.parent_matrix));
            }
        }
    }

    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
        if (!SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
            ((ViewGroup) transitionValues.view.getParent()).startViewTransition(transitionValues.view);
        }
    }

    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        if (!(startValues == null || endValues == null)) {
            Map<String, Object> map = startValues.values;
            String str = PROPNAME_PARENT;
            if (map.containsKey(str) && endValues.values.containsKey(str)) {
                ViewGroup startParent = (ViewGroup) startValues.values.get(str);
                boolean handleParentChange = this.mReparent && !parentsMatch(startParent, (ViewGroup) endValues.values.get(str));
                Matrix startMatrix = (Matrix) startValues.values.get(PROPNAME_INTERMEDIATE_MATRIX);
                if (startMatrix != null) {
                    startValues.values.put(PROPNAME_MATRIX, startMatrix);
                }
                Matrix startParentMatrix = (Matrix) startValues.values.get(PROPNAME_INTERMEDIATE_PARENT_MATRIX);
                if (startParentMatrix != null) {
                    startValues.values.put(PROPNAME_PARENT_MATRIX, startParentMatrix);
                }
                if (handleParentChange) {
                    setMatricesForParent(startValues, endValues);
                }
                ObjectAnimator transformAnimator = createTransformAnimator(startValues, endValues, handleParentChange);
                if (handleParentChange && transformAnimator != null && this.mUseOverlay) {
                    createGhostView(sceneRoot, startValues, endValues);
                } else if (!SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
                    startParent.endViewTransition(startValues.view);
                }
                return transformAnimator;
            }
        }
        return null;
    }

    private ObjectAnimator createTransformAnimator(TransitionValues startValues, TransitionValues endValues, boolean handleParentChange) {
        TransitionValues transitionValues = endValues;
        Map<String, Object> map = startValues.values;
        String str = PROPNAME_MATRIX;
        Matrix startMatrix = (Matrix) map.get(str);
        Matrix endMatrix = (Matrix) transitionValues.values.get(str);
        if (startMatrix == null) {
            startMatrix = MatrixUtils.IDENTITY_MATRIX;
        }
        if (endMatrix == null) {
            endMatrix = MatrixUtils.IDENTITY_MATRIX;
        }
        if (startMatrix.equals(endMatrix)) {
            return null;
        }
        Transforms transforms = (Transforms) transitionValues.values.get(PROPNAME_TRANSFORMS);
        View view = transitionValues.view;
        setIdentityTransforms(view);
        float[] startMatrixValues = new float[9];
        startMatrix.getValues(startMatrixValues);
        float[] endMatrixValues = new float[9];
        endMatrix.getValues(endMatrixValues);
        PathAnimatorMatrix pathAnimatorMatrix = new PathAnimatorMatrix(view, startMatrixValues);
        PropertyValuesHolder valuesProperty = PropertyValuesHolder.ofObject(NON_TRANSLATIONS_PROPERTY, new FloatArrayEvaluator(new float[9]), new float[][]{startMatrixValues, endMatrixValues});
        Path path = getPathMotion().getPath(startMatrixValues[2], startMatrixValues[5], endMatrixValues[2], endMatrixValues[5]);
        final Matrix finalEndMatrix = endMatrix;
        final boolean z = handleParentChange;
        final View view2 = view;
        ObjectAnimator animator = ObjectAnimator.ofPropertyValuesHolder(pathAnimatorMatrix, new PropertyValuesHolder[]{valuesProperty, PropertyValuesHolderUtils.ofPointF(TRANSLATIONS_PROPERTY, path)});
        final Transforms transforms2 = transforms;
        Path path2 = path;
        final PathAnimatorMatrix pathAnimatorMatrix2 = pathAnimatorMatrix;
        C03873 r4 = new AnimatorListenerAdapter() {
            private boolean mIsCanceled;
            private Matrix mTempMatrix = new Matrix();

            public void onAnimationCancel(Animator animation) {
                this.mIsCanceled = true;
            }

            public void onAnimationEnd(Animator animation) {
                if (!this.mIsCanceled) {
                    if (!z || !ChangeTransform.this.mUseOverlay) {
                        view2.setTag(C0065R.C0067id.transition_transform, null);
                        view2.setTag(C0065R.C0067id.parent_matrix, null);
                    } else {
                        setCurrentMatrix(finalEndMatrix);
                    }
                }
                ViewUtils.setAnimationMatrix(view2, null);
                transforms2.restore(view2);
            }

            public void onAnimationPause(Animator animation) {
                setCurrentMatrix(pathAnimatorMatrix2.getMatrix());
            }

            public void onAnimationResume(Animator animation) {
                ChangeTransform.setIdentityTransforms(view2);
            }

            private void setCurrentMatrix(Matrix currentMatrix) {
                this.mTempMatrix.set(currentMatrix);
                view2.setTag(C0065R.C0067id.transition_transform, this.mTempMatrix);
                transforms2.restore(view2);
            }
        };
        animator.addListener(r4);
        AnimatorUtils.addPauseListener(animator, r4);
        return animator;
    }

    private boolean parentsMatch(ViewGroup startParent, ViewGroup endParent) {
        boolean z = false;
        if (!isValidTarget(startParent) || !isValidTarget(endParent)) {
            if (startParent == endParent) {
                z = true;
            }
            return z;
        }
        TransitionValues endValues = getMatchedTransitionValues(startParent, true);
        if (endValues == null) {
            return false;
        }
        if (endParent == endValues.view) {
            z = true;
        }
        return z;
    }

    private void createGhostView(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        View view = endValues.view;
        Matrix localEndMatrix = new Matrix((Matrix) endValues.values.get(PROPNAME_PARENT_MATRIX));
        ViewUtils.transformMatrixToLocal(sceneRoot, localEndMatrix);
        GhostViewImpl ghostView = GhostViewUtils.addGhost(view, sceneRoot, localEndMatrix);
        if (ghostView != null) {
            ghostView.reserveEndViewTransition((ViewGroup) startValues.values.get(PROPNAME_PARENT), startValues.view);
            Transition outerTransition = this;
            while (outerTransition.mParent != null) {
                outerTransition = outerTransition.mParent;
            }
            outerTransition.addListener(new GhostListener(view, ghostView));
            if (SUPPORTS_VIEW_REMOVAL_SUPPRESSION) {
                if (startValues.view != endValues.view) {
                    ViewUtils.setTransitionAlpha(startValues.view, 0.0f);
                }
                ViewUtils.setTransitionAlpha(view, 1.0f);
            }
        }
    }

    private void setMatricesForParent(TransitionValues startValues, TransitionValues endValues) {
        Map<String, Object> map = endValues.values;
        String str = PROPNAME_PARENT_MATRIX;
        Matrix endParentMatrix = (Matrix) map.get(str);
        endValues.view.setTag(C0065R.C0067id.parent_matrix, endParentMatrix);
        Matrix toLocal = this.mTempMatrix;
        toLocal.reset();
        endParentMatrix.invert(toLocal);
        Map<String, Object> map2 = startValues.values;
        String str2 = PROPNAME_MATRIX;
        Matrix startLocal = (Matrix) map2.get(str2);
        if (startLocal == null) {
            startLocal = new Matrix();
            startValues.values.put(str2, startLocal);
        }
        startLocal.postConcat((Matrix) startValues.values.get(str));
        startLocal.postConcat(toLocal);
    }

    static void setIdentityTransforms(View view) {
        setTransforms(view, 0.0f, 0.0f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f);
    }

    static void setTransforms(View view, float translationX, float translationY, float translationZ, float scaleX, float scaleY, float rotationX, float rotationY, float rotationZ) {
        view.setTranslationX(translationX);
        view.setTranslationY(translationY);
        ViewCompat.setTranslationZ(view, translationZ);
        view.setScaleX(scaleX);
        view.setScaleY(scaleY);
        view.setRotationX(rotationX);
        view.setRotationY(rotationY);
        view.setRotation(rotationZ);
    }
}
