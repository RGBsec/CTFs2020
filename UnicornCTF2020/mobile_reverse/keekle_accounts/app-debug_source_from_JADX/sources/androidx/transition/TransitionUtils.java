package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.TypeEvaluator;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Picture;
import android.graphics.RectF;
import android.os.Build.VERSION;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;

class TransitionUtils {
    private static final boolean HAS_IS_ATTACHED_TO_WINDOW = (VERSION.SDK_INT >= 19);
    private static final boolean HAS_OVERLAY = (VERSION.SDK_INT >= 18);
    private static final boolean HAS_PICTURE_BITMAP;
    private static final int MAX_IMAGE_SIZE = 1048576;

    static class MatrixEvaluator implements TypeEvaluator<Matrix> {
        final float[] mTempEndValues = new float[9];
        final Matrix mTempMatrix = new Matrix();
        final float[] mTempStartValues = new float[9];

        MatrixEvaluator() {
        }

        public Matrix evaluate(float fraction, Matrix startValue, Matrix endValue) {
            startValue.getValues(this.mTempStartValues);
            endValue.getValues(this.mTempEndValues);
            for (int i = 0; i < 9; i++) {
                float[] fArr = this.mTempEndValues;
                float f = fArr[i];
                float[] fArr2 = this.mTempStartValues;
                fArr[i] = fArr2[i] + (fraction * (f - fArr2[i]));
            }
            this.mTempMatrix.setValues(this.mTempEndValues);
            return this.mTempMatrix;
        }
    }

    static {
        boolean z = true;
        if (VERSION.SDK_INT < 28) {
            z = false;
        }
        HAS_PICTURE_BITMAP = z;
    }

    static View copyViewImage(ViewGroup sceneRoot, View view, View parent) {
        Matrix matrix = new Matrix();
        matrix.setTranslate((float) (-parent.getScrollX()), (float) (-parent.getScrollY()));
        ViewUtils.transformMatrixToGlobal(view, matrix);
        ViewUtils.transformMatrixToLocal(sceneRoot, matrix);
        RectF bounds = new RectF(0.0f, 0.0f, (float) view.getWidth(), (float) view.getHeight());
        matrix.mapRect(bounds);
        int left = Math.round(bounds.left);
        int top = Math.round(bounds.top);
        int right = Math.round(bounds.right);
        int bottom = Math.round(bounds.bottom);
        ImageView copy = new ImageView(view.getContext());
        copy.setScaleType(ScaleType.CENTER_CROP);
        Bitmap bitmap = createViewBitmap(view, matrix, bounds, sceneRoot);
        if (bitmap != null) {
            copy.setImageBitmap(bitmap);
        }
        copy.measure(MeasureSpec.makeMeasureSpec(right - left, 1073741824), MeasureSpec.makeMeasureSpec(bottom - top, 1073741824));
        copy.layout(left, top, right, bottom);
        return copy;
    }

    private static Bitmap createViewBitmap(View view, Matrix matrix, RectF bounds, ViewGroup sceneRoot) {
        boolean sceneRootIsAttached;
        boolean addToOverlay;
        if (HAS_IS_ATTACHED_TO_WINDOW) {
            addToOverlay = !view.isAttachedToWindow();
            sceneRootIsAttached = sceneRoot == null ? false : sceneRoot.isAttachedToWindow();
        } else {
            addToOverlay = false;
            sceneRootIsAttached = false;
        }
        ViewGroup parent = null;
        int indexInParent = 0;
        if (HAS_OVERLAY && addToOverlay) {
            if (!sceneRootIsAttached) {
                return null;
            }
            parent = (ViewGroup) view.getParent();
            indexInParent = parent.indexOfChild(view);
            sceneRoot.getOverlay().add(view);
        }
        Bitmap bitmap = null;
        int bitmapWidth = Math.round(bounds.width());
        int bitmapHeight = Math.round(bounds.height());
        if (bitmapWidth > 0 && bitmapHeight > 0) {
            float scale = Math.min(1.0f, 1048576.0f / ((float) (bitmapWidth * bitmapHeight)));
            int bitmapWidth2 = Math.round(((float) bitmapWidth) * scale);
            int bitmapHeight2 = Math.round(((float) bitmapHeight) * scale);
            matrix.postTranslate(-bounds.left, -bounds.top);
            matrix.postScale(scale, scale);
            if (HAS_PICTURE_BITMAP) {
                Picture picture = new Picture();
                Canvas canvas = picture.beginRecording(bitmapWidth2, bitmapHeight2);
                canvas.concat(matrix);
                view.draw(canvas);
                picture.endRecording();
                bitmap = Bitmap.createBitmap(picture);
            } else {
                bitmap = Bitmap.createBitmap(bitmapWidth2, bitmapHeight2, Config.ARGB_8888);
                Canvas canvas2 = new Canvas(bitmap);
                canvas2.concat(matrix);
                view.draw(canvas2);
            }
        }
        if (HAS_OVERLAY && addToOverlay) {
            sceneRoot.getOverlay().remove(view);
            parent.addView(view, indexInParent);
        }
        return bitmap;
    }

    static Animator mergeAnimators(Animator animator1, Animator animator2) {
        if (animator1 == null) {
            return animator2;
        }
        if (animator2 == null) {
            return animator1;
        }
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(new Animator[]{animator1, animator2});
        return animatorSet;
    }

    private TransitionUtils() {
    }
}
