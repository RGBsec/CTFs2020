package com.google.android.material.animation;

import android.animation.TypeEvaluator;
import android.graphics.Matrix;

public class MatrixEvaluator implements TypeEvaluator<Matrix> {
    private final float[] tempEndValues = new float[9];
    private final Matrix tempMatrix = new Matrix();
    private final float[] tempStartValues = new float[9];

    public Matrix evaluate(float fraction, Matrix startValue, Matrix endValue) {
        startValue.getValues(this.tempStartValues);
        endValue.getValues(this.tempEndValues);
        for (int i = 0; i < 9; i++) {
            float[] fArr = this.tempEndValues;
            float f = fArr[i];
            float[] fArr2 = this.tempStartValues;
            fArr[i] = fArr2[i] + (fraction * (f - fArr2[i]));
        }
        this.tempMatrix.setValues(this.tempEndValues);
        return this.tempMatrix;
    }
}
