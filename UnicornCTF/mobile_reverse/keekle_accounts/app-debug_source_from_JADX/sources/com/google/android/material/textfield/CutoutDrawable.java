package com.google.android.material.textfield;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.graphics.drawable.Drawable.Callback;
import android.graphics.drawable.GradientDrawable;
import android.os.Build.VERSION;
import android.view.View;

class CutoutDrawable extends GradientDrawable {
    private final RectF cutoutBounds;
    private final Paint cutoutPaint = new Paint(1);
    private int savedLayer;

    CutoutDrawable() {
        setPaintStyles();
        this.cutoutBounds = new RectF();
    }

    private void setPaintStyles() {
        this.cutoutPaint.setStyle(Style.FILL_AND_STROKE);
        this.cutoutPaint.setColor(-1);
        this.cutoutPaint.setXfermode(new PorterDuffXfermode(Mode.DST_OUT));
    }

    /* access modifiers changed from: 0000 */
    public boolean hasCutout() {
        return !this.cutoutBounds.isEmpty();
    }

    /* access modifiers changed from: 0000 */
    public void setCutout(float left, float top, float right, float bottom) {
        if (left != this.cutoutBounds.left || top != this.cutoutBounds.top || right != this.cutoutBounds.right || bottom != this.cutoutBounds.bottom) {
            this.cutoutBounds.set(left, top, right, bottom);
            invalidateSelf();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setCutout(RectF bounds) {
        setCutout(bounds.left, bounds.top, bounds.right, bounds.bottom);
    }

    /* access modifiers changed from: 0000 */
    public void removeCutout() {
        setCutout(0.0f, 0.0f, 0.0f, 0.0f);
    }

    public void draw(Canvas canvas) {
        preDraw(canvas);
        super.draw(canvas);
        canvas.drawRect(this.cutoutBounds, this.cutoutPaint);
        postDraw(canvas);
    }

    private void preDraw(Canvas canvas) {
        Callback callback = getCallback();
        if (useHardwareLayer(callback)) {
            ((View) callback).setLayerType(2, null);
        } else {
            saveCanvasLayer(canvas);
        }
    }

    private void saveCanvasLayer(Canvas canvas) {
        if (VERSION.SDK_INT >= 21) {
            this.savedLayer = canvas.saveLayer(0.0f, 0.0f, (float) canvas.getWidth(), (float) canvas.getHeight(), null);
            return;
        }
        this.savedLayer = canvas.saveLayer(0.0f, 0.0f, (float) canvas.getWidth(), (float) canvas.getHeight(), null, 31);
    }

    private void postDraw(Canvas canvas) {
        if (!useHardwareLayer(getCallback())) {
            canvas.restoreToCount(this.savedLayer);
        }
    }

    private boolean useHardwareLayer(Callback callback) {
        return callback instanceof View;
    }
}
