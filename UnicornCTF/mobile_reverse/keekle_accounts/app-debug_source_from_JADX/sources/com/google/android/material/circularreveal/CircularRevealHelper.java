package com.google.android.material.circularreveal;

import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Path.Direction;
import android.graphics.Rect;
import android.graphics.Shader.TileMode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.view.View;
import androidx.core.internal.view.SupportMenu;
import androidx.core.view.ViewCompat;
import com.google.android.material.circularreveal.CircularRevealWidget.RevealInfo;
import com.google.android.material.math.MathUtils;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

public class CircularRevealHelper {
    public static final int BITMAP_SHADER = 0;
    public static final int CLIP_PATH = 1;
    private static final boolean DEBUG = false;
    public static final int REVEAL_ANIMATOR = 2;
    public static final int STRATEGY;
    private boolean buildingCircularRevealCache;
    private Paint debugPaint;
    private final Delegate delegate;
    private boolean hasCircularRevealCache;
    private Drawable overlayDrawable;
    private RevealInfo revealInfo;
    private final Paint revealPaint = new Paint(7);
    private final Path revealPath = new Path();
    private final Paint scrimPaint;
    private final View view;

    interface Delegate {
        void actualDraw(Canvas canvas);

        boolean actualIsOpaque();
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface Strategy {
    }

    static {
        if (VERSION.SDK_INT >= 21) {
            STRATEGY = 2;
        } else if (VERSION.SDK_INT >= 18) {
            STRATEGY = 1;
        } else {
            STRATEGY = 0;
        }
    }

    public CircularRevealHelper(Delegate delegate2) {
        this.delegate = delegate2;
        View view2 = (View) delegate2;
        this.view = view2;
        view2.setWillNotDraw(false);
        Paint paint = new Paint(1);
        this.scrimPaint = paint;
        paint.setColor(0);
    }

    public void buildCircularRevealCache() {
        if (STRATEGY == 0) {
            this.buildingCircularRevealCache = true;
            this.hasCircularRevealCache = false;
            this.view.buildDrawingCache();
            Bitmap bitmap = this.view.getDrawingCache();
            if (!(bitmap != null || this.view.getWidth() == 0 || this.view.getHeight() == 0)) {
                bitmap = Bitmap.createBitmap(this.view.getWidth(), this.view.getHeight(), Config.ARGB_8888);
                this.view.draw(new Canvas(bitmap));
            }
            if (bitmap != null) {
                this.revealPaint.setShader(new BitmapShader(bitmap, TileMode.CLAMP, TileMode.CLAMP));
            }
            this.buildingCircularRevealCache = false;
            this.hasCircularRevealCache = true;
        }
    }

    public void destroyCircularRevealCache() {
        if (STRATEGY == 0) {
            this.hasCircularRevealCache = false;
            this.view.destroyDrawingCache();
            this.revealPaint.setShader(null);
            this.view.invalidate();
        }
    }

    public void setRevealInfo(RevealInfo revealInfo2) {
        if (revealInfo2 == null) {
            this.revealInfo = null;
        } else {
            RevealInfo revealInfo3 = this.revealInfo;
            if (revealInfo3 == null) {
                this.revealInfo = new RevealInfo(revealInfo2);
            } else {
                revealInfo3.set(revealInfo2);
            }
            if (MathUtils.geq(revealInfo2.radius, getDistanceToFurthestCorner(revealInfo2), 1.0E-4f)) {
                this.revealInfo.radius = Float.MAX_VALUE;
            }
        }
        invalidateRevealInfo();
    }

    public RevealInfo getRevealInfo() {
        if (this.revealInfo == null) {
            return null;
        }
        RevealInfo revealInfo2 = new RevealInfo(this.revealInfo);
        if (revealInfo2.isInvalid()) {
            revealInfo2.radius = getDistanceToFurthestCorner(revealInfo2);
        }
        return revealInfo2;
    }

    public void setCircularRevealScrimColor(int color) {
        this.scrimPaint.setColor(color);
        this.view.invalidate();
    }

    public int getCircularRevealScrimColor() {
        return this.scrimPaint.getColor();
    }

    public Drawable getCircularRevealOverlayDrawable() {
        return this.overlayDrawable;
    }

    public void setCircularRevealOverlayDrawable(Drawable drawable) {
        this.overlayDrawable = drawable;
        this.view.invalidate();
    }

    private void invalidateRevealInfo() {
        if (STRATEGY == 1) {
            this.revealPath.rewind();
            RevealInfo revealInfo2 = this.revealInfo;
            if (revealInfo2 != null) {
                this.revealPath.addCircle(revealInfo2.centerX, this.revealInfo.centerY, this.revealInfo.radius, Direction.CW);
            }
        }
        this.view.invalidate();
    }

    private float getDistanceToFurthestCorner(RevealInfo revealInfo2) {
        return MathUtils.distanceToFurthestCorner(revealInfo2.centerX, revealInfo2.centerY, 0.0f, 0.0f, (float) this.view.getWidth(), (float) this.view.getHeight());
    }

    public void draw(Canvas canvas) {
        if (shouldDrawCircularReveal()) {
            int i = STRATEGY;
            if (i == 0) {
                canvas.drawCircle(this.revealInfo.centerX, this.revealInfo.centerY, this.revealInfo.radius, this.revealPaint);
                if (shouldDrawScrim()) {
                    canvas.drawCircle(this.revealInfo.centerX, this.revealInfo.centerY, this.revealInfo.radius, this.scrimPaint);
                }
            } else if (i == 1) {
                int count = canvas.save();
                canvas.clipPath(this.revealPath);
                this.delegate.actualDraw(canvas);
                if (shouldDrawScrim()) {
                    canvas.drawRect(0.0f, 0.0f, (float) this.view.getWidth(), (float) this.view.getHeight(), this.scrimPaint);
                }
                canvas.restoreToCount(count);
            } else if (i == 2) {
                this.delegate.actualDraw(canvas);
                if (shouldDrawScrim()) {
                    canvas.drawRect(0.0f, 0.0f, (float) this.view.getWidth(), (float) this.view.getHeight(), this.scrimPaint);
                }
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append("Unsupported strategy ");
                sb.append(STRATEGY);
                throw new IllegalStateException(sb.toString());
            }
        } else {
            this.delegate.actualDraw(canvas);
            if (shouldDrawScrim()) {
                canvas.drawRect(0.0f, 0.0f, (float) this.view.getWidth(), (float) this.view.getHeight(), this.scrimPaint);
            }
        }
        drawOverlayDrawable(canvas);
    }

    private void drawOverlayDrawable(Canvas canvas) {
        if (shouldDrawOverlayDrawable()) {
            Rect bounds = this.overlayDrawable.getBounds();
            float translationX = this.revealInfo.centerX - (((float) bounds.width()) / 2.0f);
            float translationY = this.revealInfo.centerY - (((float) bounds.height()) / 2.0f);
            canvas.translate(translationX, translationY);
            this.overlayDrawable.draw(canvas);
            canvas.translate(-translationX, -translationY);
        }
    }

    public boolean isOpaque() {
        return this.delegate.actualIsOpaque() && !shouldDrawCircularReveal();
    }

    private boolean shouldDrawCircularReveal() {
        RevealInfo revealInfo2 = this.revealInfo;
        boolean z = false;
        boolean invalidRevealInfo = revealInfo2 == null || revealInfo2.isInvalid();
        if (STRATEGY == 0) {
            if (!invalidRevealInfo && this.hasCircularRevealCache) {
                z = true;
            }
            return z;
        }
        if (!invalidRevealInfo) {
            z = true;
        }
        return z;
    }

    private boolean shouldDrawScrim() {
        return !this.buildingCircularRevealCache && Color.alpha(this.scrimPaint.getColor()) != 0;
    }

    private boolean shouldDrawOverlayDrawable() {
        return (this.buildingCircularRevealCache || this.overlayDrawable == null || this.revealInfo == null) ? false : true;
    }

    private void drawDebugMode(Canvas canvas) {
        this.delegate.actualDraw(canvas);
        if (shouldDrawScrim()) {
            canvas.drawCircle(this.revealInfo.centerX, this.revealInfo.centerY, this.revealInfo.radius, this.scrimPaint);
        }
        if (shouldDrawCircularReveal()) {
            drawDebugCircle(canvas, ViewCompat.MEASURED_STATE_MASK, 10.0f);
            drawDebugCircle(canvas, SupportMenu.CATEGORY_MASK, 5.0f);
        }
        drawOverlayDrawable(canvas);
    }

    private void drawDebugCircle(Canvas canvas, int color, float width) {
        this.debugPaint.setColor(color);
        this.debugPaint.setStrokeWidth(width);
        canvas.drawCircle(this.revealInfo.centerX, this.revealInfo.centerY, this.revealInfo.radius - (width / 2.0f), this.debugPaint);
    }
}
