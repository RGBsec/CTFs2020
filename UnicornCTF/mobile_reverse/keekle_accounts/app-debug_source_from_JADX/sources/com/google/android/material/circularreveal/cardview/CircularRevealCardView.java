package com.google.android.material.circularreveal.cardview;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import androidx.cardview.widget.CardView;
import com.google.android.material.circularreveal.CircularRevealHelper;
import com.google.android.material.circularreveal.CircularRevealWidget;
import com.google.android.material.circularreveal.CircularRevealWidget.RevealInfo;

public class CircularRevealCardView extends CardView implements CircularRevealWidget {
    private final CircularRevealHelper helper;

    public CircularRevealCardView(Context context) {
        this(context, null);
    }

    public CircularRevealCardView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.helper = new CircularRevealHelper(this);
    }

    public void buildCircularRevealCache() {
        this.helper.buildCircularRevealCache();
    }

    public void destroyCircularRevealCache() {
        this.helper.destroyCircularRevealCache();
    }

    public void setRevealInfo(RevealInfo revealInfo) {
        this.helper.setRevealInfo(revealInfo);
    }

    public RevealInfo getRevealInfo() {
        return this.helper.getRevealInfo();
    }

    public void setCircularRevealScrimColor(int color) {
        this.helper.setCircularRevealScrimColor(color);
    }

    public int getCircularRevealScrimColor() {
        return this.helper.getCircularRevealScrimColor();
    }

    public Drawable getCircularRevealOverlayDrawable() {
        return this.helper.getCircularRevealOverlayDrawable();
    }

    public void setCircularRevealOverlayDrawable(Drawable drawable) {
        this.helper.setCircularRevealOverlayDrawable(drawable);
    }

    public void draw(Canvas canvas) {
        CircularRevealHelper circularRevealHelper = this.helper;
        if (circularRevealHelper != null) {
            circularRevealHelper.draw(canvas);
        } else {
            super.draw(canvas);
        }
    }

    public void actualDraw(Canvas canvas) {
        super.draw(canvas);
    }

    public boolean isOpaque() {
        CircularRevealHelper circularRevealHelper = this.helper;
        if (circularRevealHelper != null) {
            return circularRevealHelper.isOpaque();
        }
        return super.isOpaque();
    }

    public boolean actualIsOpaque() {
        return super.isOpaque();
    }
}
