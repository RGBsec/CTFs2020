package com.google.android.material.circularreveal;

import android.animation.TypeEvaluator;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.util.Property;
import com.google.android.material.math.MathUtils;

public interface CircularRevealWidget extends Delegate {

    public static class CircularRevealEvaluator implements TypeEvaluator<RevealInfo> {
        public static final TypeEvaluator<RevealInfo> CIRCULAR_REVEAL = new CircularRevealEvaluator();
        private final RevealInfo revealInfo = new RevealInfo();

        public RevealInfo evaluate(float fraction, RevealInfo startValue, RevealInfo endValue) {
            this.revealInfo.set(MathUtils.lerp(startValue.centerX, endValue.centerX, fraction), MathUtils.lerp(startValue.centerY, endValue.centerY, fraction), MathUtils.lerp(startValue.radius, endValue.radius, fraction));
            return this.revealInfo;
        }
    }

    public static class CircularRevealProperty extends Property<CircularRevealWidget, RevealInfo> {
        public static final Property<CircularRevealWidget, RevealInfo> CIRCULAR_REVEAL = new CircularRevealProperty("circularReveal");

        private CircularRevealProperty(String name) {
            super(RevealInfo.class, name);
        }

        public RevealInfo get(CircularRevealWidget object) {
            return object.getRevealInfo();
        }

        public void set(CircularRevealWidget object, RevealInfo value) {
            object.setRevealInfo(value);
        }
    }

    public static class CircularRevealScrimColorProperty extends Property<CircularRevealWidget, Integer> {
        public static final Property<CircularRevealWidget, Integer> CIRCULAR_REVEAL_SCRIM_COLOR = new CircularRevealScrimColorProperty("circularRevealScrimColor");

        private CircularRevealScrimColorProperty(String name) {
            super(Integer.class, name);
        }

        public Integer get(CircularRevealWidget object) {
            return Integer.valueOf(object.getCircularRevealScrimColor());
        }

        public void set(CircularRevealWidget object, Integer value) {
            object.setCircularRevealScrimColor(value.intValue());
        }
    }

    public static class RevealInfo {
        public static final float INVALID_RADIUS = Float.MAX_VALUE;
        public float centerX;
        public float centerY;
        public float radius;

        private RevealInfo() {
        }

        public RevealInfo(float centerX2, float centerY2, float radius2) {
            this.centerX = centerX2;
            this.centerY = centerY2;
            this.radius = radius2;
        }

        public RevealInfo(RevealInfo other) {
            this(other.centerX, other.centerY, other.radius);
        }

        public void set(float centerX2, float centerY2, float radius2) {
            this.centerX = centerX2;
            this.centerY = centerY2;
            this.radius = radius2;
        }

        public void set(RevealInfo other) {
            set(other.centerX, other.centerY, other.radius);
        }

        public boolean isInvalid() {
            return this.radius == Float.MAX_VALUE;
        }
    }

    void buildCircularRevealCache();

    void destroyCircularRevealCache();

    void draw(Canvas canvas);

    Drawable getCircularRevealOverlayDrawable();

    int getCircularRevealScrimColor();

    RevealInfo getRevealInfo();

    boolean isOpaque();

    void setCircularRevealOverlayDrawable(Drawable drawable);

    void setCircularRevealScrimColor(int i);

    void setRevealInfo(RevealInfo revealInfo);
}
