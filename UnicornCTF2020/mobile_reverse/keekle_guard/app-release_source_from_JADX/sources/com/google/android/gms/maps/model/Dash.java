package com.google.android.gms.maps.model;

public final class Dash extends PatternItem {
    public final float length;

    public Dash(float f) {
        super(0, Float.valueOf(Math.max(f, 0.0f)));
        this.length = Math.max(f, 0.0f);
    }

    public final String toString() {
        float f = this.length;
        StringBuilder sb = new StringBuilder(30);
        sb.append("[Dash: length=");
        sb.append(f);
        sb.append("]");
        return sb.toString();
    }
}
