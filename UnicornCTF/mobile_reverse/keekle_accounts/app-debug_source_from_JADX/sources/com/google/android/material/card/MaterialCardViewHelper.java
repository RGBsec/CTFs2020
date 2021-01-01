package com.google.android.material.card;

import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import com.google.android.material.C0078R;

class MaterialCardViewHelper {
    private static final int DEFAULT_STROKE_VALUE = -1;
    private final MaterialCardView materialCardView;
    private int strokeColor;
    private int strokeWidth;

    public MaterialCardViewHelper(MaterialCardView card) {
        this.materialCardView = card;
    }

    public void loadFromAttributes(TypedArray attributes) {
        this.strokeColor = attributes.getColor(C0078R.styleable.MaterialCardView_strokeColor, -1);
        this.strokeWidth = attributes.getDimensionPixelSize(C0078R.styleable.MaterialCardView_strokeWidth, 0);
        updateForeground();
        adjustContentPadding();
    }

    /* access modifiers changed from: 0000 */
    public void setStrokeColor(int strokeColor2) {
        this.strokeColor = strokeColor2;
        updateForeground();
    }

    /* access modifiers changed from: 0000 */
    public int getStrokeColor() {
        return this.strokeColor;
    }

    /* access modifiers changed from: 0000 */
    public void setStrokeWidth(int strokeWidth2) {
        this.strokeWidth = strokeWidth2;
        updateForeground();
        adjustContentPadding();
    }

    /* access modifiers changed from: 0000 */
    public int getStrokeWidth() {
        return this.strokeWidth;
    }

    /* access modifiers changed from: 0000 */
    public void updateForeground() {
        this.materialCardView.setForeground(createForegroundDrawable());
    }

    private Drawable createForegroundDrawable() {
        GradientDrawable fgDrawable = new GradientDrawable();
        fgDrawable.setCornerRadius(this.materialCardView.getRadius());
        int i = this.strokeColor;
        if (i != -1) {
            fgDrawable.setStroke(this.strokeWidth, i);
        }
        return fgDrawable;
    }

    private void adjustContentPadding() {
        this.materialCardView.setContentPadding(this.materialCardView.getContentPaddingLeft() + this.strokeWidth, this.materialCardView.getContentPaddingTop() + this.strokeWidth, this.materialCardView.getContentPaddingRight() + this.strokeWidth, this.materialCardView.getContentPaddingBottom() + this.strokeWidth);
    }
}
