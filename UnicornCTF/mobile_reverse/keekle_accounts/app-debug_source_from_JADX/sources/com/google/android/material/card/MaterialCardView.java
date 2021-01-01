package com.google.android.material.card;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.cardview.widget.CardView;
import com.google.android.material.C0078R;
import com.google.android.material.internal.ThemeEnforcement;

public class MaterialCardView extends CardView {
    private final MaterialCardViewHelper cardViewHelper;

    public MaterialCardView(Context context) {
        this(context, null);
    }

    public MaterialCardView(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.materialCardViewStyle);
    }

    public MaterialCardView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        TypedArray attributes = ThemeEnforcement.obtainStyledAttributes(context, attrs, C0078R.styleable.MaterialCardView, defStyleAttr, C0078R.style.Widget_MaterialComponents_CardView, new int[0]);
        MaterialCardViewHelper materialCardViewHelper = new MaterialCardViewHelper(this);
        this.cardViewHelper = materialCardViewHelper;
        materialCardViewHelper.loadFromAttributes(attributes);
        attributes.recycle();
    }

    public void setStrokeColor(int strokeColor) {
        this.cardViewHelper.setStrokeColor(strokeColor);
    }

    public int getStrokeColor() {
        return this.cardViewHelper.getStrokeColor();
    }

    public void setStrokeWidth(int strokeWidth) {
        this.cardViewHelper.setStrokeWidth(strokeWidth);
    }

    public int getStrokeWidth() {
        return this.cardViewHelper.getStrokeWidth();
    }

    public void setRadius(float radius) {
        super.setRadius(radius);
        this.cardViewHelper.updateForeground();
    }
}
