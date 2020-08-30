package com.google.android.material.button;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Log;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.AppCompatButton;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.ViewCompat;
import androidx.core.widget.TextViewCompat;
import com.google.android.material.C0078R;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

public class MaterialButton extends AppCompatButton {
    public static final int ICON_GRAVITY_START = 1;
    public static final int ICON_GRAVITY_TEXT_START = 2;
    private static final String LOG_TAG = "MaterialButton";
    private Drawable icon;
    private int iconGravity;
    private int iconLeft;
    private int iconPadding;
    private int iconSize;
    private ColorStateList iconTint;
    private Mode iconTintMode;
    private final MaterialButtonHelper materialButtonHelper;

    @Retention(RetentionPolicy.SOURCE)
    public @interface IconGravity {
    }

    public MaterialButton(Context context) {
        this(context, null);
    }

    public MaterialButton(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.materialButtonStyle);
    }

    public MaterialButton(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        TypedArray attributes = ThemeEnforcement.obtainStyledAttributes(context, attrs, C0078R.styleable.MaterialButton, defStyleAttr, C0078R.style.Widget_MaterialComponents_Button, new int[0]);
        this.iconPadding = attributes.getDimensionPixelSize(C0078R.styleable.MaterialButton_iconPadding, 0);
        this.iconTintMode = ViewUtils.parseTintMode(attributes.getInt(C0078R.styleable.MaterialButton_iconTintMode, -1), Mode.SRC_IN);
        this.iconTint = MaterialResources.getColorStateList(getContext(), attributes, C0078R.styleable.MaterialButton_iconTint);
        this.icon = MaterialResources.getDrawable(getContext(), attributes, C0078R.styleable.MaterialButton_icon);
        this.iconGravity = attributes.getInteger(C0078R.styleable.MaterialButton_iconGravity, 1);
        this.iconSize = attributes.getDimensionPixelSize(C0078R.styleable.MaterialButton_iconSize, 0);
        MaterialButtonHelper materialButtonHelper2 = new MaterialButtonHelper(this);
        this.materialButtonHelper = materialButtonHelper2;
        materialButtonHelper2.loadFromAttributes(attributes);
        attributes.recycle();
        setCompoundDrawablePadding(this.iconPadding);
        updateIcon();
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (VERSION.SDK_INT < 21 && isUsingOriginalBackground()) {
            this.materialButtonHelper.drawStroke(canvas);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList tint) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setSupportBackgroundTintList(tint);
        } else if (this.materialButtonHelper != null) {
            super.setSupportBackgroundTintList(tint);
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getSupportBackgroundTintList();
        }
        return super.getSupportBackgroundTintList();
    }

    public void setSupportBackgroundTintMode(Mode tintMode) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setSupportBackgroundTintMode(tintMode);
        } else if (this.materialButtonHelper != null) {
            super.setSupportBackgroundTintMode(tintMode);
        }
    }

    public Mode getSupportBackgroundTintMode() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getSupportBackgroundTintMode();
        }
        return super.getSupportBackgroundTintMode();
    }

    public void setBackgroundTintList(ColorStateList tintList) {
        setSupportBackgroundTintList(tintList);
    }

    public ColorStateList getBackgroundTintList() {
        return getSupportBackgroundTintList();
    }

    public void setBackgroundTintMode(Mode tintMode) {
        setSupportBackgroundTintMode(tintMode);
    }

    public Mode getBackgroundTintMode() {
        return getSupportBackgroundTintMode();
    }

    public void setBackgroundColor(int color) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setBackgroundColor(color);
        } else {
            super.setBackgroundColor(color);
        }
    }

    public void setBackground(Drawable background) {
        setBackgroundDrawable(background);
    }

    public void setBackgroundResource(int backgroundResourceId) {
        Drawable background = null;
        if (backgroundResourceId != 0) {
            background = AppCompatResources.getDrawable(getContext(), backgroundResourceId);
        }
        setBackgroundDrawable(background);
    }

    public void setBackgroundDrawable(Drawable background) {
        if (!isUsingOriginalBackground()) {
            super.setBackgroundDrawable(background);
        } else if (background != getBackground()) {
            Log.i(LOG_TAG, "Setting a custom background is not supported.");
            this.materialButtonHelper.setBackgroundOverwritten();
            super.setBackgroundDrawable(background);
        } else {
            getBackground().setState(background.getState());
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        if (VERSION.SDK_INT == 21) {
            MaterialButtonHelper materialButtonHelper2 = this.materialButtonHelper;
            if (materialButtonHelper2 != null) {
                materialButtonHelper2.updateMaskBounds(bottom - top, right - left);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        if (this.icon != null && this.iconGravity == 2) {
            int textWidth = (int) getPaint().measureText(getText().toString());
            int localIconSize = this.iconSize;
            if (localIconSize == 0) {
                localIconSize = this.icon.getIntrinsicWidth();
            }
            int newIconLeft = (((((getMeasuredWidth() - textWidth) - ViewCompat.getPaddingEnd(this)) - localIconSize) - this.iconPadding) - ViewCompat.getPaddingStart(this)) / 2;
            if (isLayoutRTL()) {
                newIconLeft = -newIconLeft;
            }
            if (this.iconLeft != newIconLeft) {
                this.iconLeft = newIconLeft;
                updateIcon();
            }
        }
    }

    private boolean isLayoutRTL() {
        return ViewCompat.getLayoutDirection(this) == 1;
    }

    /* access modifiers changed from: 0000 */
    public void setInternalBackground(Drawable background) {
        super.setBackgroundDrawable(background);
    }

    public void setIconPadding(int iconPadding2) {
        if (this.iconPadding != iconPadding2) {
            this.iconPadding = iconPadding2;
            setCompoundDrawablePadding(iconPadding2);
        }
    }

    public int getIconPadding() {
        return this.iconPadding;
    }

    public void setIconSize(int iconSize2) {
        if (iconSize2 < 0) {
            throw new IllegalArgumentException("iconSize cannot be less than 0");
        } else if (this.iconSize != iconSize2) {
            this.iconSize = iconSize2;
            updateIcon();
        }
    }

    public int getIconSize() {
        return this.iconSize;
    }

    public void setIcon(Drawable icon2) {
        if (this.icon != icon2) {
            this.icon = icon2;
            updateIcon();
        }
    }

    public void setIconResource(int iconResourceId) {
        Drawable icon2 = null;
        if (iconResourceId != 0) {
            icon2 = AppCompatResources.getDrawable(getContext(), iconResourceId);
        }
        setIcon(icon2);
    }

    public Drawable getIcon() {
        return this.icon;
    }

    public void setIconTint(ColorStateList iconTint2) {
        if (this.iconTint != iconTint2) {
            this.iconTint = iconTint2;
            updateIcon();
        }
    }

    public void setIconTintResource(int iconTintResourceId) {
        setIconTint(AppCompatResources.getColorStateList(getContext(), iconTintResourceId));
    }

    public ColorStateList getIconTint() {
        return this.iconTint;
    }

    public void setIconTintMode(Mode iconTintMode2) {
        if (this.iconTintMode != iconTintMode2) {
            this.iconTintMode = iconTintMode2;
            updateIcon();
        }
    }

    public Mode getIconTintMode() {
        return this.iconTintMode;
    }

    private void updateIcon() {
        Drawable drawable = this.icon;
        if (drawable != null) {
            Drawable mutate = drawable.mutate();
            this.icon = mutate;
            DrawableCompat.setTintList(mutate, this.iconTint);
            Mode mode = this.iconTintMode;
            if (mode != null) {
                DrawableCompat.setTintMode(this.icon, mode);
            }
            int width = this.iconSize;
            if (width == 0) {
                width = this.icon.getIntrinsicWidth();
            }
            int height = this.iconSize;
            if (height == 0) {
                height = this.icon.getIntrinsicHeight();
            }
            Drawable drawable2 = this.icon;
            int i = this.iconLeft;
            drawable2.setBounds(i, 0, i + width, height);
        }
        TextViewCompat.setCompoundDrawablesRelative(this, this.icon, null, null, null);
    }

    public void setRippleColor(ColorStateList rippleColor) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setRippleColor(rippleColor);
        }
    }

    public void setRippleColorResource(int rippleColorResourceId) {
        if (isUsingOriginalBackground()) {
            setRippleColor(AppCompatResources.getColorStateList(getContext(), rippleColorResourceId));
        }
    }

    public ColorStateList getRippleColor() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getRippleColor();
        }
        return null;
    }

    public void setStrokeColor(ColorStateList strokeColor) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setStrokeColor(strokeColor);
        }
    }

    public void setStrokeColorResource(int strokeColorResourceId) {
        if (isUsingOriginalBackground()) {
            setStrokeColor(AppCompatResources.getColorStateList(getContext(), strokeColorResourceId));
        }
    }

    public ColorStateList getStrokeColor() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getStrokeColor();
        }
        return null;
    }

    public void setStrokeWidth(int strokeWidth) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setStrokeWidth(strokeWidth);
        }
    }

    public void setStrokeWidthResource(int strokeWidthResourceId) {
        if (isUsingOriginalBackground()) {
            setStrokeWidth(getResources().getDimensionPixelSize(strokeWidthResourceId));
        }
    }

    public int getStrokeWidth() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getStrokeWidth();
        }
        return 0;
    }

    public void setCornerRadius(int cornerRadius) {
        if (isUsingOriginalBackground()) {
            this.materialButtonHelper.setCornerRadius(cornerRadius);
        }
    }

    public void setCornerRadiusResource(int cornerRadiusResourceId) {
        if (isUsingOriginalBackground()) {
            setCornerRadius(getResources().getDimensionPixelSize(cornerRadiusResourceId));
        }
    }

    public int getCornerRadius() {
        if (isUsingOriginalBackground()) {
            return this.materialButtonHelper.getCornerRadius();
        }
        return 0;
    }

    public int getIconGravity() {
        return this.iconGravity;
    }

    public void setIconGravity(int iconGravity2) {
        this.iconGravity = iconGravity2;
    }

    private boolean isUsingOriginalBackground() {
        MaterialButtonHelper materialButtonHelper2 = this.materialButtonHelper;
        return materialButtonHelper2 != null && !materialButtonHelper2.isBackgroundOverwritten();
    }
}
