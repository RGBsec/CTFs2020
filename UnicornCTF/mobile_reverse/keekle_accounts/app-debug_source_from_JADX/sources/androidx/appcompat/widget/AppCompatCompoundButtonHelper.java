package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.content.res.Resources.NotFoundException;
import android.content.res.TypedArray;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.widget.CompoundButton;
import androidx.appcompat.C0003R;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.widget.CompoundButtonCompat;

class AppCompatCompoundButtonHelper {
    private ColorStateList mButtonTintList = null;
    private Mode mButtonTintMode = null;
    private boolean mHasButtonTint = false;
    private boolean mHasButtonTintMode = false;
    private boolean mSkipNextApply;
    private final CompoundButton mView;

    interface DirectSetButtonDrawableInterface {
        void setButtonDrawable(Drawable drawable);
    }

    AppCompatCompoundButtonHelper(CompoundButton view) {
        this.mView = view;
    }

    /* access modifiers changed from: 0000 */
    public void loadFromAttributes(AttributeSet attrs, int defStyleAttr) {
        TypedArray a = this.mView.getContext().obtainStyledAttributes(attrs, C0003R.styleable.CompoundButton, defStyleAttr, 0);
        boolean buttonDrawableLoaded = false;
        try {
            if (a.hasValue(C0003R.styleable.CompoundButton_buttonCompat)) {
                int resourceId = a.getResourceId(C0003R.styleable.CompoundButton_buttonCompat, 0);
                if (resourceId != 0) {
                    try {
                        this.mView.setButtonDrawable(AppCompatResources.getDrawable(this.mView.getContext(), resourceId));
                        buttonDrawableLoaded = true;
                    } catch (NotFoundException e) {
                    }
                }
            }
            if (!buttonDrawableLoaded) {
                if (a.hasValue(C0003R.styleable.CompoundButton_android_button)) {
                    int resourceId2 = a.getResourceId(C0003R.styleable.CompoundButton_android_button, 0);
                    if (resourceId2 != 0) {
                        this.mView.setButtonDrawable(AppCompatResources.getDrawable(this.mView.getContext(), resourceId2));
                    }
                }
            }
            if (a.hasValue(C0003R.styleable.CompoundButton_buttonTint)) {
                CompoundButtonCompat.setButtonTintList(this.mView, a.getColorStateList(C0003R.styleable.CompoundButton_buttonTint));
            }
            if (a.hasValue(C0003R.styleable.CompoundButton_buttonTintMode)) {
                CompoundButtonCompat.setButtonTintMode(this.mView, DrawableUtils.parseTintMode(a.getInt(C0003R.styleable.CompoundButton_buttonTintMode, -1), null));
            }
        } finally {
            a.recycle();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setSupportButtonTintList(ColorStateList tint) {
        this.mButtonTintList = tint;
        this.mHasButtonTint = true;
        applyButtonTint();
    }

    /* access modifiers changed from: 0000 */
    public ColorStateList getSupportButtonTintList() {
        return this.mButtonTintList;
    }

    /* access modifiers changed from: 0000 */
    public void setSupportButtonTintMode(Mode tintMode) {
        this.mButtonTintMode = tintMode;
        this.mHasButtonTintMode = true;
        applyButtonTint();
    }

    /* access modifiers changed from: 0000 */
    public Mode getSupportButtonTintMode() {
        return this.mButtonTintMode;
    }

    /* access modifiers changed from: 0000 */
    public void onSetButtonDrawable() {
        if (this.mSkipNextApply) {
            this.mSkipNextApply = false;
            return;
        }
        this.mSkipNextApply = true;
        applyButtonTint();
    }

    /* access modifiers changed from: 0000 */
    public void applyButtonTint() {
        Drawable buttonDrawable = CompoundButtonCompat.getButtonDrawable(this.mView);
        if (buttonDrawable == null) {
            return;
        }
        if (this.mHasButtonTint || this.mHasButtonTintMode) {
            Drawable buttonDrawable2 = DrawableCompat.wrap(buttonDrawable).mutate();
            if (this.mHasButtonTint) {
                DrawableCompat.setTintList(buttonDrawable2, this.mButtonTintList);
            }
            if (this.mHasButtonTintMode) {
                DrawableCompat.setTintMode(buttonDrawable2, this.mButtonTintMode);
            }
            if (buttonDrawable2.isStateful()) {
                buttonDrawable2.setState(this.mView.getDrawableState());
            }
            this.mView.setButtonDrawable(buttonDrawable2);
        }
    }

    /* access modifiers changed from: 0000 */
    public int getCompoundPaddingLeft(int superValue) {
        if (VERSION.SDK_INT >= 17) {
            return superValue;
        }
        Drawable buttonDrawable = CompoundButtonCompat.getButtonDrawable(this.mView);
        if (buttonDrawable != null) {
            return superValue + buttonDrawable.getIntrinsicWidth();
        }
        return superValue;
    }
}
