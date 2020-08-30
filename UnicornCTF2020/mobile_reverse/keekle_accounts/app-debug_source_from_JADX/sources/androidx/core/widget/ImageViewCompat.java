package androidx.core.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.widget.ImageView;

public class ImageViewCompat {
    public static ColorStateList getImageTintList(ImageView view) {
        if (VERSION.SDK_INT >= 21) {
            return view.getImageTintList();
        }
        return view instanceof TintableImageSourceView ? ((TintableImageSourceView) view).getSupportImageTintList() : null;
    }

    public static void setImageTintList(ImageView view, ColorStateList tintList) {
        if (VERSION.SDK_INT >= 21) {
            view.setImageTintList(tintList);
            if (VERSION.SDK_INT == 21) {
                Drawable imageViewDrawable = view.getDrawable();
                if (imageViewDrawable != null && view.getImageTintList() != null) {
                    if (imageViewDrawable.isStateful()) {
                        imageViewDrawable.setState(view.getDrawableState());
                    }
                    view.setImageDrawable(imageViewDrawable);
                }
            }
        } else if (view instanceof TintableImageSourceView) {
            ((TintableImageSourceView) view).setSupportImageTintList(tintList);
        }
    }

    public static Mode getImageTintMode(ImageView view) {
        if (VERSION.SDK_INT >= 21) {
            return view.getImageTintMode();
        }
        return view instanceof TintableImageSourceView ? ((TintableImageSourceView) view).getSupportImageTintMode() : null;
    }

    public static void setImageTintMode(ImageView view, Mode mode) {
        if (VERSION.SDK_INT >= 21) {
            view.setImageTintMode(mode);
            if (VERSION.SDK_INT == 21) {
                Drawable imageViewDrawable = view.getDrawable();
                if (imageViewDrawable != null && view.getImageTintList() != null) {
                    if (imageViewDrawable.isStateful()) {
                        imageViewDrawable.setState(view.getDrawableState());
                    }
                    view.setImageDrawable(imageViewDrawable);
                }
            }
        } else if (view instanceof TintableImageSourceView) {
            ((TintableImageSourceView) view).setSupportImageTintMode(mode);
        }
    }

    private ImageViewCompat() {
    }
}
