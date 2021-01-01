package androidx.core.graphics.drawable;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.DrawableContainer;
import android.graphics.drawable.DrawableContainer.DrawableContainerState;
import android.graphics.drawable.InsetDrawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Log;
import java.io.IOException;
import java.lang.reflect.Method;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public final class DrawableCompat {
    private static final String TAG = "DrawableCompat";
    private static Method sGetLayoutDirectionMethod;
    private static boolean sGetLayoutDirectionMethodFetched;
    private static Method sSetLayoutDirectionMethod;
    private static boolean sSetLayoutDirectionMethodFetched;

    @Deprecated
    public static void jumpToCurrentState(Drawable drawable) {
        drawable.jumpToCurrentState();
    }

    public static void setAutoMirrored(Drawable drawable, boolean mirrored) {
        if (VERSION.SDK_INT >= 19) {
            drawable.setAutoMirrored(mirrored);
        }
    }

    public static boolean isAutoMirrored(Drawable drawable) {
        if (VERSION.SDK_INT >= 19) {
            return drawable.isAutoMirrored();
        }
        return false;
    }

    public static void setHotspot(Drawable drawable, float x, float y) {
        if (VERSION.SDK_INT >= 21) {
            drawable.setHotspot(x, y);
        }
    }

    public static void setHotspotBounds(Drawable drawable, int left, int top, int right, int bottom) {
        if (VERSION.SDK_INT >= 21) {
            drawable.setHotspotBounds(left, top, right, bottom);
        }
    }

    public static void setTint(Drawable drawable, int tint) {
        if (VERSION.SDK_INT >= 21) {
            drawable.setTint(tint);
        } else if (drawable instanceof TintAwareDrawable) {
            ((TintAwareDrawable) drawable).setTint(tint);
        }
    }

    public static void setTintList(Drawable drawable, ColorStateList tint) {
        if (VERSION.SDK_INT >= 21) {
            drawable.setTintList(tint);
        } else if (drawable instanceof TintAwareDrawable) {
            ((TintAwareDrawable) drawable).setTintList(tint);
        }
    }

    public static void setTintMode(Drawable drawable, Mode tintMode) {
        if (VERSION.SDK_INT >= 21) {
            drawable.setTintMode(tintMode);
        } else if (drawable instanceof TintAwareDrawable) {
            ((TintAwareDrawable) drawable).setTintMode(tintMode);
        }
    }

    public static int getAlpha(Drawable drawable) {
        if (VERSION.SDK_INT >= 19) {
            return drawable.getAlpha();
        }
        return 0;
    }

    public static void applyTheme(Drawable drawable, Theme theme) {
        if (VERSION.SDK_INT >= 21) {
            drawable.applyTheme(theme);
        }
    }

    public static boolean canApplyTheme(Drawable drawable) {
        if (VERSION.SDK_INT >= 21) {
            return drawable.canApplyTheme();
        }
        return false;
    }

    public static ColorFilter getColorFilter(Drawable drawable) {
        if (VERSION.SDK_INT >= 21) {
            return drawable.getColorFilter();
        }
        return null;
    }

    public static void clearColorFilter(Drawable drawable) {
        if (VERSION.SDK_INT >= 23) {
            drawable.clearColorFilter();
        } else if (VERSION.SDK_INT >= 21) {
            drawable.clearColorFilter();
            if (drawable instanceof InsetDrawable) {
                clearColorFilter(((InsetDrawable) drawable).getDrawable());
            } else if (drawable instanceof WrappedDrawable) {
                clearColorFilter(((WrappedDrawable) drawable).getWrappedDrawable());
            } else if (drawable instanceof DrawableContainer) {
                DrawableContainerState state = (DrawableContainerState) ((DrawableContainer) drawable).getConstantState();
                if (state != null) {
                    int count = state.getChildCount();
                    for (int i = 0; i < count; i++) {
                        Drawable child = state.getChild(i);
                        if (child != null) {
                            clearColorFilter(child);
                        }
                    }
                }
            }
        } else {
            drawable.clearColorFilter();
        }
    }

    public static void inflate(Drawable drawable, Resources res, XmlPullParser parser, AttributeSet attrs, Theme theme) throws XmlPullParserException, IOException {
        if (VERSION.SDK_INT >= 21) {
            drawable.inflate(res, parser, attrs, theme);
        } else {
            drawable.inflate(res, parser, attrs);
        }
    }

    public static Drawable wrap(Drawable drawable) {
        if (VERSION.SDK_INT >= 23) {
            return drawable;
        }
        if (VERSION.SDK_INT >= 21) {
            if (!(drawable instanceof TintAwareDrawable)) {
                return new WrappedDrawableApi21(drawable);
            }
            return drawable;
        } else if (!(drawable instanceof TintAwareDrawable)) {
            return new WrappedDrawableApi14(drawable);
        } else {
            return drawable;
        }
    }

    public static <T extends Drawable> T unwrap(Drawable drawable) {
        if (drawable instanceof WrappedDrawable) {
            return ((WrappedDrawable) drawable).getWrappedDrawable();
        }
        return drawable;
    }

    public static boolean setLayoutDirection(Drawable drawable, int layoutDirection) {
        if (VERSION.SDK_INT >= 23) {
            return drawable.setLayoutDirection(layoutDirection);
        }
        if (VERSION.SDK_INT < 17) {
            return false;
        }
        boolean z = sSetLayoutDirectionMethodFetched;
        String str = TAG;
        if (!z) {
            try {
                Method declaredMethod = Drawable.class.getDeclaredMethod("setLayoutDirection", new Class[]{Integer.TYPE});
                sSetLayoutDirectionMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.i(str, "Failed to retrieve setLayoutDirection(int) method", e);
            }
            sSetLayoutDirectionMethodFetched = true;
        }
        Method method = sSetLayoutDirectionMethod;
        if (method != null) {
            try {
                method.invoke(drawable, new Object[]{Integer.valueOf(layoutDirection)});
                return true;
            } catch (Exception e2) {
                Log.i(str, "Failed to invoke setLayoutDirection(int) via reflection", e2);
                sSetLayoutDirectionMethod = null;
            }
        }
        return false;
    }

    public static int getLayoutDirection(Drawable drawable) {
        if (VERSION.SDK_INT >= 23) {
            return drawable.getLayoutDirection();
        }
        if (VERSION.SDK_INT < 17) {
            return 0;
        }
        boolean z = sGetLayoutDirectionMethodFetched;
        String str = TAG;
        if (!z) {
            try {
                Method declaredMethod = Drawable.class.getDeclaredMethod("getLayoutDirection", new Class[0]);
                sGetLayoutDirectionMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.i(str, "Failed to retrieve getLayoutDirection() method", e);
            }
            sGetLayoutDirectionMethodFetched = true;
        }
        Method method = sGetLayoutDirectionMethod;
        if (method != null) {
            try {
                return ((Integer) method.invoke(drawable, new Object[0])).intValue();
            } catch (Exception e2) {
                Log.i(str, "Failed to invoke getLayoutDirection() via reflection", e2);
                sGetLayoutDirectionMethod = null;
            }
        }
        return 0;
    }

    private DrawableCompat() {
    }
}
