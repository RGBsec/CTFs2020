package androidx.appcompat.widget;

import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.graphics.drawable.DrawableContainer;
import android.graphics.drawable.DrawableContainer.DrawableContainerState;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.ScaleDrawable;
import android.os.Build.VERSION;
import androidx.appcompat.graphics.drawable.DrawableWrapper;
import androidx.core.graphics.drawable.WrappedDrawable;

public class DrawableUtils {
    private static final int[] CHECKED_STATE_SET = {16842912};
    private static final int[] EMPTY_STATE_SET = new int[0];
    public static final Rect INSETS_NONE = new Rect();
    private static final String TAG = "DrawableUtils";
    private static final String VECTOR_DRAWABLE_CLAZZ_NAME = "android.graphics.drawable.VectorDrawable";
    private static Class<?> sInsetsClazz;

    static {
        if (VERSION.SDK_INT >= 18) {
            try {
                sInsetsClazz = Class.forName("android.graphics.Insets");
            } catch (ClassNotFoundException e) {
            }
        }
    }

    private DrawableUtils() {
    }

    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static android.graphics.Rect getOpticalBounds(android.graphics.drawable.Drawable r14) {
        /*
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 29
            if (r0 < r1) goto L_0x0020
            android.graphics.Insets r0 = r14.getOpticalInsets()
            android.graphics.Rect r1 = new android.graphics.Rect
            r1.<init>()
            int r2 = r0.left
            r1.left = r2
            int r2 = r0.right
            r1.right = r2
            int r2 = r0.top
            r1.top = r2
            int r2 = r0.bottom
            r1.bottom = r2
            return r1
        L_0x0020:
            java.lang.Class<?> r0 = sInsetsClazz
            if (r0 == 0) goto L_0x00b8
            android.graphics.drawable.Drawable r0 = androidx.core.graphics.drawable.DrawableCompat.unwrap(r14)     // Catch:{ Exception -> 0x00b0 }
            r14 = r0
            java.lang.Class r0 = r14.getClass()     // Catch:{ Exception -> 0x00b0 }
            java.lang.String r1 = "getOpticalInsets"
            r2 = 0
            java.lang.Class[] r3 = new java.lang.Class[r2]     // Catch:{ Exception -> 0x00b0 }
            java.lang.reflect.Method r0 = r0.getMethod(r1, r3)     // Catch:{ Exception -> 0x00b0 }
            java.lang.Object[] r1 = new java.lang.Object[r2]     // Catch:{ Exception -> 0x00b0 }
            java.lang.Object r1 = r0.invoke(r14, r1)     // Catch:{ Exception -> 0x00b0 }
            if (r1 == 0) goto L_0x00af
            android.graphics.Rect r3 = new android.graphics.Rect     // Catch:{ Exception -> 0x00b0 }
            r3.<init>()     // Catch:{ Exception -> 0x00b0 }
            java.lang.Class<?> r4 = sInsetsClazz     // Catch:{ Exception -> 0x00b0 }
            java.lang.reflect.Field[] r4 = r4.getFields()     // Catch:{ Exception -> 0x00b0 }
            int r5 = r4.length     // Catch:{ Exception -> 0x00b0 }
            r6 = r2
        L_0x004b:
            if (r6 >= r5) goto L_0x00ae
            r7 = r4[r6]     // Catch:{ Exception -> 0x00b0 }
            java.lang.String r8 = r7.getName()     // Catch:{ Exception -> 0x00b0 }
            r9 = -1
            int r10 = r8.hashCode()     // Catch:{ Exception -> 0x00b0 }
            r11 = 3
            r12 = 2
            r13 = 1
            switch(r10) {
                case -1383228885: goto L_0x007d;
                case 115029: goto L_0x0073;
                case 3317767: goto L_0x0069;
                case 108511772: goto L_0x005f;
                default: goto L_0x005e;
            }     // Catch:{ Exception -> 0x00b0 }
        L_0x005e:
            goto L_0x0086
        L_0x005f:
            java.lang.String r10 = "right"
            boolean r8 = r8.equals(r10)     // Catch:{ Exception -> 0x00b0 }
            if (r8 == 0) goto L_0x005e
            r9 = r12
            goto L_0x0086
        L_0x0069:
            java.lang.String r10 = "left"
            boolean r8 = r8.equals(r10)     // Catch:{ Exception -> 0x00b0 }
            if (r8 == 0) goto L_0x005e
            r9 = r2
            goto L_0x0086
        L_0x0073:
            java.lang.String r10 = "top"
            boolean r8 = r8.equals(r10)     // Catch:{ Exception -> 0x00b0 }
            if (r8 == 0) goto L_0x005e
            r9 = r13
            goto L_0x0086
        L_0x007d:
            java.lang.String r10 = "bottom"
            boolean r8 = r8.equals(r10)     // Catch:{ Exception -> 0x00b0 }
            if (r8 == 0) goto L_0x005e
            r9 = r11
        L_0x0086:
            if (r9 == 0) goto L_0x00a4
            if (r9 == r13) goto L_0x009d
            if (r9 == r12) goto L_0x0096
            if (r9 == r11) goto L_0x008f
            goto L_0x00ab
        L_0x008f:
            int r8 = r7.getInt(r1)     // Catch:{ Exception -> 0x00b0 }
            r3.bottom = r8     // Catch:{ Exception -> 0x00b0 }
            goto L_0x00ab
        L_0x0096:
            int r8 = r7.getInt(r1)     // Catch:{ Exception -> 0x00b0 }
            r3.right = r8     // Catch:{ Exception -> 0x00b0 }
            goto L_0x00ab
        L_0x009d:
            int r8 = r7.getInt(r1)     // Catch:{ Exception -> 0x00b0 }
            r3.top = r8     // Catch:{ Exception -> 0x00b0 }
            goto L_0x00ab
        L_0x00a4:
            int r8 = r7.getInt(r1)     // Catch:{ Exception -> 0x00b0 }
            r3.left = r8     // Catch:{ Exception -> 0x00b0 }
        L_0x00ab:
            int r6 = r6 + 1
            goto L_0x004b
        L_0x00ae:
            return r3
        L_0x00af:
            goto L_0x00b8
        L_0x00b0:
            r0 = move-exception
            java.lang.String r1 = "DrawableUtils"
            java.lang.String r2 = "Couldn't obtain the optical insets. Ignoring."
            android.util.Log.e(r1, r2)
        L_0x00b8:
            android.graphics.Rect r0 = INSETS_NONE
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.DrawableUtils.getOpticalBounds(android.graphics.drawable.Drawable):android.graphics.Rect");
    }

    static void fixDrawable(Drawable drawable) {
        if (VERSION.SDK_INT == 21) {
            if (VECTOR_DRAWABLE_CLAZZ_NAME.equals(drawable.getClass().getName())) {
                fixVectorDrawableTinting(drawable);
            }
        }
    }

    public static boolean canSafelyMutateDrawable(Drawable drawable) {
        if (VERSION.SDK_INT < 15 && (drawable instanceof InsetDrawable)) {
            return false;
        }
        if (VERSION.SDK_INT < 15 && (drawable instanceof GradientDrawable)) {
            return false;
        }
        if (VERSION.SDK_INT < 17 && (drawable instanceof LayerDrawable)) {
            return false;
        }
        if (drawable instanceof DrawableContainer) {
            ConstantState state = drawable.getConstantState();
            if (state instanceof DrawableContainerState) {
                for (Drawable child : ((DrawableContainerState) state).getChildren()) {
                    if (!canSafelyMutateDrawable(child)) {
                        return false;
                    }
                }
            }
        } else if (drawable instanceof WrappedDrawable) {
            return canSafelyMutateDrawable(((WrappedDrawable) drawable).getWrappedDrawable());
        } else {
            if (drawable instanceof DrawableWrapper) {
                return canSafelyMutateDrawable(((DrawableWrapper) drawable).getWrappedDrawable());
            }
            if (drawable instanceof ScaleDrawable) {
                return canSafelyMutateDrawable(((ScaleDrawable) drawable).getDrawable());
            }
        }
        return true;
    }

    private static void fixVectorDrawableTinting(Drawable drawable) {
        int[] originalState = drawable.getState();
        if (originalState == null || originalState.length == 0) {
            drawable.setState(CHECKED_STATE_SET);
        } else {
            drawable.setState(EMPTY_STATE_SET);
        }
        drawable.setState(originalState);
    }

    public static Mode parseTintMode(int value, Mode defaultMode) {
        if (value == 3) {
            return Mode.SRC_OVER;
        }
        if (value == 5) {
            return Mode.SRC_IN;
        }
        if (value == 9) {
            return Mode.SRC_ATOP;
        }
        switch (value) {
            case 14:
                return Mode.MULTIPLY;
            case 15:
                return Mode.SCREEN;
            case 16:
                return Mode.ADD;
            default:
                return defaultMode;
        }
    }
}
