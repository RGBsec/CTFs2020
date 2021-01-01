package androidx.transition;

import android.animation.LayoutTransition;
import android.util.Log;
import android.view.ViewGroup;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class ViewGroupUtilsApi14 {
    private static final int LAYOUT_TRANSITION_CHANGING = 4;
    private static final String TAG = "ViewGroupUtilsApi14";
    private static Method sCancelMethod;
    private static boolean sCancelMethodFetched;
    private static LayoutTransition sEmptyLayoutTransition;
    private static Field sLayoutSuppressedField;
    private static boolean sLayoutSuppressedFieldFetched;

    static void suppressLayout(ViewGroup group, boolean suppress) {
        if (sEmptyLayoutTransition == null) {
            C04071 r0 = new LayoutTransition() {
                public boolean isChangingLayout() {
                    return true;
                }
            };
            sEmptyLayoutTransition = r0;
            r0.setAnimator(2, null);
            sEmptyLayoutTransition.setAnimator(0, null);
            sEmptyLayoutTransition.setAnimator(1, null);
            sEmptyLayoutTransition.setAnimator(3, null);
            sEmptyLayoutTransition.setAnimator(4, null);
        }
        if (suppress) {
            LayoutTransition layoutTransition = group.getLayoutTransition();
            if (layoutTransition != null) {
                if (layoutTransition.isRunning()) {
                    cancelLayoutTransition(layoutTransition);
                }
                if (layoutTransition != sEmptyLayoutTransition) {
                    group.setTag(C0065R.C0067id.transition_layout_save, layoutTransition);
                }
            }
            group.setLayoutTransition(sEmptyLayoutTransition);
            return;
        }
        group.setLayoutTransition(null);
        boolean z = sLayoutSuppressedFieldFetched;
        String str = TAG;
        if (!z) {
            try {
                Field declaredField = ViewGroup.class.getDeclaredField("mLayoutSuppressed");
                sLayoutSuppressedField = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException e) {
                Log.i(str, "Failed to access mLayoutSuppressed field by reflection");
            }
            sLayoutSuppressedFieldFetched = true;
        }
        boolean layoutSuppressed = false;
        Field field = sLayoutSuppressedField;
        if (field != null) {
            try {
                layoutSuppressed = field.getBoolean(group);
                if (layoutSuppressed) {
                    sLayoutSuppressedField.setBoolean(group, false);
                }
            } catch (IllegalAccessException e2) {
                Log.i(str, "Failed to get mLayoutSuppressed field by reflection");
            }
        }
        if (layoutSuppressed) {
            group.requestLayout();
        }
        LayoutTransition layoutTransition2 = (LayoutTransition) group.getTag(C0065R.C0067id.transition_layout_save);
        if (layoutTransition2 != null) {
            group.setTag(C0065R.C0067id.transition_layout_save, null);
            group.setLayoutTransition(layoutTransition2);
        }
    }

    private static void cancelLayoutTransition(LayoutTransition t) {
        boolean z = sCancelMethodFetched;
        String str = "Failed to access cancel method by reflection";
        String str2 = TAG;
        if (!z) {
            try {
                Method declaredMethod = LayoutTransition.class.getDeclaredMethod("cancel", new Class[0]);
                sCancelMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.i(str2, str);
            }
            sCancelMethodFetched = true;
        }
        Method method = sCancelMethod;
        if (method != null) {
            try {
                method.invoke(t, new Object[0]);
            } catch (IllegalAccessException e2) {
                Log.i(str2, str);
            } catch (InvocationTargetException e3) {
                Log.i(str2, "Failed to invoke cancel method by reflection");
            }
        }
    }

    private ViewGroupUtilsApi14() {
    }
}
