package androidx.transition;

import android.util.Log;
import android.view.ViewGroup;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class ViewGroupUtilsApi18 {
    private static final String TAG = "ViewUtilsApi18";
    private static Method sSuppressLayoutMethod;
    private static boolean sSuppressLayoutMethodFetched;

    static void suppressLayout(ViewGroup group, boolean suppress) {
        String str = TAG;
        fetchSuppressLayoutMethod();
        Method method = sSuppressLayoutMethod;
        if (method != null) {
            try {
                method.invoke(group, new Object[]{Boolean.valueOf(suppress)});
            } catch (IllegalAccessException e) {
                Log.i(str, "Failed to invoke suppressLayout method", e);
            } catch (InvocationTargetException e2) {
                Log.i(str, "Error invoking suppressLayout method", e2);
            }
        }
    }

    private static void fetchSuppressLayoutMethod() {
        if (!sSuppressLayoutMethodFetched) {
            try {
                Method declaredMethod = ViewGroup.class.getDeclaredMethod("suppressLayout", new Class[]{Boolean.TYPE});
                sSuppressLayoutMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.i(TAG, "Failed to retrieve suppressLayout method", e);
            }
            sSuppressLayoutMethodFetched = true;
        }
    }

    private ViewGroupUtilsApi18() {
    }
}
