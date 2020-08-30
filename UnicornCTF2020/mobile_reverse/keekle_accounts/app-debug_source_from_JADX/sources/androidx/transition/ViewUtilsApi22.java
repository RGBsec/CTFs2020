package androidx.transition;

import android.util.Log;
import android.view.View;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class ViewUtilsApi22 extends ViewUtilsApi21 {
    private static final String TAG = "ViewUtilsApi22";
    private static Method sSetLeftTopRightBottomMethod;
    private static boolean sSetLeftTopRightBottomMethodFetched;

    ViewUtilsApi22() {
    }

    public void setLeftTopRightBottom(View v, int left, int top, int right, int bottom) {
        fetchSetLeftTopRightBottomMethod();
        Method method = sSetLeftTopRightBottomMethod;
        if (method != null) {
            try {
                method.invoke(v, new Object[]{Integer.valueOf(left), Integer.valueOf(top), Integer.valueOf(right), Integer.valueOf(bottom)});
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException e2) {
                throw new RuntimeException(e2.getCause());
            }
        }
    }

    private void fetchSetLeftTopRightBottomMethod() {
        if (!sSetLeftTopRightBottomMethodFetched) {
            try {
                Method declaredMethod = View.class.getDeclaredMethod("setLeftTopRightBottom", new Class[]{Integer.TYPE, Integer.TYPE, Integer.TYPE, Integer.TYPE});
                sSetLeftTopRightBottomMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.i(TAG, "Failed to retrieve setLeftTopRightBottom method", e);
            }
            sSetLeftTopRightBottomMethodFetched = true;
        }
    }
}
