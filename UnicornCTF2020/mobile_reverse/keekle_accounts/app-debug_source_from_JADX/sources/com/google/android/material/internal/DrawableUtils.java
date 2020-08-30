package com.google.android.material.internal;

import android.graphics.drawable.Drawable.ConstantState;
import android.graphics.drawable.DrawableContainer;
import android.graphics.drawable.DrawableContainer.DrawableContainerState;
import android.util.Log;
import java.lang.reflect.Method;

public class DrawableUtils {
    private static final String LOG_TAG = "DrawableUtils";
    private static Method setConstantStateMethod;
    private static boolean setConstantStateMethodFetched;

    private DrawableUtils() {
    }

    public static boolean setContainerConstantState(DrawableContainer drawable, ConstantState constantState) {
        return setContainerConstantStateV9(drawable, constantState);
    }

    private static boolean setContainerConstantStateV9(DrawableContainer drawable, ConstantState constantState) {
        boolean z = setConstantStateMethodFetched;
        String str = LOG_TAG;
        if (!z) {
            try {
                Method declaredMethod = DrawableContainer.class.getDeclaredMethod("setConstantState", new Class[]{DrawableContainerState.class});
                setConstantStateMethod = declaredMethod;
                declaredMethod.setAccessible(true);
            } catch (NoSuchMethodException e) {
                Log.e(str, "Could not fetch setConstantState(). Oh well.");
            }
            setConstantStateMethodFetched = true;
        }
        Method method = setConstantStateMethod;
        if (method != null) {
            try {
                method.invoke(drawable, new Object[]{constantState});
                return true;
            } catch (Exception e2) {
                Log.e(str, "Could not invoke setConstantState(). Oh well.");
            }
        }
        return false;
    }
}
