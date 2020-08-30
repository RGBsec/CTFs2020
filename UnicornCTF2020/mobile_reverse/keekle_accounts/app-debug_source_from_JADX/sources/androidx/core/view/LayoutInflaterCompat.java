package androidx.core.view;

import android.content.Context;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.LayoutInflater.Factory;
import android.view.LayoutInflater.Factory2;
import android.view.View;
import java.lang.reflect.Field;

public final class LayoutInflaterCompat {
    private static final String TAG = "LayoutInflaterCompatHC";
    private static boolean sCheckedField;
    private static Field sLayoutInflaterFactory2Field;

    static class Factory2Wrapper implements Factory2 {
        final LayoutInflaterFactory mDelegateFactory;

        Factory2Wrapper(LayoutInflaterFactory delegateFactory) {
            this.mDelegateFactory = delegateFactory;
        }

        public View onCreateView(String name, Context context, AttributeSet attrs) {
            return this.mDelegateFactory.onCreateView(null, name, context, attrs);
        }

        public View onCreateView(View parent, String name, Context context, AttributeSet attributeSet) {
            return this.mDelegateFactory.onCreateView(parent, name, context, attributeSet);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(getClass().getName());
            sb.append("{");
            sb.append(this.mDelegateFactory);
            sb.append("}");
            return sb.toString();
        }
    }

    private static void forceSetFactory2(LayoutInflater inflater, Factory2 factory) {
        boolean z = sCheckedField;
        String str = "; inflation may have unexpected results.";
        String str2 = TAG;
        if (!z) {
            try {
                Field declaredField = LayoutInflater.class.getDeclaredField("mFactory2");
                sLayoutInflaterFactory2Field = declaredField;
                declaredField.setAccessible(true);
            } catch (NoSuchFieldException e) {
                StringBuilder sb = new StringBuilder();
                sb.append("forceSetFactory2 Could not find field 'mFactory2' on class ");
                sb.append(LayoutInflater.class.getName());
                sb.append(str);
                Log.e(str2, sb.toString(), e);
            }
            sCheckedField = true;
        }
        Field field = sLayoutInflaterFactory2Field;
        if (field != null) {
            try {
                field.set(inflater, factory);
            } catch (IllegalAccessException e2) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("forceSetFactory2 could not set the Factory2 on LayoutInflater ");
                sb2.append(inflater);
                sb2.append(str);
                Log.e(str2, sb2.toString(), e2);
            }
        }
    }

    private LayoutInflaterCompat() {
    }

    @Deprecated
    public static void setFactory(LayoutInflater inflater, LayoutInflaterFactory factory) {
        Factory2Wrapper factory2Wrapper = null;
        if (VERSION.SDK_INT >= 21) {
            if (factory != null) {
                factory2Wrapper = new Factory2Wrapper(factory);
            }
            inflater.setFactory2(factory2Wrapper);
            return;
        }
        if (factory != null) {
            factory2Wrapper = new Factory2Wrapper(factory);
        }
        Factory2 factory2 = factory2Wrapper;
        inflater.setFactory2(factory2);
        Factory f = inflater.getFactory();
        if (f instanceof Factory2) {
            forceSetFactory2(inflater, (Factory2) f);
        } else {
            forceSetFactory2(inflater, factory2);
        }
    }

    public static void setFactory2(LayoutInflater inflater, Factory2 factory) {
        inflater.setFactory2(factory);
        if (VERSION.SDK_INT < 21) {
            Factory f = inflater.getFactory();
            if (f instanceof Factory2) {
                forceSetFactory2(inflater, (Factory2) f);
            } else {
                forceSetFactory2(inflater, factory);
            }
        }
    }

    @Deprecated
    public static LayoutInflaterFactory getFactory(LayoutInflater inflater) {
        Factory factory = inflater.getFactory();
        if (factory instanceof Factory2Wrapper) {
            return ((Factory2Wrapper) factory).mDelegateFactory;
        }
        return null;
    }
}
