package androidx.fragment.app;

import androidx.collection.SimpleArrayMap;
import androidx.fragment.app.Fragment.InstantiationException;
import java.lang.reflect.InvocationTargetException;

public class FragmentFactory {
    private static final SimpleArrayMap<String, Class<?>> sClassMap = new SimpleArrayMap<>();

    private static Class<?> loadClass(ClassLoader classLoader, String className) throws ClassNotFoundException {
        Class<?> clazz = (Class) sClassMap.get(className);
        if (clazz != null) {
            return clazz;
        }
        Class<?> clazz2 = Class.forName(className, false, classLoader);
        sClassMap.put(className, clazz2);
        return clazz2;
    }

    static boolean isFragmentClass(ClassLoader classLoader, String className) {
        try {
            return Fragment.class.isAssignableFrom(loadClass(classLoader, className));
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static Class<? extends Fragment> loadFragmentClass(ClassLoader classLoader, String className) {
        String str = "Unable to instantiate fragment ";
        try {
            return loadClass(classLoader, className);
        } catch (ClassNotFoundException e) {
            StringBuilder sb = new StringBuilder();
            sb.append(str);
            sb.append(className);
            sb.append(": make sure class name exists");
            throw new InstantiationException(sb.toString(), e);
        } catch (ClassCastException e2) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(str);
            sb2.append(className);
            sb2.append(": make sure class is a valid subclass of Fragment");
            throw new InstantiationException(sb2.toString(), e2);
        }
    }

    public Fragment instantiate(ClassLoader classLoader, String className) {
        String str = ": make sure class name exists, is public, and has an empty constructor that is public";
        String str2 = "Unable to instantiate fragment ";
        try {
            return (Fragment) loadFragmentClass(classLoader, className).getConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (InstantiationException e) {
            StringBuilder sb = new StringBuilder();
            sb.append(str2);
            sb.append(className);
            sb.append(str);
            throw new InstantiationException(sb.toString(), e);
        } catch (IllegalAccessException e2) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(str2);
            sb2.append(className);
            sb2.append(str);
            throw new InstantiationException(sb2.toString(), e2);
        } catch (NoSuchMethodException e3) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(str2);
            sb3.append(className);
            sb3.append(": could not find Fragment constructor");
            throw new InstantiationException(sb3.toString(), e3);
        } catch (InvocationTargetException e4) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append(str2);
            sb4.append(className);
            sb4.append(": calling Fragment constructor caused an exception");
            throw new InstantiationException(sb4.toString(), e4);
        }
    }
}
