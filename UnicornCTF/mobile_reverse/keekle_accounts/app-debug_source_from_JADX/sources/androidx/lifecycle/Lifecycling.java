package androidx.lifecycle;

import androidx.lifecycle.Lifecycle.Event;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Lifecycling {
    private static final int GENERATED_CALLBACK = 2;
    private static final int REFLECTIVE_CALLBACK = 1;
    private static Map<Class, Integer> sCallbackCache = new HashMap();
    private static Map<Class, List<Constructor<? extends GeneratedAdapter>>> sClassToAdapters = new HashMap();

    @Deprecated
    static GenericLifecycleObserver getCallback(Object object) {
        final LifecycleEventObserver observer = lifecycleEventObserver(object);
        return new GenericLifecycleObserver() {
            public void onStateChanged(LifecycleOwner source, Event event) {
                observer.onStateChanged(source, event);
            }
        };
    }

    static LifecycleEventObserver lifecycleEventObserver(Object object) {
        boolean isLifecycleEventObserver = object instanceof LifecycleEventObserver;
        boolean isFullLifecycleObserver = object instanceof FullLifecycleObserver;
        if (isLifecycleEventObserver && isFullLifecycleObserver) {
            return new FullLifecycleObserverAdapter((FullLifecycleObserver) object, (LifecycleEventObserver) object);
        }
        if (isFullLifecycleObserver) {
            return new FullLifecycleObserverAdapter((FullLifecycleObserver) object, null);
        }
        if (isLifecycleEventObserver) {
            return (LifecycleEventObserver) object;
        }
        Class<?> klass = object.getClass();
        if (getObserverConstructorType(klass) != 2) {
            return new ReflectiveGenericLifecycleObserver(object);
        }
        List<Constructor<? extends GeneratedAdapter>> constructors = (List) sClassToAdapters.get(klass);
        if (constructors.size() == 1) {
            return new SingleGeneratedAdapterObserver(createGeneratedAdapter((Constructor) constructors.get(0), object));
        }
        GeneratedAdapter[] adapters = new GeneratedAdapter[constructors.size()];
        for (int i = 0; i < constructors.size(); i++) {
            adapters[i] = createGeneratedAdapter((Constructor) constructors.get(i), object);
        }
        return new CompositeGeneratedAdaptersObserver(adapters);
    }

    private static GeneratedAdapter createGeneratedAdapter(Constructor<? extends GeneratedAdapter> constructor, Object object) {
        try {
            return (GeneratedAdapter) constructor.newInstance(new Object[]{object});
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e2) {
            throw new RuntimeException(e2);
        } catch (InvocationTargetException e3) {
            throw new RuntimeException(e3);
        }
    }

    private static Constructor<? extends GeneratedAdapter> generatedConstructor(Class<?> klass) {
        String str;
        String str2;
        try {
            Package aPackage = klass.getPackage();
            String name = klass.getCanonicalName();
            String fullPackage = aPackage != null ? aPackage.getName() : "";
            if (fullPackage.isEmpty()) {
                str = name;
            } else {
                str = name.substring(fullPackage.length() + 1);
            }
            String adapterName = getAdapterName(str);
            if (fullPackage.isEmpty()) {
                str2 = adapterName;
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(fullPackage);
                sb.append(".");
                sb.append(adapterName);
                str2 = sb.toString();
            }
            Constructor<? extends GeneratedAdapter> constructor = Class.forName(str2).getDeclaredConstructor(new Class[]{klass});
            if (!constructor.isAccessible()) {
                constructor.setAccessible(true);
            }
            return constructor;
        } catch (ClassNotFoundException e) {
            return null;
        } catch (NoSuchMethodException e2) {
            throw new RuntimeException(e2);
        }
    }

    private static int getObserverConstructorType(Class<?> klass) {
        Integer callbackCache = (Integer) sCallbackCache.get(klass);
        if (callbackCache != null) {
            return callbackCache.intValue();
        }
        int type = resolveObserverCallbackType(klass);
        sCallbackCache.put(klass, Integer.valueOf(type));
        return type;
    }

    private static int resolveObserverCallbackType(Class<?> klass) {
        Class<?>[] interfaces;
        if (klass.getCanonicalName() == null) {
            return 1;
        }
        Constructor<? extends GeneratedAdapter> constructor = generatedConstructor(klass);
        if (constructor != null) {
            sClassToAdapters.put(klass, Collections.singletonList(constructor));
            return 2;
        } else if (ClassesInfoCache.sInstance.hasLifecycleMethods(klass)) {
            return 1;
        } else {
            Class<?> superclass = klass.getSuperclass();
            List<Constructor<? extends GeneratedAdapter>> adapterConstructors = null;
            if (isLifecycleParent(superclass)) {
                if (getObserverConstructorType(superclass) == 1) {
                    return 1;
                }
                adapterConstructors = new ArrayList<>((Collection) sClassToAdapters.get(superclass));
            }
            for (Class<?> intrface : klass.getInterfaces()) {
                if (isLifecycleParent(intrface)) {
                    if (getObserverConstructorType(intrface) == 1) {
                        return 1;
                    }
                    if (adapterConstructors == null) {
                        adapterConstructors = new ArrayList<>();
                    }
                    adapterConstructors.addAll((Collection) sClassToAdapters.get(intrface));
                }
            }
            if (adapterConstructors == null) {
                return 1;
            }
            sClassToAdapters.put(klass, adapterConstructors);
            return 2;
        }
    }

    private static boolean isLifecycleParent(Class<?> klass) {
        return klass != null && LifecycleObserver.class.isAssignableFrom(klass);
    }

    public static String getAdapterName(String className) {
        StringBuilder sb = new StringBuilder();
        sb.append(className.replace(".", "_"));
        sb.append("_LifecycleAdapter");
        return sb.toString();
    }

    private Lifecycling() {
    }
}
