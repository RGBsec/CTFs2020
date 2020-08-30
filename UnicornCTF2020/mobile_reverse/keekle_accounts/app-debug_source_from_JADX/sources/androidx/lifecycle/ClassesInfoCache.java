package androidx.lifecycle;

import androidx.lifecycle.Lifecycle.Event;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

class ClassesInfoCache {
    private static final int CALL_TYPE_NO_ARG = 0;
    private static final int CALL_TYPE_PROVIDER = 1;
    private static final int CALL_TYPE_PROVIDER_WITH_EVENT = 2;
    static ClassesInfoCache sInstance = new ClassesInfoCache();
    private final Map<Class, CallbackInfo> mCallbackMap = new HashMap();
    private final Map<Class, Boolean> mHasLifecycleMethods = new HashMap();

    static class CallbackInfo {
        final Map<Event, List<MethodReference>> mEventToHandlers = new HashMap();
        final Map<MethodReference, Event> mHandlerToEvent;

        CallbackInfo(Map<MethodReference, Event> handlerToEvent) {
            this.mHandlerToEvent = handlerToEvent;
            for (Entry<MethodReference, Event> entry : handlerToEvent.entrySet()) {
                Event event = (Event) entry.getValue();
                List list = (List) this.mEventToHandlers.get(event);
                if (list == null) {
                    list = new ArrayList();
                    this.mEventToHandlers.put(event, list);
                }
                list.add(entry.getKey());
            }
        }

        /* access modifiers changed from: 0000 */
        public void invokeCallbacks(LifecycleOwner source, Event event, Object target) {
            invokeMethodsForEvent((List) this.mEventToHandlers.get(event), source, event, target);
            invokeMethodsForEvent((List) this.mEventToHandlers.get(Event.ON_ANY), source, event, target);
        }

        private static void invokeMethodsForEvent(List<MethodReference> handlers, LifecycleOwner source, Event event, Object mWrapped) {
            if (handlers != null) {
                for (int i = handlers.size() - 1; i >= 0; i--) {
                    ((MethodReference) handlers.get(i)).invokeCallback(source, event, mWrapped);
                }
            }
        }
    }

    static class MethodReference {
        final int mCallType;
        final Method mMethod;

        MethodReference(int callType, Method method) {
            this.mCallType = callType;
            this.mMethod = method;
            method.setAccessible(true);
        }

        /* access modifiers changed from: 0000 */
        public void invokeCallback(LifecycleOwner source, Event event, Object target) {
            try {
                int i = this.mCallType;
                if (i == 0) {
                    this.mMethod.invoke(target, new Object[0]);
                } else if (i == 1) {
                    this.mMethod.invoke(target, new Object[]{source});
                } else if (i == 2) {
                    this.mMethod.invoke(target, new Object[]{source, event});
                }
            } catch (InvocationTargetException e) {
                throw new RuntimeException("Failed to call observer method", e.getCause());
            } catch (IllegalAccessException e2) {
                throw new RuntimeException(e2);
            }
        }

        public boolean equals(Object o) {
            boolean z = true;
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            MethodReference that = (MethodReference) o;
            if (this.mCallType != that.mCallType || !this.mMethod.getName().equals(that.mMethod.getName())) {
                z = false;
            }
            return z;
        }

        public int hashCode() {
            return (this.mCallType * 31) + this.mMethod.getName().hashCode();
        }
    }

    ClassesInfoCache() {
    }

    /* access modifiers changed from: 0000 */
    public boolean hasLifecycleMethods(Class klass) {
        Boolean hasLifecycleMethods = (Boolean) this.mHasLifecycleMethods.get(klass);
        if (hasLifecycleMethods != null) {
            return hasLifecycleMethods.booleanValue();
        }
        Method[] methods = getDeclaredMethods(klass);
        for (Method method : methods) {
            if (((OnLifecycleEvent) method.getAnnotation(OnLifecycleEvent.class)) != null) {
                createInfo(klass, methods);
                return true;
            }
        }
        this.mHasLifecycleMethods.put(klass, Boolean.valueOf(false));
        return false;
    }

    private Method[] getDeclaredMethods(Class klass) {
        try {
            return klass.getDeclaredMethods();
        } catch (NoClassDefFoundError e) {
            throw new IllegalArgumentException("The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot access even other methods so you should make sure that your observer classes only access framework classes that are available in your min API level OR use lifecycle:compiler annotation processor.", e);
        }
    }

    /* access modifiers changed from: 0000 */
    public CallbackInfo getInfo(Class klass) {
        CallbackInfo existing = (CallbackInfo) this.mCallbackMap.get(klass);
        if (existing != null) {
            return existing;
        }
        return createInfo(klass, null);
    }

    private void verifyAndPutHandler(Map<MethodReference, Event> handlers, MethodReference newHandler, Event newEvent, Class klass) {
        Event event = (Event) handlers.get(newHandler);
        if (event != null && newEvent != event) {
            Method method = newHandler.mMethod;
            StringBuilder sb = new StringBuilder();
            sb.append("Method ");
            sb.append(method.getName());
            sb.append(" in ");
            sb.append(klass.getName());
            sb.append(" already declared with different @OnLifecycleEvent value: previous value ");
            sb.append(event);
            sb.append(", new value ");
            sb.append(newEvent);
            throw new IllegalArgumentException(sb.toString());
        } else if (event == null) {
            handlers.put(newHandler, newEvent);
        }
    }

    private CallbackInfo createInfo(Class klass, Method[] declaredMethods) {
        Class cls = klass;
        Class superclass = klass.getSuperclass();
        Map<MethodReference, Event> handlerToEvent = new HashMap<>();
        if (superclass != null) {
            CallbackInfo superInfo = getInfo(superclass);
            if (superInfo != null) {
                handlerToEvent.putAll(superInfo.mHandlerToEvent);
            }
        }
        char c = 0;
        for (Class intrfc : klass.getInterfaces()) {
            for (Entry<MethodReference, Event> entry : getInfo(intrfc).mHandlerToEvent.entrySet()) {
                verifyAndPutHandler(handlerToEvent, (MethodReference) entry.getKey(), (Event) entry.getValue(), cls);
            }
        }
        Method[] methods = declaredMethods != null ? declaredMethods : getDeclaredMethods(klass);
        boolean hasLifecycleMethods = false;
        int length = methods.length;
        int i = 0;
        while (i < length) {
            Method method = methods[i];
            OnLifecycleEvent annotation = (OnLifecycleEvent) method.getAnnotation(OnLifecycleEvent.class);
            if (annotation != null) {
                hasLifecycleMethods = true;
                Class<?>[] params = method.getParameterTypes();
                int callType = 0;
                if (params.length > 0) {
                    callType = 1;
                    if (!params[c].isAssignableFrom(LifecycleOwner.class)) {
                        throw new IllegalArgumentException("invalid parameter type. Must be one and instanceof LifecycleOwner");
                    }
                }
                Event event = annotation.value();
                if (params.length > 1) {
                    callType = 2;
                    if (!params[1].isAssignableFrom(Event.class)) {
                        throw new IllegalArgumentException("invalid parameter type. second arg must be an event");
                    } else if (event != Event.ON_ANY) {
                        throw new IllegalArgumentException("Second arg is supported only for ON_ANY value");
                    }
                }
                if (params.length <= 2) {
                    verifyAndPutHandler(handlerToEvent, new MethodReference(callType, method), event, cls);
                } else {
                    throw new IllegalArgumentException("cannot have more than 2 params");
                }
            }
            i++;
            c = 0;
        }
        CallbackInfo info = new CallbackInfo(handlerToEvent);
        this.mCallbackMap.put(cls, info);
        this.mHasLifecycleMethods.put(cls, Boolean.valueOf(hasLifecycleMethods));
        return info;
    }
}
