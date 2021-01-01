package androidx.savedstate;

import android.os.Bundle;
import androidx.lifecycle.GenericLifecycleObserver;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleOwner;
import androidx.savedstate.SavedStateRegistry.AutoRecreated;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

final class Recreator implements GenericLifecycleObserver {
    static final String CLASSES_KEY = "classes_to_restore";
    static final String COMPONENT_KEY = "androidx.savedstate.Restarter";
    private final SavedStateRegistryOwner mOwner;

    static final class SavedStateProvider implements androidx.savedstate.SavedStateRegistry.SavedStateProvider {
        final Set<String> mClasses = new HashSet();

        SavedStateProvider(SavedStateRegistry registry) {
            registry.registerSavedStateProvider(Recreator.COMPONENT_KEY, this);
        }

        public Bundle saveState() {
            Bundle bundle = new Bundle();
            bundle.putStringArrayList(Recreator.CLASSES_KEY, new ArrayList(this.mClasses));
            return bundle;
        }

        /* access modifiers changed from: 0000 */
        public void add(String className) {
            this.mClasses.add(className);
        }
    }

    Recreator(SavedStateRegistryOwner owner) {
        this.mOwner = owner;
    }

    public void onStateChanged(LifecycleOwner source, Event event) {
        if (event == Event.ON_CREATE) {
            source.getLifecycle().removeObserver(this);
            Bundle bundle = this.mOwner.getSavedStateRegistry().consumeRestoredStateForKey(COMPONENT_KEY);
            if (bundle != null) {
                ArrayList<String> classes = bundle.getStringArrayList(CLASSES_KEY);
                if (classes != null) {
                    Iterator it = classes.iterator();
                    while (it.hasNext()) {
                        reflectiveNew((String) it.next());
                    }
                    return;
                }
                throw new IllegalStateException("Bundle with restored state for the component \"androidx.savedstate.Restarter\" must contain list of strings by the key \"classes_to_restore\"");
            }
            return;
        }
        throw new AssertionError("Next event must be ON_CREATE");
    }

    private void reflectiveNew(String className) {
        try {
            Class<? extends AutoRecreated> clazz = Class.forName(className, false, Recreator.class.getClassLoader()).asSubclass(AutoRecreated.class);
            try {
                Constructor<? extends AutoRecreated> constructor = clazz.getDeclaredConstructor(new Class[0]);
                constructor.setAccessible(true);
                try {
                    ((AutoRecreated) constructor.newInstance(new Object[0])).onRecreated(this.mOwner);
                } catch (Exception e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Failed to instantiate ");
                    sb.append(className);
                    throw new RuntimeException(sb.toString(), e);
                }
            } catch (NoSuchMethodException e2) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Class");
                sb2.append(clazz.getSimpleName());
                sb2.append(" must have default constructor in order to be automatically recreated");
                throw new IllegalStateException(sb2.toString(), e2);
            }
        } catch (ClassNotFoundException e3) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("Class ");
            sb3.append(className);
            sb3.append(" wasn't found");
            throw new RuntimeException(sb3.toString(), e3);
        }
    }
}
