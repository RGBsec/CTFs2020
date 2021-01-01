package androidx.savedstate;

import android.os.Bundle;
import androidx.arch.core.internal.SafeIterableMap;
import androidx.lifecycle.GenericLifecycleObserver;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.LifecycleOwner;
import java.util.Iterator;
import java.util.Map.Entry;

public final class SavedStateRegistry {
    private static final String SAVED_COMPONENTS_KEY = "androidx.lifecycle.BundlableSavedStateRegistry.key";
    boolean mAllowingSavingState = true;
    private SafeIterableMap<String, SavedStateProvider> mComponents = new SafeIterableMap<>();
    private SavedStateProvider mRecreatorProvider;
    private boolean mRestored;
    private Bundle mRestoredState;

    public interface AutoRecreated {
        void onRecreated(SavedStateRegistryOwner savedStateRegistryOwner);
    }

    public interface SavedStateProvider {
        Bundle saveState();
    }

    SavedStateRegistry() {
    }

    public Bundle consumeRestoredStateForKey(String key) {
        if (this.mRestored) {
            Bundle bundle = this.mRestoredState;
            if (bundle == null) {
                return null;
            }
            Bundle result = bundle.getBundle(key);
            this.mRestoredState.remove(key);
            if (this.mRestoredState.isEmpty()) {
                this.mRestoredState = null;
            }
            return result;
        }
        throw new IllegalStateException("You can consumeRestoredStateForKey only after super.onCreate of corresponding component");
    }

    public void registerSavedStateProvider(String key, SavedStateProvider provider) {
        if (((SavedStateProvider) this.mComponents.putIfAbsent(key, provider)) != null) {
            throw new IllegalArgumentException("SavedStateProvider with the given key is already registered");
        }
    }

    public void unregisterSavedStateProvider(String key) {
        this.mComponents.remove(key);
    }

    public boolean isRestored() {
        return this.mRestored;
    }

    public void runOnNextRecreation(Class<? extends AutoRecreated> clazz) {
        if (this.mAllowingSavingState) {
            if (this.mRecreatorProvider == null) {
                this.mRecreatorProvider = new SavedStateProvider(this);
            }
            try {
                clazz.getDeclaredConstructor(new Class[0]);
                this.mRecreatorProvider.add(clazz.getName());
            } catch (NoSuchMethodException e) {
                StringBuilder sb = new StringBuilder();
                sb.append("Class");
                sb.append(clazz.getSimpleName());
                sb.append(" must have default constructor in order to be automatically recreated");
                throw new IllegalArgumentException(sb.toString(), e);
            }
        } else {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
    }

    /* access modifiers changed from: 0000 */
    public void performRestore(Lifecycle lifecycle, Bundle savedState) {
        if (!this.mRestored) {
            if (savedState != null) {
                this.mRestoredState = savedState.getBundle(SAVED_COMPONENTS_KEY);
            }
            lifecycle.addObserver(new GenericLifecycleObserver() {
                public void onStateChanged(LifecycleOwner source, Event event) {
                    if (event == Event.ON_START) {
                        SavedStateRegistry.this.mAllowingSavingState = true;
                    } else if (event == Event.ON_STOP) {
                        SavedStateRegistry.this.mAllowingSavingState = false;
                    }
                }
            });
            this.mRestored = true;
            return;
        }
        throw new IllegalStateException("SavedStateRegistry was already restored.");
    }

    /* access modifiers changed from: 0000 */
    public void performSave(Bundle outBundle) {
        Bundle components = new Bundle();
        Bundle bundle = this.mRestoredState;
        if (bundle != null) {
            components.putAll(bundle);
        }
        Iterator<Entry<String, SavedStateProvider>> it = this.mComponents.iteratorWithAdditions();
        while (it.hasNext()) {
            Entry<String, SavedStateProvider> entry1 = (Entry) it.next();
            components.putBundle((String) entry1.getKey(), ((SavedStateProvider) entry1.getValue()).saveState());
        }
        outBundle.putBundle(SAVED_COMPONENTS_KEY, components);
    }
}
