package androidx.lifecycle;

import androidx.lifecycle.Lifecycle.Event;

class SingleGeneratedAdapterObserver implements LifecycleEventObserver {
    private final GeneratedAdapter mGeneratedAdapter;

    SingleGeneratedAdapterObserver(GeneratedAdapter generatedAdapter) {
        this.mGeneratedAdapter = generatedAdapter;
    }

    public void onStateChanged(LifecycleOwner source, Event event) {
        this.mGeneratedAdapter.callMethods(source, event, false, null);
        this.mGeneratedAdapter.callMethods(source, event, true, null);
    }
}
