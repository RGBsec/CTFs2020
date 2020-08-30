package androidx.lifecycle;

import android.os.Handler;
import androidx.lifecycle.Lifecycle.Event;

public class ServiceLifecycleDispatcher {
    private final Handler mHandler = new Handler();
    private DispatchRunnable mLastDispatchRunnable;
    private final LifecycleRegistry mRegistry;

    static class DispatchRunnable implements Runnable {
        final Event mEvent;
        private final LifecycleRegistry mRegistry;
        private boolean mWasExecuted = false;

        DispatchRunnable(LifecycleRegistry registry, Event event) {
            this.mRegistry = registry;
            this.mEvent = event;
        }

        public void run() {
            if (!this.mWasExecuted) {
                this.mRegistry.handleLifecycleEvent(this.mEvent);
                this.mWasExecuted = true;
            }
        }
    }

    public ServiceLifecycleDispatcher(LifecycleOwner provider) {
        this.mRegistry = new LifecycleRegistry(provider);
    }

    private void postDispatchRunnable(Event event) {
        DispatchRunnable dispatchRunnable = this.mLastDispatchRunnable;
        if (dispatchRunnable != null) {
            dispatchRunnable.run();
        }
        DispatchRunnable dispatchRunnable2 = new DispatchRunnable(this.mRegistry, event);
        this.mLastDispatchRunnable = dispatchRunnable2;
        this.mHandler.postAtFrontOfQueue(dispatchRunnable2);
    }

    public void onServicePreSuperOnCreate() {
        postDispatchRunnable(Event.ON_CREATE);
    }

    public void onServicePreSuperOnBind() {
        postDispatchRunnable(Event.ON_START);
    }

    public void onServicePreSuperOnStart() {
        postDispatchRunnable(Event.ON_START);
    }

    public void onServicePreSuperOnDestroy() {
        postDispatchRunnable(Event.ON_STOP);
        postDispatchRunnable(Event.ON_DESTROY);
    }

    public Lifecycle getLifecycle() {
        return this.mRegistry;
    }
}
