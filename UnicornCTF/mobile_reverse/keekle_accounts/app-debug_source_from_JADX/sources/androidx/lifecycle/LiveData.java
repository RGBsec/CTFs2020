package androidx.lifecycle;

import androidx.arch.core.executor.ArchTaskExecutor;
import androidx.arch.core.internal.SafeIterableMap;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.Lifecycle.State;
import java.util.Iterator;
import java.util.Map.Entry;

public abstract class LiveData<T> {
    static final Object NOT_SET = new Object();
    static final int START_VERSION = -1;
    int mActiveCount;
    private volatile Object mData;
    final Object mDataLock;
    private boolean mDispatchInvalidated;
    private boolean mDispatchingValue;
    private SafeIterableMap<Observer<? super T>, ObserverWrapper> mObservers;
    volatile Object mPendingData;
    private final Runnable mPostValueRunnable;
    private int mVersion;

    private class AlwaysActiveObserver extends ObserverWrapper {
        AlwaysActiveObserver(Observer<? super T> observer) {
            super(observer);
        }

        /* access modifiers changed from: 0000 */
        public boolean shouldBeActive() {
            return true;
        }
    }

    class LifecycleBoundObserver extends ObserverWrapper implements LifecycleEventObserver {
        final LifecycleOwner mOwner;

        LifecycleBoundObserver(LifecycleOwner owner, Observer<? super T> observer) {
            super(observer);
            this.mOwner = owner;
        }

        /* access modifiers changed from: 0000 */
        public boolean shouldBeActive() {
            return this.mOwner.getLifecycle().getCurrentState().isAtLeast(State.STARTED);
        }

        public void onStateChanged(LifecycleOwner source, Event event) {
            if (this.mOwner.getLifecycle().getCurrentState() == State.DESTROYED) {
                LiveData.this.removeObserver(this.mObserver);
            } else {
                activeStateChanged(shouldBeActive());
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean isAttachedTo(LifecycleOwner owner) {
            return this.mOwner == owner;
        }

        /* access modifiers changed from: 0000 */
        public void detachObserver() {
            this.mOwner.getLifecycle().removeObserver(this);
        }
    }

    private abstract class ObserverWrapper {
        boolean mActive;
        int mLastVersion = -1;
        final Observer<? super T> mObserver;

        /* access modifiers changed from: 0000 */
        public abstract boolean shouldBeActive();

        ObserverWrapper(Observer<? super T> observer) {
            this.mObserver = observer;
        }

        /* access modifiers changed from: 0000 */
        public boolean isAttachedTo(LifecycleOwner owner) {
            return false;
        }

        /* access modifiers changed from: 0000 */
        public void detachObserver() {
        }

        /* access modifiers changed from: 0000 */
        public void activeStateChanged(boolean newActive) {
            if (newActive != this.mActive) {
                this.mActive = newActive;
                int i = 1;
                boolean wasInactive = LiveData.this.mActiveCount == 0;
                LiveData liveData = LiveData.this;
                int i2 = liveData.mActiveCount;
                if (!this.mActive) {
                    i = -1;
                }
                liveData.mActiveCount = i2 + i;
                if (wasInactive && this.mActive) {
                    LiveData.this.onActive();
                }
                if (LiveData.this.mActiveCount == 0 && !this.mActive) {
                    LiveData.this.onInactive();
                }
                if (this.mActive) {
                    LiveData.this.dispatchingValue(this);
                }
            }
        }
    }

    public LiveData(T value) {
        this.mDataLock = new Object();
        this.mObservers = new SafeIterableMap<>();
        this.mActiveCount = 0;
        this.mPendingData = NOT_SET;
        this.mPostValueRunnable = new Runnable() {
            public void run() {
                Object newValue;
                synchronized (LiveData.this.mDataLock) {
                    newValue = LiveData.this.mPendingData;
                    LiveData.this.mPendingData = LiveData.NOT_SET;
                }
                LiveData.this.setValue(newValue);
            }
        };
        this.mData = value;
        this.mVersion = 0;
    }

    public LiveData() {
        this.mDataLock = new Object();
        this.mObservers = new SafeIterableMap<>();
        this.mActiveCount = 0;
        this.mPendingData = NOT_SET;
        this.mPostValueRunnable = new Runnable() {
            public void run() {
                Object newValue;
                synchronized (LiveData.this.mDataLock) {
                    newValue = LiveData.this.mPendingData;
                    LiveData.this.mPendingData = LiveData.NOT_SET;
                }
                LiveData.this.setValue(newValue);
            }
        };
        this.mData = NOT_SET;
        this.mVersion = -1;
    }

    private void considerNotify(ObserverWrapper observer) {
        if (observer.mActive) {
            if (!observer.shouldBeActive()) {
                observer.activeStateChanged(false);
                return;
            }
            int i = observer.mLastVersion;
            int i2 = this.mVersion;
            if (i < i2) {
                observer.mLastVersion = i2;
                observer.mObserver.onChanged(this.mData);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void dispatchingValue(ObserverWrapper initiator) {
        if (this.mDispatchingValue) {
            this.mDispatchInvalidated = true;
            return;
        }
        this.mDispatchingValue = true;
        do {
            this.mDispatchInvalidated = false;
            if (initiator == null) {
                Iterator<Entry<Observer<? super T>, ObserverWrapper>> iterator = this.mObservers.iteratorWithAdditions();
                while (iterator.hasNext()) {
                    considerNotify((ObserverWrapper) ((Entry) iterator.next()).getValue());
                    if (this.mDispatchInvalidated) {
                        break;
                    }
                }
            } else {
                considerNotify(initiator);
                initiator = null;
            }
        } while (this.mDispatchInvalidated);
        this.mDispatchingValue = false;
    }

    public void observe(LifecycleOwner owner, Observer<? super T> observer) {
        assertMainThread("observe");
        if (owner.getLifecycle().getCurrentState() != State.DESTROYED) {
            LifecycleBoundObserver wrapper = new LifecycleBoundObserver<>(owner, observer);
            ObserverWrapper existing = (ObserverWrapper) this.mObservers.putIfAbsent(observer, wrapper);
            if (existing != null && !existing.isAttachedTo(owner)) {
                throw new IllegalArgumentException("Cannot add the same observer with different lifecycles");
            } else if (existing == null) {
                owner.getLifecycle().addObserver(wrapper);
            }
        }
    }

    public void observeForever(Observer<? super T> observer) {
        assertMainThread("observeForever");
        AlwaysActiveObserver wrapper = new AlwaysActiveObserver<>(observer);
        ObserverWrapper existing = (ObserverWrapper) this.mObservers.putIfAbsent(observer, wrapper);
        if (existing instanceof LifecycleBoundObserver) {
            throw new IllegalArgumentException("Cannot add the same observer with different lifecycles");
        } else if (existing == null) {
            wrapper.activeStateChanged(true);
        }
    }

    public void removeObserver(Observer<? super T> observer) {
        assertMainThread("removeObserver");
        ObserverWrapper removed = (ObserverWrapper) this.mObservers.remove(observer);
        if (removed != null) {
            removed.detachObserver();
            removed.activeStateChanged(false);
        }
    }

    public void removeObservers(LifecycleOwner owner) {
        assertMainThread("removeObservers");
        Iterator it = this.mObservers.iterator();
        while (it.hasNext()) {
            Entry<Observer<? super T>, ObserverWrapper> entry = (Entry) it.next();
            if (((ObserverWrapper) entry.getValue()).isAttachedTo(owner)) {
                removeObserver((Observer) entry.getKey());
            }
        }
    }

    /* access modifiers changed from: protected */
    public void postValue(T value) {
        boolean postTask;
        synchronized (this.mDataLock) {
            postTask = this.mPendingData == NOT_SET;
            this.mPendingData = value;
        }
        if (postTask) {
            ArchTaskExecutor.getInstance().postToMainThread(this.mPostValueRunnable);
        }
    }

    /* access modifiers changed from: protected */
    public void setValue(T value) {
        assertMainThread("setValue");
        this.mVersion++;
        this.mData = value;
        dispatchingValue(null);
    }

    public T getValue() {
        Object data = this.mData;
        if (data != NOT_SET) {
            return data;
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public int getVersion() {
        return this.mVersion;
    }

    /* access modifiers changed from: protected */
    public void onActive() {
    }

    /* access modifiers changed from: protected */
    public void onInactive() {
    }

    public boolean hasObservers() {
        return this.mObservers.size() > 0;
    }

    public boolean hasActiveObservers() {
        return this.mActiveCount > 0;
    }

    static void assertMainThread(String methodName) {
        if (!ArchTaskExecutor.getInstance().isMainThread()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Cannot invoke ");
            sb.append(methodName);
            sb.append(" on a background thread");
            throw new IllegalStateException(sb.toString());
        }
    }
}
