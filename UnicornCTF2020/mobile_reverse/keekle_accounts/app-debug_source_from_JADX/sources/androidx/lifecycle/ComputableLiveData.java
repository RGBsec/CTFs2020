package androidx.lifecycle;

import androidx.arch.core.executor.ArchTaskExecutor;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class ComputableLiveData<T> {
    final AtomicBoolean mComputing;
    final Executor mExecutor;
    final AtomicBoolean mInvalid;
    final Runnable mInvalidationRunnable;
    final LiveData<T> mLiveData;
    final Runnable mRefreshRunnable;

    /* access modifiers changed from: protected */
    public abstract T compute();

    public ComputableLiveData() {
        this(ArchTaskExecutor.getIOThreadExecutor());
    }

    public ComputableLiveData(Executor executor) {
        this.mInvalid = new AtomicBoolean(true);
        this.mComputing = new AtomicBoolean(false);
        this.mRefreshRunnable = new Runnable() {
            public void run() {
                do {
                    boolean computed = false;
                    if (ComputableLiveData.this.mComputing.compareAndSet(false, true)) {
                        Object obj = null;
                        while (ComputableLiveData.this.mInvalid.compareAndSet(true, false)) {
                            try {
                                computed = true;
                                obj = ComputableLiveData.this.compute();
                            } finally {
                                ComputableLiveData.this.mComputing.set(false);
                            }
                        }
                        if (computed) {
                            ComputableLiveData.this.mLiveData.postValue(obj);
                        }
                    }
                    if (!computed) {
                        return;
                    }
                } while (ComputableLiveData.this.mInvalid.get());
            }
        };
        this.mInvalidationRunnable = new Runnable() {
            public void run() {
                boolean isActive = ComputableLiveData.this.mLiveData.hasActiveObservers();
                if (ComputableLiveData.this.mInvalid.compareAndSet(false, true) && isActive) {
                    ComputableLiveData.this.mExecutor.execute(ComputableLiveData.this.mRefreshRunnable);
                }
            }
        };
        this.mExecutor = executor;
        this.mLiveData = new LiveData<T>() {
            /* access modifiers changed from: protected */
            public void onActive() {
                ComputableLiveData.this.mExecutor.execute(ComputableLiveData.this.mRefreshRunnable);
            }
        };
    }

    public LiveData<T> getLiveData() {
        return this.mLiveData;
    }

    public void invalidate() {
        ArchTaskExecutor.getInstance().executeOnMainThread(this.mInvalidationRunnable);
    }
}
