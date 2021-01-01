package com.google.android.gms.tasks;

import android.app.Activity;
import com.google.android.gms.common.api.internal.LifecycleCallback;
import com.google.android.gms.common.api.internal.LifecycleFragment;
import com.google.android.gms.common.internal.Preconditions;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;

final class zzu<TResult> extends Task<TResult> {
    private final Object mLock = new Object();
    private TResult zzaa;
    private Exception zzab;
    private final zzr<TResult> zzx = new zzr<>();
    private boolean zzy;
    private volatile boolean zzz;

    private static class zza extends LifecycleCallback {
        private final List<WeakReference<zzq<?>>> zzac = new ArrayList();

        public static zza zza(Activity activity) {
            LifecycleFragment fragment = getFragment(activity);
            zza zza = (zza) fragment.getCallbackOrNull("TaskOnStopCallback", zza.class);
            return zza == null ? new zza(fragment) : zza;
        }

        private zza(LifecycleFragment lifecycleFragment) {
            super(lifecycleFragment);
            this.mLifecycleFragment.addCallback("TaskOnStopCallback", this);
        }

        public final <T> void zzb(zzq<T> zzq) {
            synchronized (this.zzac) {
                this.zzac.add(new WeakReference(zzq));
            }
        }

        public void onStop() {
            synchronized (this.zzac) {
                for (WeakReference weakReference : this.zzac) {
                    zzq zzq = (zzq) weakReference.get();
                    if (zzq != null) {
                        zzq.cancel();
                    }
                }
                this.zzac.clear();
            }
        }
    }

    zzu() {
    }

    public final boolean isComplete() {
        boolean z;
        synchronized (this.mLock) {
            z = this.zzy;
        }
        return z;
    }

    public final boolean isCanceled() {
        return this.zzz;
    }

    public final boolean isSuccessful() {
        boolean z;
        synchronized (this.mLock) {
            z = this.zzy && !this.zzz && this.zzab == null;
        }
        return z;
    }

    public final TResult getResult() {
        TResult tresult;
        synchronized (this.mLock) {
            zzb();
            zzd();
            if (this.zzab == null) {
                tresult = this.zzaa;
            } else {
                throw new RuntimeExecutionException(this.zzab);
            }
        }
        return tresult;
    }

    public final <X extends Throwable> TResult getResult(Class<X> cls) throws Throwable {
        TResult tresult;
        synchronized (this.mLock) {
            zzb();
            zzd();
            if (cls.isInstance(this.zzab)) {
                throw ((Throwable) cls.cast(this.zzab));
            } else if (this.zzab == null) {
                tresult = this.zzaa;
            } else {
                throw new RuntimeExecutionException(this.zzab);
            }
        }
        return tresult;
    }

    public final Exception getException() {
        Exception exc;
        synchronized (this.mLock) {
            exc = this.zzab;
        }
        return exc;
    }

    public final Task<TResult> addOnSuccessListener(OnSuccessListener<? super TResult> onSuccessListener) {
        return addOnSuccessListener(TaskExecutors.MAIN_THREAD, onSuccessListener);
    }

    public final Task<TResult> addOnSuccessListener(Executor executor, OnSuccessListener<? super TResult> onSuccessListener) {
        this.zzx.zza((zzq<TResult>) new zzm<TResult>(executor, onSuccessListener));
        zze();
        return this;
    }

    public final Task<TResult> addOnSuccessListener(Activity activity, OnSuccessListener<? super TResult> onSuccessListener) {
        zzm zzm = new zzm(TaskExecutors.MAIN_THREAD, onSuccessListener);
        this.zzx.zza((zzq<TResult>) zzm);
        zza.zza(activity).zzb(zzm);
        zze();
        return this;
    }

    public final Task<TResult> addOnFailureListener(OnFailureListener onFailureListener) {
        return addOnFailureListener(TaskExecutors.MAIN_THREAD, onFailureListener);
    }

    public final Task<TResult> addOnFailureListener(Executor executor, OnFailureListener onFailureListener) {
        this.zzx.zza((zzq<TResult>) new zzk<TResult>(executor, onFailureListener));
        zze();
        return this;
    }

    public final Task<TResult> addOnFailureListener(Activity activity, OnFailureListener onFailureListener) {
        zzk zzk = new zzk(TaskExecutors.MAIN_THREAD, onFailureListener);
        this.zzx.zza((zzq<TResult>) zzk);
        zza.zza(activity).zzb(zzk);
        zze();
        return this;
    }

    public final Task<TResult> addOnCompleteListener(OnCompleteListener<TResult> onCompleteListener) {
        return addOnCompleteListener(TaskExecutors.MAIN_THREAD, onCompleteListener);
    }

    public final Task<TResult> addOnCompleteListener(Executor executor, OnCompleteListener<TResult> onCompleteListener) {
        this.zzx.zza((zzq<TResult>) new zzi<TResult>(executor, onCompleteListener));
        zze();
        return this;
    }

    public final Task<TResult> addOnCompleteListener(Activity activity, OnCompleteListener<TResult> onCompleteListener) {
        zzi zzi = new zzi(TaskExecutors.MAIN_THREAD, onCompleteListener);
        this.zzx.zza((zzq<TResult>) zzi);
        zza.zza(activity).zzb(zzi);
        zze();
        return this;
    }

    public final <TContinuationResult> Task<TContinuationResult> continueWith(Continuation<TResult, TContinuationResult> continuation) {
        return continueWith(TaskExecutors.MAIN_THREAD, continuation);
    }

    public final <TContinuationResult> Task<TContinuationResult> continueWith(Executor executor, Continuation<TResult, TContinuationResult> continuation) {
        zzu zzu = new zzu();
        this.zzx.zza((zzq<TResult>) new zzc<TResult>(executor, continuation, zzu));
        zze();
        return zzu;
    }

    public final <TContinuationResult> Task<TContinuationResult> continueWithTask(Continuation<TResult, Task<TContinuationResult>> continuation) {
        return continueWithTask(TaskExecutors.MAIN_THREAD, continuation);
    }

    public final Task<TResult> addOnCanceledListener(OnCanceledListener onCanceledListener) {
        return addOnCanceledListener(TaskExecutors.MAIN_THREAD, onCanceledListener);
    }

    public final Task<TResult> addOnCanceledListener(Executor executor, OnCanceledListener onCanceledListener) {
        this.zzx.zza((zzq<TResult>) new zzg<TResult>(executor, onCanceledListener));
        zze();
        return this;
    }

    public final Task<TResult> addOnCanceledListener(Activity activity, OnCanceledListener onCanceledListener) {
        zzg zzg = new zzg(TaskExecutors.MAIN_THREAD, onCanceledListener);
        this.zzx.zza((zzq<TResult>) zzg);
        zza.zza(activity).zzb(zzg);
        zze();
        return this;
    }

    public final <TContinuationResult> Task<TContinuationResult> continueWithTask(Executor executor, Continuation<TResult, Task<TContinuationResult>> continuation) {
        zzu zzu = new zzu();
        this.zzx.zza((zzq<TResult>) new zze<TResult>(executor, continuation, zzu));
        zze();
        return zzu;
    }

    public final <TContinuationResult> Task<TContinuationResult> onSuccessTask(Executor executor, SuccessContinuation<TResult, TContinuationResult> successContinuation) {
        zzu zzu = new zzu();
        this.zzx.zza((zzq<TResult>) new zzo<TResult>(executor, successContinuation, zzu));
        zze();
        return zzu;
    }

    public final <TContinuationResult> Task<TContinuationResult> onSuccessTask(SuccessContinuation<TResult, TContinuationResult> successContinuation) {
        return onSuccessTask(TaskExecutors.MAIN_THREAD, successContinuation);
    }

    public final void setResult(TResult tresult) {
        synchronized (this.mLock) {
            zzc();
            this.zzy = true;
            this.zzaa = tresult;
        }
        this.zzx.zza((Task<TResult>) this);
    }

    public final boolean trySetResult(TResult tresult) {
        synchronized (this.mLock) {
            if (this.zzy) {
                return false;
            }
            this.zzy = true;
            this.zzaa = tresult;
            this.zzx.zza((Task<TResult>) this);
            return true;
        }
    }

    public final void setException(Exception exc) {
        Preconditions.checkNotNull(exc, "Exception must not be null");
        synchronized (this.mLock) {
            zzc();
            this.zzy = true;
            this.zzab = exc;
        }
        this.zzx.zza((Task<TResult>) this);
    }

    public final boolean trySetException(Exception exc) {
        Preconditions.checkNotNull(exc, "Exception must not be null");
        synchronized (this.mLock) {
            if (this.zzy) {
                return false;
            }
            this.zzy = true;
            this.zzab = exc;
            this.zzx.zza((Task<TResult>) this);
            return true;
        }
    }

    public final boolean zza() {
        synchronized (this.mLock) {
            if (this.zzy) {
                return false;
            }
            this.zzy = true;
            this.zzz = true;
            this.zzx.zza((Task<TResult>) this);
            return true;
        }
    }

    private final void zzb() {
        Preconditions.checkState(this.zzy, "Task is not yet complete");
    }

    private final void zzc() {
        Preconditions.checkState(!this.zzy, "Task is already complete");
    }

    private final void zzd() {
        if (this.zzz) {
            throw new CancellationException("Task is already canceled.");
        }
    }

    private final void zze() {
        synchronized (this.mLock) {
            if (this.zzy) {
                this.zzx.zza((Task<TResult>) this);
            }
        }
    }
}
