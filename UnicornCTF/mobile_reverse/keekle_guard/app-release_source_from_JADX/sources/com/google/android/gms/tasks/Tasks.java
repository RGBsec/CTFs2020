package com.google.android.gms.tasks;

import com.google.android.gms.common.internal.Preconditions;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class Tasks {

    private static final class zza implements zzb {
        private final CountDownLatch zzaf;

        private zza() {
            this.zzaf = new CountDownLatch(1);
        }

        public final void onSuccess(Object obj) {
            this.zzaf.countDown();
        }

        public final void onFailure(Exception exc) {
            this.zzaf.countDown();
        }

        public final void onCanceled() {
            this.zzaf.countDown();
        }

        public final void await() throws InterruptedException {
            this.zzaf.await();
        }

        public final boolean await(long j, TimeUnit timeUnit) throws InterruptedException {
            return this.zzaf.await(j, timeUnit);
        }

        /* synthetic */ zza(zzv zzv) {
            this();
        }
    }

    interface zzb extends OnCanceledListener, OnFailureListener, OnSuccessListener<Object> {
    }

    private static final class zzc implements zzb {
        private final Object mLock = new Object();
        private final zzu<Void> zza;
        private Exception zzab;
        private final int zzag;
        private int zzah;
        private int zzai;
        private int zzaj;
        private boolean zzak;

        public zzc(int i, zzu<Void> zzu) {
            this.zzag = i;
            this.zza = zzu;
        }

        public final void onFailure(Exception exc) {
            synchronized (this.mLock) {
                this.zzai++;
                this.zzab = exc;
                zzf();
            }
        }

        public final void onSuccess(Object obj) {
            synchronized (this.mLock) {
                this.zzah++;
                zzf();
            }
        }

        public final void onCanceled() {
            synchronized (this.mLock) {
                this.zzaj++;
                this.zzak = true;
                zzf();
            }
        }

        private final void zzf() {
            if (this.zzah + this.zzai + this.zzaj == this.zzag) {
                if (this.zzab != null) {
                    zzu<Void> zzu = this.zza;
                    int i = this.zzai;
                    int i2 = this.zzag;
                    StringBuilder sb = new StringBuilder(54);
                    sb.append(i);
                    sb.append(" out of ");
                    sb.append(i2);
                    sb.append(" underlying tasks failed");
                    zzu.setException(new ExecutionException(sb.toString(), this.zzab));
                } else if (this.zzak) {
                    this.zza.zza();
                } else {
                    this.zza.setResult(null);
                }
            }
        }
    }

    public static <TResult> Task<TResult> forResult(TResult tresult) {
        zzu zzu = new zzu();
        zzu.setResult(tresult);
        return zzu;
    }

    public static <TResult> Task<TResult> forException(Exception exc) {
        zzu zzu = new zzu();
        zzu.setException(exc);
        return zzu;
    }

    public static <TResult> Task<TResult> forCanceled() {
        zzu zzu = new zzu();
        zzu.zza();
        return zzu;
    }

    public static <TResult> Task<TResult> call(Callable<TResult> callable) {
        return call(TaskExecutors.MAIN_THREAD, callable);
    }

    public static <TResult> Task<TResult> call(Executor executor, Callable<TResult> callable) {
        Preconditions.checkNotNull(executor, "Executor must not be null");
        Preconditions.checkNotNull(callable, "Callback must not be null");
        zzu zzu = new zzu();
        executor.execute(new zzv(zzu, callable));
        return zzu;
    }

    public static <TResult> TResult await(Task<TResult> task) throws ExecutionException, InterruptedException {
        Preconditions.checkNotMainThread();
        Preconditions.checkNotNull(task, "Task must not be null");
        if (task.isComplete()) {
            return zzb(task);
        }
        zza zza2 = new zza(null);
        zza(task, zza2);
        zza2.await();
        return zzb(task);
    }

    public static <TResult> TResult await(Task<TResult> task, long j, TimeUnit timeUnit) throws ExecutionException, InterruptedException, TimeoutException {
        Preconditions.checkNotMainThread();
        Preconditions.checkNotNull(task, "Task must not be null");
        Preconditions.checkNotNull(timeUnit, "TimeUnit must not be null");
        if (task.isComplete()) {
            return zzb(task);
        }
        zza zza2 = new zza(null);
        zza(task, zza2);
        if (zza2.await(j, timeUnit)) {
            return zzb(task);
        }
        throw new TimeoutException("Timed out waiting for Task");
    }

    public static Task<Void> whenAll(Collection<? extends Task<?>> collection) {
        if (collection.isEmpty()) {
            return forResult(null);
        }
        for (Task task : collection) {
            if (task == null) {
                throw new NullPointerException("null tasks are not accepted");
            }
        }
        zzu zzu = new zzu();
        zzc zzc2 = new zzc(collection.size(), zzu);
        for (Task zza2 : collection) {
            zza(zza2, zzc2);
        }
        return zzu;
    }

    public static Task<Void> whenAll(Task<?>... taskArr) {
        if (taskArr.length == 0) {
            return forResult(null);
        }
        return whenAll((Collection<? extends Task<?>>) Arrays.asList(taskArr));
    }

    public static <TResult> Task<List<TResult>> whenAllSuccess(Collection<? extends Task<?>> collection) {
        return whenAll(collection).continueWith(new zzw(collection));
    }

    public static <TResult> Task<List<TResult>> whenAllSuccess(Task<?>... taskArr) {
        return whenAllSuccess((Collection<? extends Task<?>>) Arrays.asList(taskArr));
    }

    public static Task<List<Task<?>>> whenAllComplete(Collection<? extends Task<?>> collection) {
        return whenAll(collection).continueWithTask(new zzx(collection));
    }

    public static Task<List<Task<?>>> whenAllComplete(Task<?>... taskArr) {
        return whenAllComplete((Collection<? extends Task<?>>) Arrays.asList(taskArr));
    }

    private static <TResult> TResult zzb(Task<TResult> task) throws ExecutionException {
        if (task.isSuccessful()) {
            return task.getResult();
        }
        if (task.isCanceled()) {
            throw new CancellationException("Task is already canceled");
        }
        throw new ExecutionException(task.getException());
    }

    private static void zza(Task<?> task, zzb zzb2) {
        task.addOnSuccessListener(TaskExecutors.zzw, (OnSuccessListener<? super TResult>) zzb2);
        task.addOnFailureListener(TaskExecutors.zzw, (OnFailureListener) zzb2);
        task.addOnCanceledListener(TaskExecutors.zzw, (OnCanceledListener) zzb2);
    }

    private Tasks() {
    }
}
