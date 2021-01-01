package com.google.android.gms.tasks;

import java.util.concurrent.Executor;

final class zzk<TResult> implements zzq<TResult> {
    /* access modifiers changed from: private */
    public final Object mLock = new Object();
    private final Executor zzd;
    /* access modifiers changed from: private */
    public OnFailureListener zzn;

    public zzk(Executor executor, OnFailureListener onFailureListener) {
        this.zzd = executor;
        this.zzn = onFailureListener;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:12:0x0016, code lost:
        r2.zzd.execute(new com.google.android.gms.tasks.zzl(r2, r3));
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void onComplete(com.google.android.gms.tasks.Task<TResult> r3) {
        /*
            r2 = this;
            boolean r0 = r3.isSuccessful()
            if (r0 != 0) goto L_0x0024
            boolean r0 = r3.isCanceled()
            if (r0 != 0) goto L_0x0024
            java.lang.Object r0 = r2.mLock
            monitor-enter(r0)
            com.google.android.gms.tasks.OnFailureListener r1 = r2.zzn     // Catch:{ all -> 0x0021 }
            if (r1 != 0) goto L_0x0015
            monitor-exit(r0)     // Catch:{ all -> 0x0021 }
            return
        L_0x0015:
            monitor-exit(r0)     // Catch:{ all -> 0x0021 }
            java.util.concurrent.Executor r0 = r2.zzd
            com.google.android.gms.tasks.zzl r1 = new com.google.android.gms.tasks.zzl
            r1.<init>(r2, r3)
            r0.execute(r1)
            goto L_0x0024
        L_0x0021:
            r3 = move-exception
            monitor-exit(r0)     // Catch:{ all -> 0x0021 }
            throw r3
        L_0x0024:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tasks.zzk.onComplete(com.google.android.gms.tasks.Task):void");
    }

    public final void cancel() {
        synchronized (this.mLock) {
            this.zzn = null;
        }
    }
}
