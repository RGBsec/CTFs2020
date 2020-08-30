package com.google.android.gms.tasks;

import java.util.concurrent.Executor;

final class zzm<TResult> implements zzq<TResult> {
    /* access modifiers changed from: private */
    public final Object mLock = new Object();
    private final Executor zzd;
    /* access modifiers changed from: private */
    public OnSuccessListener<? super TResult> zzp;

    public zzm(Executor executor, OnSuccessListener<? super TResult> onSuccessListener) {
        this.zzd = executor;
        this.zzp = onSuccessListener;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0010, code lost:
        r2.zzd.execute(new com.google.android.gms.tasks.zzn(r2, r3));
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void onComplete(com.google.android.gms.tasks.Task<TResult> r3) {
        /*
            r2 = this;
            boolean r0 = r3.isSuccessful()
            if (r0 == 0) goto L_0x001e
            java.lang.Object r0 = r2.mLock
            monitor-enter(r0)
            com.google.android.gms.tasks.OnSuccessListener<? super TResult> r1 = r2.zzp     // Catch:{ all -> 0x001b }
            if (r1 != 0) goto L_0x000f
            monitor-exit(r0)     // Catch:{ all -> 0x001b }
            return
        L_0x000f:
            monitor-exit(r0)     // Catch:{ all -> 0x001b }
            java.util.concurrent.Executor r0 = r2.zzd
            com.google.android.gms.tasks.zzn r1 = new com.google.android.gms.tasks.zzn
            r1.<init>(r2, r3)
            r0.execute(r1)
            goto L_0x001e
        L_0x001b:
            r3 = move-exception
            monitor-exit(r0)     // Catch:{ all -> 0x001b }
            throw r3
        L_0x001e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tasks.zzm.onComplete(com.google.android.gms.tasks.Task):void");
    }

    public final void cancel() {
        synchronized (this.mLock) {
            this.zzp = null;
        }
    }
}
