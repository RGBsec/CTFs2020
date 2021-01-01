package com.google.android.gms.tasks;

import java.util.concurrent.Executor;

final class zzg<TResult> implements zzq<TResult> {
    /* access modifiers changed from: private */
    public final Object mLock = new Object();
    private final Executor zzd;
    /* access modifiers changed from: private */
    public OnCanceledListener zzj;

    public zzg(Executor executor, OnCanceledListener onCanceledListener) {
        this.zzd = executor;
        this.zzj = onCanceledListener;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0010, code lost:
        r1.zzd.execute(new com.google.android.gms.tasks.zzh(r1));
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void onComplete(com.google.android.gms.tasks.Task r2) {
        /*
            r1 = this;
            boolean r2 = r2.isCanceled()
            if (r2 == 0) goto L_0x001e
            java.lang.Object r2 = r1.mLock
            monitor-enter(r2)
            com.google.android.gms.tasks.OnCanceledListener r0 = r1.zzj     // Catch:{ all -> 0x001b }
            if (r0 != 0) goto L_0x000f
            monitor-exit(r2)     // Catch:{ all -> 0x001b }
            return
        L_0x000f:
            monitor-exit(r2)     // Catch:{ all -> 0x001b }
            java.util.concurrent.Executor r2 = r1.zzd
            com.google.android.gms.tasks.zzh r0 = new com.google.android.gms.tasks.zzh
            r0.<init>(r1)
            r2.execute(r0)
            goto L_0x001e
        L_0x001b:
            r0 = move-exception
            monitor-exit(r2)     // Catch:{ all -> 0x001b }
            throw r0
        L_0x001e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tasks.zzg.onComplete(com.google.android.gms.tasks.Task):void");
    }

    public final void cancel() {
        synchronized (this.mLock) {
            this.zzj = null;
        }
    }
}
