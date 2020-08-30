package androidx.core.p005os;

import android.os.Build.VERSION;

/* renamed from: androidx.core.os.CancellationSignal */
public final class CancellationSignal {
    private boolean mCancelInProgress;
    private Object mCancellationSignalObj;
    private boolean mIsCanceled;
    private OnCancelListener mOnCancelListener;

    /* renamed from: androidx.core.os.CancellationSignal$OnCancelListener */
    public interface OnCancelListener {
        void onCancel();
    }

    public boolean isCanceled() {
        boolean z;
        synchronized (this) {
            z = this.mIsCanceled;
        }
        return z;
    }

    public void throwIfCanceled() {
        if (isCanceled()) {
            throw new OperationCanceledException();
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:11:?, code lost:
        r0.onCancel();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x0018, code lost:
        r3 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x001a, code lost:
        if (r1 == null) goto L_0x0034;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0020, code lost:
        if (android.os.Build.VERSION.SDK_INT < 16) goto L_0x0034;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0022, code lost:
        ((android.os.CancellationSignal) r1).cancel();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0029, code lost:
        monitor-enter(r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:20:?, code lost:
        r5.mCancelInProgress = false;
        notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x0030, code lost:
        throw r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x0034, code lost:
        monitor-enter(r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:?, code lost:
        r5.mCancelInProgress = false;
        notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x003a, code lost:
        monitor-exit(r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:0x003c, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0012, code lost:
        if (r0 == null) goto L_0x001a;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void cancel() {
        /*
            r5 = this;
            monitor-enter(r5)
            boolean r0 = r5.mIsCanceled     // Catch:{ all -> 0x0040 }
            if (r0 == 0) goto L_0x0007
            monitor-exit(r5)     // Catch:{ all -> 0x0040 }
            return
        L_0x0007:
            r0 = 1
            r5.mIsCanceled = r0     // Catch:{ all -> 0x0040 }
            r5.mCancelInProgress = r0     // Catch:{ all -> 0x0040 }
            androidx.core.os.CancellationSignal$OnCancelListener r0 = r5.mOnCancelListener     // Catch:{ all -> 0x0040 }
            java.lang.Object r1 = r5.mCancellationSignalObj     // Catch:{ all -> 0x0040 }
            monitor-exit(r5)     // Catch:{ all -> 0x0040 }
            r2 = 0
            if (r0 == 0) goto L_0x001a
            r0.onCancel()     // Catch:{ all -> 0x0018 }
            goto L_0x001a
        L_0x0018:
            r3 = move-exception
            goto L_0x0029
        L_0x001a:
            if (r1 == 0) goto L_0x0034
            int r3 = android.os.Build.VERSION.SDK_INT     // Catch:{ all -> 0x0018 }
            r4 = 16
            if (r3 < r4) goto L_0x0034
            r3 = r1
            android.os.CancellationSignal r3 = (android.os.CancellationSignal) r3     // Catch:{ all -> 0x0018 }
            r3.cancel()     // Catch:{ all -> 0x0018 }
            goto L_0x0034
        L_0x0029:
            monitor-enter(r5)
            r5.mCancelInProgress = r2     // Catch:{ all -> 0x0031 }
            r5.notifyAll()     // Catch:{ all -> 0x0031 }
            monitor-exit(r5)     // Catch:{ all -> 0x0031 }
            throw r3
        L_0x0031:
            r2 = move-exception
            monitor-exit(r5)     // Catch:{ all -> 0x0031 }
            throw r2
        L_0x0034:
            monitor-enter(r5)
            r5.mCancelInProgress = r2     // Catch:{ all -> 0x003d }
            r5.notifyAll()     // Catch:{ all -> 0x003d }
            monitor-exit(r5)     // Catch:{ all -> 0x003d }
            return
        L_0x003d:
            r2 = move-exception
            monitor-exit(r5)     // Catch:{ all -> 0x003d }
            throw r2
        L_0x0040:
            r0 = move-exception
            monitor-exit(r5)     // Catch:{ all -> 0x0040 }
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.p005os.CancellationSignal.cancel():void");
    }

    public void setOnCancelListener(OnCancelListener listener) {
        synchronized (this) {
            waitForCancelFinishedLocked();
            if (this.mOnCancelListener != listener) {
                this.mOnCancelListener = listener;
                if (this.mIsCanceled) {
                    if (listener != null) {
                        listener.onCancel();
                    }
                }
            }
        }
    }

    public Object getCancellationSignalObject() {
        Object obj;
        if (VERSION.SDK_INT < 16) {
            return null;
        }
        synchronized (this) {
            if (this.mCancellationSignalObj == null) {
                android.os.CancellationSignal cancellationSignal = new android.os.CancellationSignal();
                this.mCancellationSignalObj = cancellationSignal;
                if (this.mIsCanceled) {
                    cancellationSignal.cancel();
                }
            }
            obj = this.mCancellationSignalObj;
        }
        return obj;
    }

    private void waitForCancelFinishedLocked() {
        while (this.mCancelInProgress) {
            try {
                wait();
            } catch (InterruptedException e) {
            }
        }
    }
}
