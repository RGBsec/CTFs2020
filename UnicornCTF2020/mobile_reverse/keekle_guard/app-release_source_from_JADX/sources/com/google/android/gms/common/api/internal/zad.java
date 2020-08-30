package com.google.android.gms.common.api.internal;

import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.GoogleApiManager.zaa;
import com.google.android.gms.tasks.TaskCompletionSource;

abstract class zad<T> extends zac {
    protected final TaskCompletionSource<T> zacn;

    public zad(int i, TaskCompletionSource<T> taskCompletionSource) {
        super(i);
        this.zacn = taskCompletionSource;
    }

    public void zaa(zaab zaab, boolean z) {
    }

    /* access modifiers changed from: protected */
    public abstract void zad(zaa<?> zaa) throws RemoteException;

    public void zaa(Status status) {
        this.zacn.trySetException(new ApiException(status));
    }

    public void zaa(RuntimeException runtimeException) {
        this.zacn.trySetException(runtimeException);
    }

    public final void zaa(zaa<?> zaa) throws DeadObjectException {
        try {
            zad(zaa);
        } catch (DeadObjectException e) {
            zaa(zab.zaa((RemoteException) e));
            throw e;
        } catch (RemoteException e2) {
            zaa(zab.zaa(e2));
        } catch (RuntimeException e3) {
            zaa(e3);
        }
    }
}
