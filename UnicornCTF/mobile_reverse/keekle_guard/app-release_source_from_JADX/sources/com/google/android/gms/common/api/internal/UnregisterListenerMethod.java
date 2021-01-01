package com.google.android.gms.common.api.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.internal.ListenerHolder.ListenerKey;
import com.google.android.gms.tasks.TaskCompletionSource;

public abstract class UnregisterListenerMethod<A extends AnyClient, L> {
    private final ListenerKey<L> zajl;

    protected UnregisterListenerMethod(ListenerKey<L> listenerKey) {
        this.zajl = listenerKey;
    }

    /* access modifiers changed from: protected */
    public abstract void unregisterListener(A a, TaskCompletionSource<Boolean> taskCompletionSource) throws RemoteException;

    public ListenerKey<L> getListenerKey() {
        return this.zajl;
    }
}
