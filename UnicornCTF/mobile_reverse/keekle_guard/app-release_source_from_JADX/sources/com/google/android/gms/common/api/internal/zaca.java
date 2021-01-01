package com.google.android.gms.common.api.internal;

import android.os.RemoteException;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.internal.RegistrationMethods.Builder;
import com.google.android.gms.tasks.TaskCompletionSource;

final class zaca extends RegisterListenerMethod<A, L> {
    private final /* synthetic */ Builder zakh;

    zaca(Builder builder, ListenerHolder listenerHolder, Feature[] featureArr, boolean z) {
        this.zakh = builder;
        super(listenerHolder, featureArr, z);
    }

    /* access modifiers changed from: protected */
    public final void registerListener(A a, TaskCompletionSource<Void> taskCompletionSource) throws RemoteException {
        this.zakh.zakb.accept(a, taskCompletionSource);
    }
}
