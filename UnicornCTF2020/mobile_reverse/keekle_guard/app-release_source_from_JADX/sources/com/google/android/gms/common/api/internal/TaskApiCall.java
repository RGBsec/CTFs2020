package com.google.android.gms.common.api.internal;

import android.os.RemoteException;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.util.BiConsumer;
import com.google.android.gms.tasks.TaskCompletionSource;

public abstract class TaskApiCall<A extends AnyClient, ResultT> {
    private final Feature[] zake;
    private final boolean zakl;

    public static class Builder<A extends AnyClient, ResultT> {
        private Feature[] zake;
        private boolean zakl;
        /* access modifiers changed from: private */
        public RemoteCall<A, TaskCompletionSource<ResultT>> zakm;

        private Builder() {
            this.zakl = true;
        }

        @Deprecated
        public Builder<A, ResultT> execute(BiConsumer<A, TaskCompletionSource<ResultT>> biConsumer) {
            this.zakm = new zacj(biConsumer);
            return this;
        }

        public Builder<A, ResultT> run(RemoteCall<A, TaskCompletionSource<ResultT>> remoteCall) {
            this.zakm = remoteCall;
            return this;
        }

        public Builder<A, ResultT> setFeatures(Feature... featureArr) {
            this.zake = featureArr;
            return this;
        }

        public Builder<A, ResultT> setAutoResolveMissingFeatures(boolean z) {
            this.zakl = z;
            return this;
        }

        public TaskApiCall<A, ResultT> build() {
            Preconditions.checkArgument(this.zakm != null, "execute parameter required");
            return new zack(this, this.zake, this.zakl);
        }
    }

    @Deprecated
    public TaskApiCall() {
        this.zake = null;
        this.zakl = false;
    }

    /* access modifiers changed from: protected */
    public abstract void doExecute(A a, TaskCompletionSource<ResultT> taskCompletionSource) throws RemoteException;

    private TaskApiCall(Feature[] featureArr, boolean z) {
        this.zake = featureArr;
        this.zakl = z;
    }

    public final Feature[] zabt() {
        return this.zake;
    }

    public boolean shouldAutoResolveMissingFeatures() {
        return this.zakl;
    }

    public static <A extends AnyClient, ResultT> Builder<A, ResultT> builder() {
        return new Builder<>();
    }
}
