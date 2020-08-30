package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.internal.RegistrationMethods.Builder;
import com.google.android.gms.tasks.TaskCompletionSource;

final /* synthetic */ class zabz implements RemoteCall {
    private final Builder zakg;

    zabz(Builder builder) {
        this.zakg = builder;
    }

    public final void accept(Object obj, Object obj2) {
        this.zakg.zaa((AnyClient) obj, (TaskCompletionSource) obj2);
    }
}
