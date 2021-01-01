package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.util.BiConsumer;
import com.google.android.gms.tasks.TaskCompletionSource;

final /* synthetic */ class zacj implements RemoteCall {
    private final BiConsumer zakf;

    zacj(BiConsumer biConsumer) {
        this.zakf = biConsumer;
    }

    public final void accept(Object obj, Object obj2) {
        this.zakf.accept((AnyClient) obj, (TaskCompletionSource) obj2);
    }
}
