package com.google.android.gms.common.api.internal;

import android.content.Context;
import android.os.Looper;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.ApiOptions;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;

public final class zabp<O extends ApiOptions> extends zaag {
    private final GoogleApi<O> zajh;

    public zabp(GoogleApi<O> googleApi) {
        super("Method is not supported by connectionless client. APIs supporting connectionless client must not call this method.");
        this.zajh = googleApi;
    }

    public final void zaa(zacm zacm) {
    }

    public final void zab(zacm zacm) {
    }

    public final <A extends AnyClient, R extends Result, T extends ApiMethodImpl<R, A>> T enqueue(T t) {
        return this.zajh.doRead(t);
    }

    public final <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T execute(T t) {
        return this.zajh.doWrite(t);
    }

    public final Looper getLooper() {
        return this.zajh.getLooper();
    }

    public final Context getContext() {
        return this.zajh.getApplicationContext();
    }
}
