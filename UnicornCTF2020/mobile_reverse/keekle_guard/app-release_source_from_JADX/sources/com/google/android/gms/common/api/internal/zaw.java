package com.google.android.gms.common.api.internal;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.ApiOptions;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.GoogleApi;
import com.google.android.gms.common.api.internal.GoogleApiManager.zaa;
import com.google.android.gms.common.internal.ClientSettings;
import com.google.android.gms.signin.SignInOptions;
import com.google.android.gms.signin.zad;

public final class zaw<O extends ApiOptions> extends GoogleApi<O> {
    private final AbstractClientBuilder<? extends zad, SignInOptions> zace;
    private final Client zaer;
    private final zaq zaes;
    private final ClientSettings zaet;

    public zaw(Context context, Api<O> api, Looper looper, Client client, zaq zaq, ClientSettings clientSettings, AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder) {
        super(context, api, looper);
        this.zaer = client;
        this.zaes = zaq;
        this.zaet = clientSettings;
        this.zace = abstractClientBuilder;
        this.zabm.zaa((GoogleApi<?>) this);
    }

    public final Client zaab() {
        return this.zaer;
    }

    public final Client zaa(Looper looper, zaa<O> zaa) {
        this.zaes.zaa(zaa);
        return this.zaer;
    }

    public final zace zaa(Context context, Handler handler) {
        return new zace(context, handler, this.zaet, this.zace);
    }
}
