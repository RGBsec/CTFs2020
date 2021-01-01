package com.google.android.gms.common.internal.service;

import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.ApiOptions.NoOptions;
import com.google.android.gms.common.api.Api.ClientKey;

public final class Common {
    public static final Api<NoOptions> API = new Api<>("Common.API", zaph, CLIENT_KEY);
    public static final ClientKey<zai> CLIENT_KEY = new ClientKey<>();
    private static final AbstractClientBuilder<zai, NoOptions> zaph = new zab();
    public static final zac zapi = new zad();
}
