package com.google.android.gms.signin;

import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.ClientKey;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.signin.internal.SignInClientImpl;

public final class zaa {
    public static final Api<SignInOptions> API = new Api<>("SignIn.API", zaph, CLIENT_KEY);
    private static final ClientKey<SignInClientImpl> CLIENT_KEY = new ClientKey<>();
    public static final AbstractClientBuilder<SignInClientImpl, SignInOptions> zaph = new zab();
    private static final Scope zar = new Scope(Scopes.PROFILE);
    private static final ClientKey<SignInClientImpl> zars = new ClientKey<>();
    private static final AbstractClientBuilder<SignInClientImpl, Object> zart = new zac();
    private static final Api<Object> zaru = new Api<>("SignIn.INTERNAL_API", zart, zars);
    private static final Scope zas = new Scope("email");
}
