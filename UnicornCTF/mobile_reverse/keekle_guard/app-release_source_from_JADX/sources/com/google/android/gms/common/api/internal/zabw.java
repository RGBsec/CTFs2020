package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Api.AnyClient;

public final class zabw {
    public final RegisterListenerMethod<AnyClient, ?> zajx;
    public final UnregisterListenerMethod<AnyClient, ?> zajy;

    public zabw(RegisterListenerMethod<AnyClient, ?> registerListenerMethod, UnregisterListenerMethod<AnyClient, ?> unregisterListenerMethod) {
        this.zajx = registerListenerMethod;
        this.zajy = unregisterListenerMethod;
    }
}
