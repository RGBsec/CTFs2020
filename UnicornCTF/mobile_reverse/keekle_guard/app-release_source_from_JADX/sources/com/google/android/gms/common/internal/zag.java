package com.google.android.gms.common.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.common.internal.BaseGmsClient.BaseOnConnectionFailedListener;

final class zag implements BaseOnConnectionFailedListener {
    private final /* synthetic */ OnConnectionFailedListener zaok;

    zag(OnConnectionFailedListener onConnectionFailedListener) {
        this.zaok = onConnectionFailedListener;
    }

    public final void onConnectionFailed(ConnectionResult connectionResult) {
        this.zaok.onConnectionFailed(connectionResult);
    }
}
