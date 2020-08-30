package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.common.api.Status;

final class zaaz implements OnConnectionFailedListener {
    private final /* synthetic */ StatusPendingResult zahj;

    zaaz(zaaw zaaw, StatusPendingResult statusPendingResult) {
        this.zahj = statusPendingResult;
    }

    public final void onConnectionFailed(ConnectionResult connectionResult) {
        this.zahj.setResult(new Status(8));
    }
}
