package com.google.android.gms.common.internal;

import android.os.Bundle;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.internal.BaseGmsClient.BaseConnectionCallbacks;

final class zaf implements BaseConnectionCallbacks {
    private final /* synthetic */ ConnectionCallbacks zaoj;

    zaf(ConnectionCallbacks connectionCallbacks) {
        this.zaoj = connectionCallbacks;
    }

    public final void onConnected(Bundle bundle) {
        this.zaoj.onConnected(bundle);
    }

    public final void onConnectionSuspended(int i) {
        this.zaoj.onConnectionSuspended(i);
    }
}
