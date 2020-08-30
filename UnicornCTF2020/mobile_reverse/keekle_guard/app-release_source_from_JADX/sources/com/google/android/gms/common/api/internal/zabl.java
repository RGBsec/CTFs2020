package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.internal.GoogleApiManager.zaa;

final class zabl implements Runnable {
    private final /* synthetic */ zaa zaiy;
    private final /* synthetic */ ConnectionResult zaiz;

    zabl(zaa zaa, ConnectionResult connectionResult) {
        this.zaiy = zaa;
        this.zaiz = connectionResult;
    }

    public final void run() {
        this.zaiy.onConnectionFailed(this.zaiz);
    }
}
