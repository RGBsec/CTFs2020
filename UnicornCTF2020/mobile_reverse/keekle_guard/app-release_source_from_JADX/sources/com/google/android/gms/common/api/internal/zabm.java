package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.internal.GoogleApiManager.zaa;
import com.google.android.gms.common.internal.BaseGmsClient.SignOutCallbacks;

final class zabm implements SignOutCallbacks {
    final /* synthetic */ zaa zaiy;

    zabm(zaa zaa) {
        this.zaiy = zaa;
    }

    public final void onSignOutComplete() {
        GoogleApiManager.this.handler.post(new zabn(this));
    }
}
