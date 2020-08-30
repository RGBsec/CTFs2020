package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.internal.BackgroundDetector.BackgroundStateChangeListener;

final class zabi implements BackgroundStateChangeListener {
    private final /* synthetic */ GoogleApiManager zaim;

    zabi(GoogleApiManager googleApiManager) {
        this.zaim = googleApiManager;
    }

    public final void onBackgroundStateChanged(boolean z) {
        this.zaim.handler.sendMessage(this.zaim.handler.obtainMessage(1, Boolean.valueOf(z)));
    }
}
