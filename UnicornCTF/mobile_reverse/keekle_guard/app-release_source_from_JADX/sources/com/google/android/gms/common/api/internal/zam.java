package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.Preconditions;

final class zam {
    private final int zadh;
    private final ConnectionResult zadi;

    zam(ConnectionResult connectionResult, int i) {
        Preconditions.checkNotNull(connectionResult);
        this.zadi = connectionResult;
        this.zadh = i;
    }

    /* access modifiers changed from: 0000 */
    public final int zar() {
        return this.zadh;
    }

    /* access modifiers changed from: 0000 */
    public final ConnectionResult getConnectionResult() {
        return this.zadi;
    }
}
