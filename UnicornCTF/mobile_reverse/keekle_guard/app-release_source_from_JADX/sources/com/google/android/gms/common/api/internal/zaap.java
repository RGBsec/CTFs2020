package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.BaseGmsClient.ConnectionProgressReportCallbacks;

final class zaap extends zabf {
    private final /* synthetic */ ConnectionProgressReportCallbacks zago;

    zaap(zaan zaan, zabd zabd, ConnectionProgressReportCallbacks connectionProgressReportCallbacks) {
        this.zago = connectionProgressReportCallbacks;
        super(zabd);
    }

    public final void zaan() {
        this.zago.onReportServiceBinding(new ConnectionResult(16, null));
    }
}
