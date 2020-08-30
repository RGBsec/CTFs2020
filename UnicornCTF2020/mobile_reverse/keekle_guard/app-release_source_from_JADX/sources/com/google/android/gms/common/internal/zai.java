package com.google.android.gms.common.internal;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.PendingResultUtil.zaa;

final class zai implements zaa {
    zai() {
    }

    public final ApiException zaf(Status status) {
        return ApiExceptionUtil.fromStatus(status);
    }
}
