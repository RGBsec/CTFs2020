package com.google.android.gms.common.internal;

import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.PendingResult.StatusListener;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.PendingResultUtil.ResultConverter;
import com.google.android.gms.common.internal.PendingResultUtil.zaa;
import com.google.android.gms.tasks.TaskCompletionSource;
import java.util.concurrent.TimeUnit;

final class zaj implements StatusListener {
    private final /* synthetic */ PendingResult zaov;
    private final /* synthetic */ TaskCompletionSource zaow;
    private final /* synthetic */ ResultConverter zaox;
    private final /* synthetic */ zaa zaoy;

    zaj(PendingResult pendingResult, TaskCompletionSource taskCompletionSource, ResultConverter resultConverter, zaa zaa) {
        this.zaov = pendingResult;
        this.zaow = taskCompletionSource;
        this.zaox = resultConverter;
        this.zaoy = zaa;
    }

    public final void onComplete(Status status) {
        if (status.isSuccess()) {
            this.zaow.setResult(this.zaox.convert(this.zaov.await(0, TimeUnit.MILLISECONDS)));
            return;
        }
        this.zaow.setException(this.zaoy.zaf(status));
    }
}
