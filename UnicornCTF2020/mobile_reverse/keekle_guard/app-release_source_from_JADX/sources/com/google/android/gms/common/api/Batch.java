package com.google.android.gms.common.api;

import com.google.android.gms.common.api.internal.BasePendingResult;
import java.util.ArrayList;
import java.util.List;

public final class Batch extends BasePendingResult<BatchResult> {
    /* access modifiers changed from: private */
    public final Object mLock;
    /* access modifiers changed from: private */
    public int zaaz;
    /* access modifiers changed from: private */
    public boolean zaba;
    /* access modifiers changed from: private */
    public boolean zabb;
    /* access modifiers changed from: private */
    public final PendingResult<?>[] zabc;

    public static final class Builder {
        private List<PendingResult<?>> zabe = new ArrayList();
        private GoogleApiClient zabf;

        public Builder(GoogleApiClient googleApiClient) {
            this.zabf = googleApiClient;
        }

        public final <R extends Result> BatchResultToken<R> add(PendingResult<R> pendingResult) {
            BatchResultToken<R> batchResultToken = new BatchResultToken<>(this.zabe.size());
            this.zabe.add(pendingResult);
            return batchResultToken;
        }

        public final Batch build() {
            return new Batch(this.zabe, this.zabf, null);
        }
    }

    private Batch(List<PendingResult<?>> list, GoogleApiClient googleApiClient) {
        super(googleApiClient);
        this.mLock = new Object();
        int size = list.size();
        this.zaaz = size;
        this.zabc = new PendingResult[size];
        if (list.isEmpty()) {
            setResult(new BatchResult(Status.RESULT_SUCCESS, this.zabc));
            return;
        }
        for (int i = 0; i < list.size(); i++) {
            PendingResult<?> pendingResult = (PendingResult) list.get(i);
            this.zabc[i] = pendingResult;
            pendingResult.addStatusListener(new zaa(this));
        }
    }

    public final void cancel() {
        super.cancel();
        for (PendingResult<?> cancel : this.zabc) {
            cancel.cancel();
        }
    }

    public final BatchResult createFailedResult(Status status) {
        return new BatchResult(status, this.zabc);
    }

    /* synthetic */ Batch(List list, GoogleApiClient googleApiClient, zaa zaa) {
        this(list, googleApiClient);
    }
}
