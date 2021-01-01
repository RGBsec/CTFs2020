package com.google.android.gms.common.internal.service;

import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation.ResultHolder;

final class zaf extends zaa {
    private final ResultHolder<Status> mResultHolder;

    public zaf(ResultHolder<Status> resultHolder) {
        this.mResultHolder = resultHolder;
    }

    public final void zaj(int i) throws RemoteException {
        this.mResultHolder.setResult(new Status(i));
    }
}
