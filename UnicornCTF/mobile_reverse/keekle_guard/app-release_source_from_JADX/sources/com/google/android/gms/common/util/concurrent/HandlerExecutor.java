package com.google.android.gms.common.util.concurrent;

import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.internal.common.zze;
import java.util.concurrent.Executor;

public class HandlerExecutor implements Executor {
    private final Handler handler;

    public HandlerExecutor(Looper looper) {
        this.handler = new zze(looper);
    }

    public void execute(Runnable runnable) {
        this.handler.post(runnable);
    }
}
