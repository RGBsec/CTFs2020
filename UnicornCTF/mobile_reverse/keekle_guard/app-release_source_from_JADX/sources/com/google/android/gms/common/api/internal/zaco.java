package com.google.android.gms.common.api.internal;

import android.os.Looper;
import android.os.Message;
import android.util.Log;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.base.zap;

final class zaco extends zap {
    private final /* synthetic */ zacm zakw;

    public zaco(zacm zacm, Looper looper) {
        this.zakw = zacm;
        super(looper);
    }

    public final void handleMessage(Message message) {
        int i = message.what;
        if (i == 0) {
            PendingResult pendingResult = (PendingResult) message.obj;
            synchronized (this.zakw.zado) {
                if (pendingResult == null) {
                    this.zakw.zakp.zad(new Status(13, "Transform returned null"));
                } else if (pendingResult instanceof zacd) {
                    this.zakw.zakp.zad(((zacd) pendingResult).getStatus());
                } else {
                    this.zakw.zakp.zaa(pendingResult);
                }
            }
        } else if (i != 1) {
            int i2 = message.what;
            StringBuilder sb = new StringBuilder(70);
            sb.append("TransformationResultHandler received unknown message type: ");
            sb.append(i2);
            Log.e("TransformedResultImpl", sb.toString());
        } else {
            RuntimeException runtimeException = (RuntimeException) message.obj;
            String str = "TransformedResultImpl";
            String str2 = "Runtime exception on the transformation worker thread: ";
            String valueOf = String.valueOf(runtimeException.getMessage());
            Log.e(str, valueOf.length() != 0 ? str2.concat(valueOf) : new String(str2));
            throw runtimeException;
        }
    }
}
