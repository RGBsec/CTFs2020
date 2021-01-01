package com.google.android.gms.common;

import java.util.concurrent.Callable;

final class zzo extends zzm {
    private final Callable<String> zzaf;

    private zzo(Callable<String> callable) {
        super(false, null, null);
        this.zzaf = callable;
    }

    /* access modifiers changed from: 0000 */
    public final String getErrorMessage() {
        try {
            return (String) this.zzaf.call();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
