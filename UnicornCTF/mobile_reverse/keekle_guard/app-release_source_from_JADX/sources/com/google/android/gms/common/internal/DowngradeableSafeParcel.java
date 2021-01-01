package com.google.android.gms.common.internal;

import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;

public abstract class DowngradeableSafeParcel extends AbstractSafeParcelable implements ReflectedParcelable {
    private static final Object zzdc = new Object();
    private static ClassLoader zzdd = null;
    private static Integer zzde = null;
    private boolean zzdf = false;

    /* access modifiers changed from: protected */
    public abstract boolean prepareForClientVersion(int i);

    private static ClassLoader zzp() {
        synchronized (zzdc) {
        }
        return null;
    }

    protected static Integer getUnparcelClientVersion() {
        synchronized (zzdc) {
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public boolean shouldDowngrade() {
        return this.zzdf;
    }

    public void setShouldDowngrade(boolean z) {
        this.zzdf = z;
    }

    protected static boolean canUnparcelSafely(String str) {
        zzp();
        return true;
    }
}
