package com.google.android.gms.common.internal;

import android.util.Log;

public final class GmsLogger {
    private static final int zzef = 15;
    private static final String zzeg = null;
    private final String zzeh;
    private final String zzei;

    public GmsLogger(String str, String str2) {
        Preconditions.checkNotNull(str, "log tag cannot be null");
        Preconditions.checkArgument(str.length() <= 23, "tag \"%s\" is longer than the %d character maximum", str, Integer.valueOf(23));
        this.zzeh = str;
        if (str2 == null || str2.length() <= 0) {
            this.zzei = null;
        } else {
            this.zzei = str2;
        }
    }

    public final boolean canLogPii() {
        return false;
    }

    public GmsLogger(String str) {
        this(str, null);
    }

    public final boolean canLog(int i) {
        return Log.isLoggable(this.zzeh, i);
    }

    /* renamed from: d */
    public final void mo6737d(String str, String str2) {
        if (canLog(3)) {
            Log.d(str, zzh(str2));
        }
    }

    /* renamed from: d */
    public final void mo6738d(String str, String str2, Throwable th) {
        if (canLog(3)) {
            Log.d(str, zzh(str2), th);
        }
    }

    /* renamed from: v */
    public final void mo6746v(String str, String str2) {
        if (canLog(2)) {
            Log.v(str, zzh(str2));
        }
    }

    /* renamed from: v */
    public final void mo6747v(String str, String str2, Throwable th) {
        if (canLog(2)) {
            Log.v(str, zzh(str2), th);
        }
    }

    /* renamed from: i */
    public final void mo6742i(String str, String str2) {
        if (canLog(4)) {
            Log.i(str, zzh(str2));
        }
    }

    /* renamed from: i */
    public final void mo6743i(String str, String str2, Throwable th) {
        if (canLog(4)) {
            Log.i(str, zzh(str2), th);
        }
    }

    /* renamed from: w */
    public final void mo6748w(String str, String str2) {
        if (canLog(5)) {
            Log.w(str, zzh(str2));
        }
    }

    /* renamed from: w */
    public final void mo6749w(String str, String str2, Throwable th) {
        if (canLog(5)) {
            Log.w(str, zzh(str2), th);
        }
    }

    public final void wfmt(String str, String str2, Object... objArr) {
        if (canLog(5)) {
            Log.w(this.zzeh, zza(str2, objArr));
        }
    }

    /* renamed from: e */
    public final void mo6739e(String str, String str2) {
        if (canLog(6)) {
            Log.e(str, zzh(str2));
        }
    }

    /* renamed from: e */
    public final void mo6740e(String str, String str2, Throwable th) {
        if (canLog(6)) {
            Log.e(str, zzh(str2), th);
        }
    }

    public final void efmt(String str, String str2, Object... objArr) {
        if (canLog(6)) {
            Log.e(str, zza(str2, objArr));
        }
    }

    public final void wtf(String str, String str2, Throwable th) {
        if (canLog(7)) {
            Log.e(str, zzh(str2), th);
            Log.wtf(str, zzh(str2), th);
        }
    }

    public final void pii(String str, String str2) {
        if (canLogPii()) {
            String valueOf = String.valueOf(str);
            String str3 = " PII_LOG";
            Log.i(str3.length() != 0 ? valueOf.concat(str3) : new String(valueOf), zzh(str2));
        }
    }

    public final void pii(String str, String str2, Throwable th) {
        if (canLogPii()) {
            String valueOf = String.valueOf(str);
            String str3 = " PII_LOG";
            Log.i(str3.length() != 0 ? valueOf.concat(str3) : new String(valueOf), zzh(str2), th);
        }
    }

    private final String zzh(String str) {
        String str2 = this.zzei;
        if (str2 == null) {
            return str;
        }
        return str2.concat(str);
    }

    private final String zza(String str, Object... objArr) {
        String format = String.format(str, objArr);
        String str2 = this.zzei;
        if (str2 == null) {
            return format;
        }
        return str2.concat(format);
    }
}
