package com.google.android.gms.common.logging;

import android.util.Log;
import com.google.android.gms.common.internal.GmsLogger;
import java.util.Locale;

public class Logger {
    private final String mTag;
    private final String zzei;
    private final GmsLogger zzew;
    private final int zzex;

    public Logger(String str, String... strArr) {
        String str2;
        if (strArr.length == 0) {
            str2 = "";
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (String str3 : strArr) {
                if (sb.length() > 1) {
                    sb.append(",");
                }
                sb.append(str3);
            }
            sb.append(']');
            sb.append(' ');
            str2 = sb.toString();
        }
        this(str, str2);
    }

    private Logger(String str, String str2) {
        this.zzei = str2;
        this.mTag = str;
        this.zzew = new GmsLogger(str);
        int i = 2;
        while (7 >= i && !Log.isLoggable(this.mTag, i)) {
            i++;
        }
        this.zzex = i;
    }

    public boolean isLoggable(int i) {
        return this.zzex <= i;
    }

    /* renamed from: v */
    public void mo6857v(String str, Object... objArr) {
        if (isLoggable(2)) {
            Log.v(this.mTag, format(str, objArr));
        }
    }

    /* renamed from: d */
    public void mo6852d(String str, Object... objArr) {
        if (isLoggable(3)) {
            Log.d(this.mTag, format(str, objArr));
        }
    }

    /* renamed from: i */
    public void mo6855i(String str, Object... objArr) {
        Log.i(this.mTag, format(str, objArr));
    }

    /* renamed from: w */
    public void mo6858w(String str, Object... objArr) {
        Log.w(this.mTag, format(str, objArr));
    }

    /* renamed from: e */
    public void mo6854e(String str, Object... objArr) {
        Log.e(this.mTag, format(str, objArr));
    }

    /* renamed from: e */
    public void mo6853e(String str, Throwable th, Object... objArr) {
        Log.e(this.mTag, format(str, objArr), th);
    }

    public void wtf(String str, Throwable th, Object... objArr) {
        Log.wtf(this.mTag, format(str, objArr), th);
    }

    public void wtf(Throwable th) {
        Log.wtf(this.mTag, th);
    }

    private final String format(String str, Object... objArr) {
        if (objArr != null && objArr.length > 0) {
            str = String.format(Locale.US, str, objArr);
        }
        return this.zzei.concat(str);
    }
}
