package com.google.android.gms.common.stats;

import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.common.util.zza;
import java.util.Arrays;
import java.util.List;

public class WakeLockTracker {
    private static WakeLockTracker zzgc = new WakeLockTracker();
    private static Boolean zzgd;
    private static boolean zzge = false;

    public static WakeLockTracker getInstance() {
        return zzgc;
    }

    public void registerAcquireEvent(Context context, Intent intent, String str, String str2, String str3, int i, String str4) {
        Intent intent2 = intent;
        Context context2 = context;
        registerEvent(context2, intent.getStringExtra(LoggingConstants.EXTRA_WAKE_LOCK_KEY), 7, str, str2, str3, i, Arrays.asList(new String[]{str4}));
    }

    public void registerReleaseEvent(Context context, Intent intent) {
        registerEvent(context, intent.getStringExtra(LoggingConstants.EXTRA_WAKE_LOCK_KEY), 8, null, null, null, 0, null);
    }

    public void registerEvent(Context context, String str, int i, String str2, String str3, String str4, int i2, List<String> list) {
        registerEvent(context, str, i, str2, str3, str4, i2, list, 0);
    }

    public void registerEvent(Context context, String str, int i, String str2, String str3, String str4, int i2, List<String> list, long j) {
        int i3 = i;
        if (zzw()) {
            if (TextUtils.isEmpty(str)) {
                String str5 = "missing wakeLock key. ";
                String valueOf = String.valueOf(str);
                Log.e("WakeLockTracker", valueOf.length() != 0 ? str5.concat(valueOf) : new String(str5));
                return;
            }
            if (7 == i3 || 8 == i3 || 10 == i3 || 11 == i3) {
                WakeLockEvent wakeLockEvent = r0;
                WakeLockEvent wakeLockEvent2 = new WakeLockEvent(System.currentTimeMillis(), i, str2, i2, StatsUtils.zza(list), str, SystemClock.elapsedRealtime(), zza.zzg(context), str3, StatsUtils.zzi(context.getPackageName()), zza.zzh(context), j, str4, false);
                zza(context, wakeLockEvent);
            }
        }
    }

    public void registerDeadlineEvent(Context context, String str, String str2, String str3, int i, List<String> list, boolean z, long j) {
        if (zzw()) {
            WakeLockEvent wakeLockEvent = new WakeLockEvent(System.currentTimeMillis(), 16, str, i, StatsUtils.zza(list), null, j, zza.zzg(context), str2, StatsUtils.zzi(context.getPackageName()), zza.zzh(context), 0, str3, z);
            zza(context, wakeLockEvent);
        }
    }

    private static void zza(Context context, WakeLockEvent wakeLockEvent) {
        try {
            context.startService(new Intent().setComponent(LoggingConstants.zzfg).putExtra("com.google.android.gms.common.stats.EXTRA_LOG_EVENT", wakeLockEvent));
        } catch (Exception e) {
            Log.wtf("WakeLockTracker", e);
        }
    }

    private static boolean zzw() {
        if (zzgd == null) {
            zzgd = Boolean.valueOf(false);
        }
        return zzgd.booleanValue();
    }
}
