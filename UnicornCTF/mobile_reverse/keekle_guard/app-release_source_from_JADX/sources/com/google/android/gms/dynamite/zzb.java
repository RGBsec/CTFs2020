package com.google.android.gms.dynamite;

import android.content.Context;
import com.google.android.gms.dynamite.DynamiteModule.LoadingException;
import com.google.android.gms.dynamite.DynamiteModule.VersionPolicy;
import com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zza;

final class zzb implements VersionPolicy {
    zzb() {
    }

    public final com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zzb zza(Context context, String str, zza zza) throws LoadingException {
        com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zzb zzb = new com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zzb();
        zzb.zzis = zza.zza(context, str, true);
        if (zzb.zzis != 0) {
            zzb.zzit = 1;
        } else {
            zzb.zzir = zza.getLocalVersion(context, str);
            if (zzb.zzir != 0) {
                zzb.zzit = -1;
            }
        }
        return zzb;
    }
}
