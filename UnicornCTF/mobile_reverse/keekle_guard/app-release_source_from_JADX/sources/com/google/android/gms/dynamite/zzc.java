package com.google.android.gms.dynamite;

import android.content.Context;
import com.google.android.gms.dynamite.DynamiteModule.LoadingException;
import com.google.android.gms.dynamite.DynamiteModule.VersionPolicy;
import com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zza;
import com.google.android.gms.dynamite.DynamiteModule.VersionPolicy.zzb;

final class zzc implements VersionPolicy {
    zzc() {
    }

    public final zzb zza(Context context, String str, zza zza) throws LoadingException {
        zzb zzb = new zzb();
        zzb.zzir = zza.getLocalVersion(context, str);
        if (zzb.zzir != 0) {
            zzb.zzit = -1;
        } else {
            zzb.zzis = zza.zza(context, str, true);
            if (zzb.zzis != 0) {
                zzb.zzit = 1;
            }
        }
        return zzb;
    }
}
