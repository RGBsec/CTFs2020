package com.google.android.gms.common.internal;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import java.util.HashSet;
import java.util.Set;

final class zzf implements ServiceConnection {
    private ComponentName mComponentName;
    private int mState = 2;
    private IBinder zzcz;
    private final Set<ServiceConnection> zzdz = new HashSet();
    private boolean zzea;
    private final zza zzeb;
    private final /* synthetic */ zze zzec;

    public zzf(zze zze, zza zza) {
        this.zzec = zze;
        this.zzeb = zza;
    }

    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        synchronized (this.zzec.zzdu) {
            this.zzec.mHandler.removeMessages(1, this.zzeb);
            this.zzcz = iBinder;
            this.mComponentName = componentName;
            for (ServiceConnection onServiceConnected : this.zzdz) {
                onServiceConnected.onServiceConnected(componentName, iBinder);
            }
            this.mState = 1;
        }
    }

    public final void onServiceDisconnected(ComponentName componentName) {
        synchronized (this.zzec.zzdu) {
            this.zzec.mHandler.removeMessages(1, this.zzeb);
            this.zzcz = null;
            this.mComponentName = componentName;
            for (ServiceConnection onServiceDisconnected : this.zzdz) {
                onServiceDisconnected.onServiceDisconnected(componentName);
            }
            this.mState = 2;
        }
    }

    public final void zze(String str) {
        this.mState = 3;
        boolean zza = this.zzec.zzdw.zza(this.zzec.zzdv, str, this.zzeb.zzb(this.zzec.zzdv), this, this.zzeb.zzq());
        this.zzea = zza;
        if (zza) {
            this.zzec.mHandler.sendMessageDelayed(this.zzec.mHandler.obtainMessage(1, this.zzeb), this.zzec.zzdy);
            return;
        }
        this.mState = 2;
        try {
            this.zzec.zzdw.unbindService(this.zzec.zzdv, this);
        } catch (IllegalArgumentException unused) {
        }
    }

    public final void zzf(String str) {
        this.zzec.mHandler.removeMessages(1, this.zzeb);
        this.zzec.zzdw.unbindService(this.zzec.zzdv, this);
        this.zzea = false;
        this.mState = 2;
    }

    public final void zza(ServiceConnection serviceConnection, String str) {
        this.zzec.zzdw;
        this.zzec.zzdv;
        this.zzeb.zzb(this.zzec.zzdv);
        this.zzdz.add(serviceConnection);
    }

    public final void zzb(ServiceConnection serviceConnection, String str) {
        this.zzec.zzdw;
        this.zzec.zzdv;
        this.zzdz.remove(serviceConnection);
    }

    public final boolean isBound() {
        return this.zzea;
    }

    public final int getState() {
        return this.mState;
    }

    public final boolean zza(ServiceConnection serviceConnection) {
        return this.zzdz.contains(serviceConnection);
    }

    public final boolean zzr() {
        return this.zzdz.isEmpty();
    }

    public final IBinder getBinder() {
        return this.zzcz;
    }

    public final ComponentName getComponentName() {
        return this.mComponentName;
    }
}
