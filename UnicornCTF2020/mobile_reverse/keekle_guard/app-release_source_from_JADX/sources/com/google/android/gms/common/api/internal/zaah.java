package com.google.android.gms.common.api.internal;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;

public final class zaah implements zabd {
    /* access modifiers changed from: private */
    public final zabe zaft;
    private boolean zafu = false;

    public zaah(zabe zabe) {
        this.zaft = zabe;
    }

    public final void begin() {
    }

    public final void onConnected(Bundle bundle) {
    }

    public final void zaa(ConnectionResult connectionResult, Api<?> api, boolean z) {
    }

    public final <A extends AnyClient, R extends Result, T extends ApiMethodImpl<R, A>> T enqueue(T t) {
        return execute(t);
    }

    /* JADX WARNING: type inference failed for: r0v11, types: [com.google.android.gms.common.api.Api$SimpleClient] */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final <A extends com.google.android.gms.common.api.Api.AnyClient, T extends com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl<? extends com.google.android.gms.common.api.Result, A>> T execute(T r4) {
        /*
            r3 = this;
            com.google.android.gms.common.api.internal.zabe r0 = r3.zaft     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.internal.zaaw r0 = r0.zaee     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.internal.zacp r0 = r0.zahf     // Catch:{ DeadObjectException -> 0x004b }
            r0.zab(r4)     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.internal.zabe r0 = r3.zaft     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.internal.zaaw r0 = r0.zaee     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.Api$AnyClientKey r1 = r4.getClientKey()     // Catch:{ DeadObjectException -> 0x004b }
            java.util.Map<com.google.android.gms.common.api.Api$AnyClientKey<?>, com.google.android.gms.common.api.Api$Client> r0 = r0.zagz     // Catch:{ DeadObjectException -> 0x004b }
            java.lang.Object r0 = r0.get(r1)     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.Api$Client r0 = (com.google.android.gms.common.api.Api.Client) r0     // Catch:{ DeadObjectException -> 0x004b }
            java.lang.String r1 = "Appropriate Api was not requested."
            com.google.android.gms.common.internal.Preconditions.checkNotNull(r0, r1)     // Catch:{ DeadObjectException -> 0x004b }
            boolean r1 = r0.isConnected()     // Catch:{ DeadObjectException -> 0x004b }
            if (r1 != 0) goto L_0x003d
            com.google.android.gms.common.api.internal.zabe r1 = r3.zaft     // Catch:{ DeadObjectException -> 0x004b }
            java.util.Map<com.google.android.gms.common.api.Api$AnyClientKey<?>, com.google.android.gms.common.ConnectionResult> r1 = r1.zahp     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.Api$AnyClientKey r2 = r4.getClientKey()     // Catch:{ DeadObjectException -> 0x004b }
            boolean r1 = r1.containsKey(r2)     // Catch:{ DeadObjectException -> 0x004b }
            if (r1 == 0) goto L_0x003d
            com.google.android.gms.common.api.Status r0 = new com.google.android.gms.common.api.Status     // Catch:{ DeadObjectException -> 0x004b }
            r1 = 17
            r0.<init>(r1)     // Catch:{ DeadObjectException -> 0x004b }
            r4.setFailedResult(r0)     // Catch:{ DeadObjectException -> 0x004b }
            goto L_0x0055
        L_0x003d:
            boolean r1 = r0 instanceof com.google.android.gms.common.internal.SimpleClientAdapter     // Catch:{ DeadObjectException -> 0x004b }
            if (r1 == 0) goto L_0x0047
            com.google.android.gms.common.internal.SimpleClientAdapter r0 = (com.google.android.gms.common.internal.SimpleClientAdapter) r0     // Catch:{ DeadObjectException -> 0x004b }
            com.google.android.gms.common.api.Api$SimpleClient r0 = r0.getClient()     // Catch:{ DeadObjectException -> 0x004b }
        L_0x0047:
            r4.run(r0)     // Catch:{ DeadObjectException -> 0x004b }
            goto L_0x0055
        L_0x004b:
            com.google.android.gms.common.api.internal.zabe r0 = r3.zaft
            com.google.android.gms.common.api.internal.zaai r1 = new com.google.android.gms.common.api.internal.zaai
            r1.<init>(r3, r3)
            r0.zaa(r1)
        L_0x0055:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.internal.zaah.execute(com.google.android.gms.common.api.internal.BaseImplementation$ApiMethodImpl):com.google.android.gms.common.api.internal.BaseImplementation$ApiMethodImpl");
    }

    public final boolean disconnect() {
        if (this.zafu) {
            return false;
        }
        if (this.zaft.zaee.zaax()) {
            this.zafu = true;
            for (zacm zabv : this.zaft.zaee.zahe) {
                zabv.zabv();
            }
            return false;
        }
        this.zaft.zaf(null);
        return true;
    }

    public final void connect() {
        if (this.zafu) {
            this.zafu = false;
            this.zaft.zaa((zabf) new zaaj(this, this));
        }
    }

    public final void onConnectionSuspended(int i) {
        this.zaft.zaf(null);
        this.zaft.zaht.zab(i, this.zafu);
    }

    /* access modifiers changed from: 0000 */
    public final void zaam() {
        if (this.zafu) {
            this.zafu = false;
            this.zaft.zaee.zahf.release();
            disconnect();
        }
    }
}
