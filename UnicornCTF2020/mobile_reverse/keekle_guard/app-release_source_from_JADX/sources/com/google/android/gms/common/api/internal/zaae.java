package com.google.android.gms.common.api.internal;

import android.app.Activity;
import androidx.collection.ArraySet;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.Preconditions;

public class zaae extends zal {
    private GoogleApiManager zabm;
    private final ArraySet<zai<?>> zafp = new ArraySet<>();

    public static void zaa(Activity activity, GoogleApiManager googleApiManager, zai<?> zai) {
        LifecycleFragment fragment = getFragment(activity);
        zaae zaae = (zaae) fragment.getCallbackOrNull("ConnectionlessLifecycleHelper", zaae.class);
        if (zaae == null) {
            zaae = new zaae(fragment);
        }
        zaae.zabm = googleApiManager;
        Preconditions.checkNotNull(zai, "ApiKey cannot be null");
        zaae.zafp.add(zai);
        googleApiManager.zaa(zaae);
    }

    private zaae(LifecycleFragment lifecycleFragment) {
        super(lifecycleFragment);
        this.mLifecycleFragment.addCallback("ConnectionlessLifecycleHelper", this);
    }

    public void onStart() {
        super.onStart();
        zaak();
    }

    public void onResume() {
        super.onResume();
        zaak();
    }

    public void onStop() {
        super.onStop();
        this.zabm.zab(this);
    }

    /* access modifiers changed from: protected */
    public final void zaa(ConnectionResult connectionResult, int i) {
        this.zabm.zaa(connectionResult, i);
    }

    /* access modifiers changed from: protected */
    public final void zao() {
        this.zabm.zao();
    }

    /* access modifiers changed from: 0000 */
    public final ArraySet<zai<?>> zaaj() {
        return this.zafp;
    }

    private final void zaak() {
        if (!this.zafp.isEmpty()) {
            this.zabm.zaa(this);
        }
    }
}
