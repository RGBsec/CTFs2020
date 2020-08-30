package com.google.android.gms.common.api.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.AnyClientKey;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;
import com.google.android.gms.common.internal.ClientSettings;
import com.google.android.gms.common.internal.ClientSettings.OptionalApiSettings;
import com.google.android.gms.common.internal.IAccountAccessor;
import com.google.android.gms.common.internal.ResolveAccountResponse;
import com.google.android.gms.signin.SignInOptions;
import com.google.android.gms.signin.internal.zaj;
import com.google.android.gms.signin.zad;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.locks.Lock;

public final class zaak implements zabd {
    /* access modifiers changed from: private */
    public final Context mContext;
    private final AbstractClientBuilder<? extends zad, SignInOptions> zace;
    /* access modifiers changed from: private */
    public final Lock zaeo;
    /* access modifiers changed from: private */
    public final ClientSettings zaet;
    private final Map<Api<?>, Boolean> zaew;
    /* access modifiers changed from: private */
    public final GoogleApiAvailabilityLight zaey;
    private ConnectionResult zafh;
    /* access modifiers changed from: private */
    public final zabe zaft;
    private int zafw;
    private int zafx = 0;
    private int zafy;
    private final Bundle zafz = new Bundle();
    private final Set<AnyClientKey> zaga = new HashSet();
    /* access modifiers changed from: private */
    public zad zagb;
    private boolean zagc;
    /* access modifiers changed from: private */
    public boolean zagd;
    private boolean zage;
    /* access modifiers changed from: private */
    public IAccountAccessor zagf;
    private boolean zagg;
    private boolean zagh;
    private ArrayList<Future<?>> zagi = new ArrayList<>();

    public zaak(zabe zabe, ClientSettings clientSettings, Map<Api<?>, Boolean> map, GoogleApiAvailabilityLight googleApiAvailabilityLight, AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder, Lock lock, Context context) {
        this.zaft = zabe;
        this.zaet = clientSettings;
        this.zaew = map;
        this.zaey = googleApiAvailabilityLight;
        this.zace = abstractClientBuilder;
        this.zaeo = lock;
        this.mContext = context;
    }

    private static String zad(int i) {
        return i != 0 ? i != 1 ? "UNKNOWN" : "STEP_GETTING_REMOTE_SERVICE" : "STEP_SERVICE_BINDINGS_AND_SIGN_IN";
    }

    public final void connect() {
    }

    public final void begin() {
        this.zaft.zahp.clear();
        this.zagd = false;
        this.zafh = null;
        this.zafx = 0;
        this.zagc = true;
        this.zage = false;
        this.zagg = false;
        HashMap hashMap = new HashMap();
        boolean z = false;
        for (Api api : this.zaew.keySet()) {
            Client client = (Client) this.zaft.zagz.get(api.getClientKey());
            z |= api.zah().getPriority() == 1;
            boolean booleanValue = ((Boolean) this.zaew.get(api)).booleanValue();
            if (client.requiresSignIn()) {
                this.zagd = true;
                if (booleanValue) {
                    this.zaga.add(api.getClientKey());
                } else {
                    this.zagc = false;
                }
            }
            hashMap.put(client, new zaam(this, api, booleanValue));
        }
        if (z) {
            this.zagd = false;
        }
        if (this.zagd) {
            this.zaet.setClientSessionId(Integer.valueOf(System.identityHashCode(this.zaft.zaee)));
            zaat zaat = new zaat(this, null);
            AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder = this.zace;
            Context context = this.mContext;
            Looper looper = this.zaft.zaee.getLooper();
            ClientSettings clientSettings = this.zaet;
            this.zagb = (zad) abstractClientBuilder.buildClient(context, looper, clientSettings, clientSettings.getSignInOptions(), zaat, zaat);
        }
        this.zafy = this.zaft.zagz.size();
        this.zagi.add(zabh.zabb().submit(new zaan(this, hashMap)));
    }

    /* access modifiers changed from: private */
    public final boolean zaao() {
        int i = this.zafy - 1;
        this.zafy = i;
        if (i > 0) {
            return false;
        }
        if (i < 0) {
            String str = "GoogleApiClientConnecting";
            Log.w(str, this.zaft.zaee.zaay());
            Log.wtf(str, "GoogleApiClient received too many callbacks for the given step. Clients may be in an unexpected state; GoogleApiClient will now disconnect.", new Exception());
            zae(new ConnectionResult(8, null));
            return false;
        } else if (this.zafh == null) {
            return true;
        } else {
            this.zaft.zahs = this.zafw;
            zae(this.zafh);
            return false;
        }
    }

    /* access modifiers changed from: private */
    public final void zaa(zaj zaj) {
        if (zac(0)) {
            ConnectionResult connectionResult = zaj.getConnectionResult();
            if (connectionResult.isSuccess()) {
                ResolveAccountResponse zacx = zaj.zacx();
                ConnectionResult connectionResult2 = zacx.getConnectionResult();
                if (!connectionResult2.isSuccess()) {
                    String valueOf = String.valueOf(connectionResult2);
                    StringBuilder sb = new StringBuilder(String.valueOf(valueOf).length() + 48);
                    sb.append("Sign-in succeeded with resolve account failure: ");
                    sb.append(valueOf);
                    Log.wtf("GoogleApiClientConnecting", sb.toString(), new Exception());
                    zae(connectionResult2);
                    return;
                }
                this.zage = true;
                this.zagf = zacx.getAccountAccessor();
                this.zagg = zacx.getSaveDefaultAccount();
                this.zagh = zacx.isFromCrossClientAuth();
                zaap();
            } else if (zad(connectionResult)) {
                zaar();
                zaap();
            } else {
                zae(connectionResult);
            }
        }
    }

    /* access modifiers changed from: private */
    public final void zaap() {
        if (this.zafy == 0) {
            if (!this.zagd || this.zage) {
                ArrayList arrayList = new ArrayList();
                this.zafx = 1;
                this.zafy = this.zaft.zagz.size();
                for (AnyClientKey anyClientKey : this.zaft.zagz.keySet()) {
                    if (!this.zaft.zahp.containsKey(anyClientKey)) {
                        arrayList.add((Client) this.zaft.zagz.get(anyClientKey));
                    } else if (zaao()) {
                        zaaq();
                    }
                }
                if (!arrayList.isEmpty()) {
                    this.zagi.add(zabh.zabb().submit(new zaaq(this, arrayList)));
                }
            }
        }
    }

    public final void onConnected(Bundle bundle) {
        if (zac(1)) {
            if (bundle != null) {
                this.zafz.putAll(bundle);
            }
            if (zaao()) {
                zaaq();
            }
        }
    }

    public final void zaa(ConnectionResult connectionResult, Api<?> api, boolean z) {
        if (zac(1)) {
            zab(connectionResult, api, z);
            if (zaao()) {
                zaaq();
            }
        }
    }

    private final void zaaq() {
        this.zaft.zaba();
        zabh.zabb().execute(new zaal(this));
        zad zad = this.zagb;
        if (zad != null) {
            if (this.zagg) {
                zad.zaa(this.zagf, this.zagh);
            }
            zab(false);
        }
        for (AnyClientKey anyClientKey : this.zaft.zahp.keySet()) {
            ((Client) this.zaft.zagz.get(anyClientKey)).disconnect();
        }
        this.zaft.zaht.zab(this.zafz.isEmpty() ? null : this.zafz);
    }

    public final <A extends AnyClient, R extends Result, T extends ApiMethodImpl<R, A>> T enqueue(T t) {
        this.zaft.zaee.zafc.add(t);
        return t;
    }

    public final <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T execute(T t) {
        throw new IllegalStateException("GoogleApiClient is not connected yet.");
    }

    public final boolean disconnect() {
        zaas();
        zab(true);
        this.zaft.zaf(null);
        return true;
    }

    public final void onConnectionSuspended(int i) {
        zae(new ConnectionResult(8, null));
    }

    /* access modifiers changed from: private */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0022, code lost:
        if (r7 != false) goto L_0x0024;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void zab(com.google.android.gms.common.ConnectionResult r5, com.google.android.gms.common.api.Api<?> r6, boolean r7) {
        /*
            r4 = this;
            com.google.android.gms.common.api.Api$BaseClientBuilder r0 = r6.zah()
            int r0 = r0.getPriority()
            r1 = 0
            r2 = 1
            if (r7 == 0) goto L_0x0024
            boolean r7 = r5.hasResolution()
            if (r7 == 0) goto L_0x0014
        L_0x0012:
            r7 = r2
            goto L_0x0022
        L_0x0014:
            com.google.android.gms.common.GoogleApiAvailabilityLight r7 = r4.zaey
            int r3 = r5.getErrorCode()
            android.content.Intent r7 = r7.getErrorResolutionIntent(r3)
            if (r7 == 0) goto L_0x0021
            goto L_0x0012
        L_0x0021:
            r7 = r1
        L_0x0022:
            if (r7 == 0) goto L_0x002d
        L_0x0024:
            com.google.android.gms.common.ConnectionResult r7 = r4.zafh
            if (r7 == 0) goto L_0x002c
            int r7 = r4.zafw
            if (r0 >= r7) goto L_0x002d
        L_0x002c:
            r1 = r2
        L_0x002d:
            if (r1 == 0) goto L_0x0033
            r4.zafh = r5
            r4.zafw = r0
        L_0x0033:
            com.google.android.gms.common.api.internal.zabe r7 = r4.zaft
            java.util.Map<com.google.android.gms.common.api.Api$AnyClientKey<?>, com.google.android.gms.common.ConnectionResult> r7 = r7.zahp
            com.google.android.gms.common.api.Api$AnyClientKey r6 = r6.getClientKey()
            r7.put(r6, r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.internal.zaak.zab(com.google.android.gms.common.ConnectionResult, com.google.android.gms.common.api.Api, boolean):void");
    }

    /* access modifiers changed from: private */
    public final void zaar() {
        this.zagd = false;
        this.zaft.zaee.zaha = Collections.emptySet();
        for (AnyClientKey anyClientKey : this.zaga) {
            if (!this.zaft.zahp.containsKey(anyClientKey)) {
                this.zaft.zahp.put(anyClientKey, new ConnectionResult(17, null));
            }
        }
    }

    /* access modifiers changed from: private */
    public final boolean zad(ConnectionResult connectionResult) {
        return this.zagc && !connectionResult.hasResolution();
    }

    /* access modifiers changed from: private */
    public final void zae(ConnectionResult connectionResult) {
        zaas();
        zab(!connectionResult.hasResolution());
        this.zaft.zaf(connectionResult);
        this.zaft.zaht.zac(connectionResult);
    }

    private final void zab(boolean z) {
        zad zad = this.zagb;
        if (zad != null) {
            if (zad.isConnected() && z) {
                this.zagb.zacw();
            }
            this.zagb.disconnect();
            if (this.zaet.isSignInClientDisconnectFixEnabled()) {
                this.zagb = null;
            }
            this.zagf = null;
        }
    }

    private final void zaas() {
        ArrayList arrayList = this.zagi;
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            Object obj = arrayList.get(i);
            i++;
            ((Future) obj).cancel(true);
        }
        this.zagi.clear();
    }

    /* access modifiers changed from: private */
    public final Set<Scope> zaat() {
        if (this.zaet == null) {
            return Collections.emptySet();
        }
        HashSet hashSet = new HashSet(this.zaet.getRequiredScopes());
        Map optionalApiSettings = this.zaet.getOptionalApiSettings();
        for (Api api : optionalApiSettings.keySet()) {
            if (!this.zaft.zahp.containsKey(api.getClientKey())) {
                hashSet.addAll(((OptionalApiSettings) optionalApiSettings.get(api)).mScopes);
            }
        }
        return hashSet;
    }

    /* access modifiers changed from: private */
    public final boolean zac(int i) {
        if (this.zafx == i) {
            return true;
        }
        String str = "GoogleApiClientConnecting";
        Log.w(str, this.zaft.zaee.zaay());
        String valueOf = String.valueOf(this);
        StringBuilder sb = new StringBuilder(String.valueOf(valueOf).length() + 23);
        sb.append("Unexpected callback in ");
        sb.append(valueOf);
        Log.w(str, sb.toString());
        int i2 = this.zafy;
        StringBuilder sb2 = new StringBuilder(33);
        sb2.append("mRemainingConnections=");
        sb2.append(i2);
        Log.w(str, sb2.toString());
        String zad = zad(this.zafx);
        String zad2 = zad(i);
        StringBuilder sb3 = new StringBuilder(String.valueOf(zad).length() + 70 + String.valueOf(zad2).length());
        sb3.append("GoogleApiClient connecting is in step ");
        sb3.append(zad);
        sb3.append(" but received callback for step ");
        sb3.append(zad2);
        Log.wtf(str, sb3.toString(), new Exception());
        zae(new ConnectionResult(8, null));
        return false;
    }
}
