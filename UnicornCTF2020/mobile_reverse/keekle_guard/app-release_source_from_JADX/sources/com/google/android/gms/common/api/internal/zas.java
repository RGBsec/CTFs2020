package com.google.android.gms.common.api.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import androidx.collection.ArrayMap;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.AnyClientKey;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;
import com.google.android.gms.common.internal.ClientSettings;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.internal.base.zap;
import com.google.android.gms.signin.SignInOptions;
import com.google.android.gms.signin.zad;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

final class zas implements zabs {
    private final Context mContext;
    private final Looper zabj;
    private final zaaw zaee;
    /* access modifiers changed from: private */
    public final zabe zaef;
    /* access modifiers changed from: private */
    public final zabe zaeg;
    private final Map<AnyClientKey<?>, zabe> zaeh;
    private final Set<SignInConnectionListener> zaei = Collections.newSetFromMap(new WeakHashMap());
    private final Client zaej;
    private Bundle zaek;
    /* access modifiers changed from: private */
    public ConnectionResult zael = null;
    /* access modifiers changed from: private */
    public ConnectionResult zaem = null;
    /* access modifiers changed from: private */
    public boolean zaen = false;
    /* access modifiers changed from: private */
    public final Lock zaeo;
    private int zaep = 0;

    public static zas zaa(Context context, zaaw zaaw, Lock lock, Looper looper, GoogleApiAvailabilityLight googleApiAvailabilityLight, Map<AnyClientKey<?>, Client> map, ClientSettings clientSettings, Map<Api<?>, Boolean> map2, AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder, ArrayList<zaq> arrayList) {
        Map<Api<?>, Boolean> map3 = map2;
        ArrayMap arrayMap = new ArrayMap();
        ArrayMap arrayMap2 = new ArrayMap();
        Client client = null;
        for (Entry entry : map.entrySet()) {
            Client client2 = (Client) entry.getValue();
            if (client2.providesSignIn()) {
                client = client2;
            }
            if (client2.requiresSignIn()) {
                arrayMap.put((AnyClientKey) entry.getKey(), client2);
            } else {
                arrayMap2.put((AnyClientKey) entry.getKey(), client2);
            }
        }
        Preconditions.checkState(!arrayMap.isEmpty(), "CompositeGoogleApiClient should not be used without any APIs that require sign-in.");
        ArrayMap arrayMap3 = new ArrayMap();
        ArrayMap arrayMap4 = new ArrayMap();
        for (Api api : map2.keySet()) {
            AnyClientKey clientKey = api.getClientKey();
            if (arrayMap.containsKey(clientKey)) {
                arrayMap3.put(api, (Boolean) map3.get(api));
            } else if (arrayMap2.containsKey(clientKey)) {
                arrayMap4.put(api, (Boolean) map3.get(api));
            } else {
                throw new IllegalStateException("Each API in the isOptionalMap must have a corresponding client in the clients map.");
            }
        }
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList();
        ArrayList arrayList4 = arrayList;
        int size = arrayList4.size();
        int i = 0;
        while (i < size) {
            Object obj = arrayList4.get(i);
            i++;
            zaq zaq = (zaq) obj;
            if (arrayMap3.containsKey(zaq.mApi)) {
                arrayList2.add(zaq);
            } else if (arrayMap4.containsKey(zaq.mApi)) {
                arrayList3.add(zaq);
            } else {
                throw new IllegalStateException("Each ClientCallbacks must have a corresponding API in the isOptionalMap");
            }
        }
        zas zas = new zas(context, zaaw, lock, looper, googleApiAvailabilityLight, arrayMap, arrayMap2, clientSettings, abstractClientBuilder, client, arrayList2, arrayList3, arrayMap3, arrayMap4);
        return zas;
    }

    private zas(Context context, zaaw zaaw, Lock lock, Looper looper, GoogleApiAvailabilityLight googleApiAvailabilityLight, Map<AnyClientKey<?>, Client> map, Map<AnyClientKey<?>, Client> map2, ClientSettings clientSettings, AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder, Client client, ArrayList<zaq> arrayList, ArrayList<zaq> arrayList2, Map<Api<?>, Boolean> map3, Map<Api<?>, Boolean> map4) {
        this.mContext = context;
        this.zaee = zaaw;
        this.zaeo = lock;
        this.zabj = looper;
        this.zaej = client;
        Context context2 = context;
        Lock lock2 = lock;
        Looper looper2 = looper;
        GoogleApiAvailabilityLight googleApiAvailabilityLight2 = googleApiAvailabilityLight;
        zabe zabe = r3;
        zabe zabe2 = new zabe(context2, this.zaee, lock2, looper2, googleApiAvailabilityLight2, map2, null, map4, null, arrayList2, new zau(this, null));
        this.zaef = zabe;
        zabe zabe3 = new zabe(context2, this.zaee, lock2, looper2, googleApiAvailabilityLight2, map, clientSettings, map3, abstractClientBuilder, arrayList, new zav(this, null));
        this.zaeg = zabe3;
        ArrayMap arrayMap = new ArrayMap();
        for (AnyClientKey put : map2.keySet()) {
            arrayMap.put(put, this.zaef);
        }
        for (AnyClientKey put2 : map.keySet()) {
            arrayMap.put(put2, this.zaeg);
        }
        this.zaeh = Collections.unmodifiableMap(arrayMap);
    }

    public final <A extends AnyClient, R extends Result, T extends ApiMethodImpl<R, A>> T enqueue(T t) {
        if (!zaa((ApiMethodImpl<? extends Result, ? extends AnyClient>) t)) {
            return this.zaef.enqueue(t);
        }
        if (!zaz()) {
            return this.zaeg.enqueue(t);
        }
        t.setFailedResult(new Status(4, null, zaaa()));
        return t;
    }

    public final <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T execute(T t) {
        if (!zaa((ApiMethodImpl<? extends Result, ? extends AnyClient>) t)) {
            return this.zaef.execute(t);
        }
        if (!zaz()) {
            return this.zaeg.execute(t);
        }
        t.setFailedResult(new Status(4, null, zaaa()));
        return t;
    }

    public final ConnectionResult getConnectionResult(Api<?> api) {
        if (!((zabe) this.zaeh.get(api.getClientKey())).equals(this.zaeg)) {
            return this.zaef.getConnectionResult(api);
        }
        if (zaz()) {
            return new ConnectionResult(4, zaaa());
        }
        return this.zaeg.getConnectionResult(api);
    }

    public final void connect() {
        this.zaep = 2;
        this.zaen = false;
        this.zaem = null;
        this.zael = null;
        this.zaef.connect();
        this.zaeg.connect();
    }

    public final ConnectionResult blockingConnect() {
        throw new UnsupportedOperationException();
    }

    public final ConnectionResult blockingConnect(long j, TimeUnit timeUnit) {
        throw new UnsupportedOperationException();
    }

    public final void disconnect() {
        this.zaem = null;
        this.zael = null;
        this.zaep = 0;
        this.zaef.disconnect();
        this.zaeg.disconnect();
        zay();
    }

    public final boolean isConnected() {
        this.zaeo.lock();
        try {
            boolean z = true;
            if (!this.zaef.isConnected() || (!this.zaeg.isConnected() && !zaz() && this.zaep != 1)) {
                z = false;
            }
            return z;
        } finally {
            this.zaeo.unlock();
        }
    }

    public final boolean isConnecting() {
        this.zaeo.lock();
        try {
            return this.zaep == 2;
        } finally {
            this.zaeo.unlock();
        }
    }

    public final boolean maybeSignIn(SignInConnectionListener signInConnectionListener) {
        this.zaeo.lock();
        try {
            if ((isConnecting() || isConnected()) && !this.zaeg.isConnected()) {
                this.zaei.add(signInConnectionListener);
                if (this.zaep == 0) {
                    this.zaep = 1;
                }
                this.zaem = null;
                this.zaeg.connect();
                return true;
            }
            this.zaeo.unlock();
            return false;
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void zaw() {
        this.zaef.zaw();
        this.zaeg.zaw();
    }

    public final void maybeSignOut() {
        this.zaeo.lock();
        try {
            boolean isConnecting = isConnecting();
            this.zaeg.disconnect();
            this.zaem = new ConnectionResult(4);
            if (isConnecting) {
                new zap(this.zabj).post(new zat(this));
            } else {
                zay();
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    /* access modifiers changed from: private */
    public final void zax() {
        if (zab(this.zael)) {
            if (zab(this.zaem) || zaz()) {
                int i = this.zaep;
                if (i != 1) {
                    if (i != 2) {
                        Log.wtf("CompositeGAC", "Attempted to call success callbacks in CONNECTION_MODE_NONE. Callbacks should be disabled via GmsClientSupervisor", new AssertionError());
                        this.zaep = 0;
                        return;
                    }
                    this.zaee.zab(this.zaek);
                }
                zay();
                this.zaep = 0;
                return;
            }
            ConnectionResult connectionResult = this.zaem;
            if (connectionResult != null) {
                if (this.zaep == 1) {
                    zay();
                    return;
                }
                zaa(connectionResult);
                this.zaef.disconnect();
            }
        } else if (this.zael == null || !zab(this.zaem)) {
            ConnectionResult connectionResult2 = this.zael;
            if (!(connectionResult2 == null || this.zaem == null)) {
                if (this.zaeg.zahs < this.zaef.zahs) {
                    connectionResult2 = this.zaem;
                }
                zaa(connectionResult2);
            }
        } else {
            this.zaeg.disconnect();
            zaa(this.zael);
        }
    }

    private final void zaa(ConnectionResult connectionResult) {
        int i = this.zaep;
        if (i != 1) {
            if (i != 2) {
                Log.wtf("CompositeGAC", "Attempted to call failure callbacks in CONNECTION_MODE_NONE. Callbacks should be disabled via GmsClientSupervisor", new Exception());
                this.zaep = 0;
            }
            this.zaee.zac(connectionResult);
        }
        zay();
        this.zaep = 0;
    }

    private final void zay() {
        for (SignInConnectionListener onComplete : this.zaei) {
            onComplete.onComplete();
        }
        this.zaei.clear();
    }

    /* access modifiers changed from: private */
    public final void zaa(int i, boolean z) {
        this.zaee.zab(i, z);
        this.zaem = null;
        this.zael = null;
    }

    private final boolean zaz() {
        ConnectionResult connectionResult = this.zaem;
        return connectionResult != null && connectionResult.getErrorCode() == 4;
    }

    private final boolean zaa(ApiMethodImpl<? extends Result, ? extends AnyClient> apiMethodImpl) {
        AnyClientKey clientKey = apiMethodImpl.getClientKey();
        Preconditions.checkArgument(this.zaeh.containsKey(clientKey), "GoogleApiClient is not configured to use the API required for this call.");
        return ((zabe) this.zaeh.get(clientKey)).equals(this.zaeg);
    }

    private final PendingIntent zaaa() {
        if (this.zaej == null) {
            return null;
        }
        return PendingIntent.getActivity(this.mContext, System.identityHashCode(this.zaee), this.zaej.getSignInIntent(), 134217728);
    }

    /* access modifiers changed from: private */
    public final void zaa(Bundle bundle) {
        Bundle bundle2 = this.zaek;
        if (bundle2 == null) {
            this.zaek = bundle;
            return;
        }
        if (bundle != null) {
            bundle2.putAll(bundle);
        }
    }

    private static boolean zab(ConnectionResult connectionResult) {
        return connectionResult != null && connectionResult.isSuccess();
    }

    public final void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        String str2 = ":";
        printWriter.append(str).append("authClient").println(str2);
        String str3 = "  ";
        this.zaeg.dump(String.valueOf(str).concat(str3), fileDescriptor, printWriter, strArr);
        printWriter.append(str).append("anonClient").println(str2);
        this.zaef.dump(String.valueOf(str).concat(str3), fileDescriptor, printWriter, strArr);
    }
}
