package com.google.android.gms.common.api.internal;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import androidx.fragment.app.FragmentActivity;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AbstractClientBuilder;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.AnyClientKey;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.GoogleApiClient.Builder;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;
import com.google.android.gms.common.internal.ClientSettings;
import com.google.android.gms.common.internal.GmsClientEventManager;
import com.google.android.gms.common.internal.GmsClientEventManager.GmsClientEventState;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.service.Common;
import com.google.android.gms.common.util.ClientLibraryUtils;
import com.google.android.gms.signin.SignInOptions;
import com.google.android.gms.signin.zad;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;

public final class zaaw extends GoogleApiClient implements zabt {
    /* access modifiers changed from: private */
    public final Context mContext;
    private final Looper zabj;
    private final int zacb;
    private final GoogleApiAvailability zacd;
    private final AbstractClientBuilder<? extends zad, SignInOptions> zace;
    private boolean zach;
    private final Lock zaeo;
    private final ClientSettings zaet;
    private final Map<Api<?>, Boolean> zaew;
    final Queue<ApiMethodImpl<?, ?>> zafc = new LinkedList();
    private final GmsClientEventManager zags;
    private zabs zagt = null;
    private volatile boolean zagu;
    private long zagv;
    private long zagw;
    private final zabb zagx;
    private zabq zagy;
    final Map<AnyClientKey<?>, Client> zagz;
    Set<Scope> zaha;
    private final ListenerHolders zahb;
    private final ArrayList<zaq> zahc;
    private Integer zahd;
    Set<zacm> zahe;
    final zacp zahf;
    private final GmsClientEventState zahg;

    public zaaw(Context context, Lock lock, Looper looper, ClientSettings clientSettings, GoogleApiAvailability googleApiAvailability, AbstractClientBuilder<? extends zad, SignInOptions> abstractClientBuilder, Map<Api<?>, Boolean> map, List<ConnectionCallbacks> list, List<OnConnectionFailedListener> list2, Map<AnyClientKey<?>, Client> map2, int i, int i2, ArrayList<zaq> arrayList, boolean z) {
        Looper looper2 = looper;
        int i3 = i;
        this.zagv = ClientLibraryUtils.isPackageSide() ? 10000 : 120000;
        this.zagw = 5000;
        this.zaha = new HashSet();
        this.zahb = new ListenerHolders();
        this.zahd = null;
        this.zahe = null;
        this.zahg = new zaax(this);
        this.mContext = context;
        this.zaeo = lock;
        this.zach = false;
        this.zags = new GmsClientEventManager(looper, this.zahg);
        this.zabj = looper2;
        this.zagx = new zabb(this, looper);
        this.zacd = googleApiAvailability;
        this.zacb = i3;
        if (i3 >= 0) {
            this.zahd = Integer.valueOf(i2);
        }
        this.zaew = map;
        this.zagz = map2;
        this.zahc = arrayList;
        this.zahf = new zacp(this.zagz);
        for (ConnectionCallbacks registerConnectionCallbacks : list) {
            this.zags.registerConnectionCallbacks(registerConnectionCallbacks);
        }
        for (OnConnectionFailedListener registerConnectionFailedListener : list2) {
            this.zags.registerConnectionFailedListener(registerConnectionFailedListener);
        }
        this.zaet = clientSettings;
        this.zace = abstractClientBuilder;
    }

    private static String zaf(int i) {
        return i != 1 ? i != 2 ? i != 3 ? "UNKNOWN" : "SIGN_IN_MODE_NONE" : "SIGN_IN_MODE_OPTIONAL" : "SIGN_IN_MODE_REQUIRED";
    }

    public final <A extends AnyClient, R extends Result, T extends ApiMethodImpl<R, A>> T enqueue(T t) {
        Preconditions.checkArgument(t.getClientKey() != null, "This task can not be enqueued (it's probably a Batch or malformed)");
        boolean containsKey = this.zagz.containsKey(t.getClientKey());
        String name = t.getApi() != null ? t.getApi().getName() : "the API";
        StringBuilder sb = new StringBuilder(String.valueOf(name).length() + 65);
        sb.append("GoogleApiClient is not configured to use ");
        sb.append(name);
        sb.append(" required for this call.");
        Preconditions.checkArgument(containsKey, sb.toString());
        this.zaeo.lock();
        try {
            if (this.zagt == null) {
                this.zafc.add(t);
                return t;
            }
            T enqueue = this.zagt.enqueue(t);
            this.zaeo.unlock();
            return enqueue;
        } finally {
            this.zaeo.unlock();
        }
    }

    public final <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T execute(T t) {
        Preconditions.checkArgument(t.getClientKey() != null, "This task can not be executed (it's probably a Batch or malformed)");
        boolean containsKey = this.zagz.containsKey(t.getClientKey());
        String name = t.getApi() != null ? t.getApi().getName() : "the API";
        StringBuilder sb = new StringBuilder(String.valueOf(name).length() + 65);
        sb.append("GoogleApiClient is not configured to use ");
        sb.append(name);
        sb.append(" required for this call.");
        Preconditions.checkArgument(containsKey, sb.toString());
        this.zaeo.lock();
        try {
            if (this.zagt == null) {
                throw new IllegalStateException("GoogleApiClient is not connected yet.");
            } else if (this.zagu) {
                this.zafc.add(t);
                while (!this.zafc.isEmpty()) {
                    ApiMethodImpl apiMethodImpl = (ApiMethodImpl) this.zafc.remove();
                    this.zahf.zab(apiMethodImpl);
                    apiMethodImpl.setFailedResult(Status.RESULT_INTERNAL_ERROR);
                }
                return t;
            } else {
                T execute = this.zagt.execute(t);
                this.zaeo.unlock();
                return execute;
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    public final <L> ListenerHolder<L> registerListener(L l) {
        this.zaeo.lock();
        try {
            return this.zahb.zaa(l, this.zabj, "NO_TYPE");
        } finally {
            this.zaeo.unlock();
        }
    }

    public final <C extends Client> C getClient(AnyClientKey<C> anyClientKey) {
        C c = (Client) this.zagz.get(anyClientKey);
        Preconditions.checkNotNull(c, "Appropriate Api was not requested.");
        return c;
    }

    public final boolean hasApi(Api<?> api) {
        return this.zagz.containsKey(api.getClientKey());
    }

    public final boolean hasConnectedApi(Api<?> api) {
        if (!isConnected()) {
            return false;
        }
        Client client = (Client) this.zagz.get(api.getClientKey());
        if (client == null || !client.isConnected()) {
            return false;
        }
        return true;
    }

    public final ConnectionResult getConnectionResult(Api<?> api) {
        String str = "GoogleApiClientImpl";
        this.zaeo.lock();
        try {
            if (!isConnected()) {
                if (!this.zagu) {
                    throw new IllegalStateException("Cannot invoke getConnectionResult unless GoogleApiClient is connected");
                }
            }
            if (this.zagz.containsKey(api.getClientKey())) {
                ConnectionResult connectionResult = this.zagt.getConnectionResult(api);
                if (connectionResult != null) {
                    this.zaeo.unlock();
                    return connectionResult;
                } else if (this.zagu) {
                    return ConnectionResult.RESULT_SUCCESS;
                } else {
                    Log.w(str, zaay());
                    Log.wtf(str, String.valueOf(api.getName()).concat(" requested in getConnectionResult is not connected but is not present in the failed  connections map"), new Exception());
                    ConnectionResult connectionResult2 = new ConnectionResult(8, null);
                    this.zaeo.unlock();
                    return connectionResult2;
                }
            } else {
                throw new IllegalArgumentException(String.valueOf(api.getName()).concat(" was never registered with GoogleApiClient"));
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void connect() {
        this.zaeo.lock();
        try {
            boolean z = false;
            if (this.zacb >= 0) {
                if (this.zahd != null) {
                    z = true;
                }
                Preconditions.checkState(z, "Sign-in mode should have been set explicitly by auto-manage.");
            } else if (this.zahd == null) {
                this.zahd = Integer.valueOf(zaa(this.zagz.values(), false));
            } else if (this.zahd.intValue() == 2) {
                throw new IllegalStateException("Cannot call connect() when SignInMode is set to SIGN_IN_MODE_OPTIONAL. Call connect(SIGN_IN_MODE_OPTIONAL) instead.");
            }
            connect(this.zahd.intValue());
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void connect(int i) {
        this.zaeo.lock();
        boolean z = true;
        if (!(i == 3 || i == 1 || i == 2)) {
            z = false;
        }
        try {
            StringBuilder sb = new StringBuilder(33);
            sb.append("Illegal sign-in mode: ");
            sb.append(i);
            Preconditions.checkArgument(z, sb.toString());
            zae(i);
            zaau();
        } finally {
            this.zaeo.unlock();
        }
    }

    public final ConnectionResult blockingConnect() {
        boolean z = true;
        Preconditions.checkState(Looper.myLooper() != Looper.getMainLooper(), "blockingConnect must not be called on the UI thread");
        this.zaeo.lock();
        try {
            if (this.zacb >= 0) {
                if (this.zahd == null) {
                    z = false;
                }
                Preconditions.checkState(z, "Sign-in mode should have been set explicitly by auto-manage.");
            } else if (this.zahd == null) {
                this.zahd = Integer.valueOf(zaa(this.zagz.values(), false));
            } else if (this.zahd.intValue() == 2) {
                throw new IllegalStateException("Cannot call blockingConnect() when sign-in mode is set to SIGN_IN_MODE_OPTIONAL. Call connect(SIGN_IN_MODE_OPTIONAL) instead.");
            }
            zae(this.zahd.intValue());
            this.zags.enableCallbacks();
            return this.zagt.blockingConnect();
        } finally {
            this.zaeo.unlock();
        }
    }

    public final ConnectionResult blockingConnect(long j, TimeUnit timeUnit) {
        Preconditions.checkState(Looper.myLooper() != Looper.getMainLooper(), "blockingConnect must not be called on the UI thread");
        Preconditions.checkNotNull(timeUnit, "TimeUnit must not be null");
        this.zaeo.lock();
        try {
            if (this.zahd == null) {
                this.zahd = Integer.valueOf(zaa(this.zagz.values(), false));
            } else if (this.zahd.intValue() == 2) {
                throw new IllegalStateException("Cannot call blockingConnect() when sign-in mode is set to SIGN_IN_MODE_OPTIONAL. Call connect(SIGN_IN_MODE_OPTIONAL) instead.");
            }
            zae(this.zahd.intValue());
            this.zags.enableCallbacks();
            return this.zagt.blockingConnect(j, timeUnit);
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void disconnect() {
        this.zaeo.lock();
        try {
            this.zahf.release();
            if (this.zagt != null) {
                this.zagt.disconnect();
            }
            this.zahb.release();
            for (ApiMethodImpl apiMethodImpl : this.zafc) {
                apiMethodImpl.zaa((zacs) null);
                apiMethodImpl.cancel();
            }
            this.zafc.clear();
            if (this.zagt != null) {
                zaaw();
                this.zags.disableCallbacks();
                this.zaeo.unlock();
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void reconnect() {
        disconnect();
        connect();
    }

    public final PendingResult<Status> clearDefaultAccountAndReconnect() {
        Preconditions.checkState(isConnected(), "GoogleApiClient is not connected yet.");
        Preconditions.checkState(this.zahd.intValue() != 2, "Cannot use clearDefaultAccountAndReconnect with GOOGLE_SIGN_IN_API");
        StatusPendingResult statusPendingResult = new StatusPendingResult((GoogleApiClient) this);
        if (this.zagz.containsKey(Common.CLIENT_KEY)) {
            zaa(this, statusPendingResult, false);
        } else {
            AtomicReference atomicReference = new AtomicReference();
            GoogleApiClient build = new Builder(this.mContext).addApi(Common.API).addConnectionCallbacks(new zaay(this, atomicReference, statusPendingResult)).addOnConnectionFailedListener(new zaaz(this, statusPendingResult)).setHandler(this.zagx).build();
            atomicReference.set(build);
            build.connect();
        }
        return statusPendingResult;
    }

    /* access modifiers changed from: private */
    public final void zaa(GoogleApiClient googleApiClient, StatusPendingResult statusPendingResult, boolean z) {
        Common.zapi.zaa(googleApiClient).setResultCallback(new zaba(this, statusPendingResult, z, googleApiClient));
    }

    public final void stopAutoManage(FragmentActivity fragmentActivity) {
        LifecycleActivity lifecycleActivity = new LifecycleActivity((Activity) fragmentActivity);
        if (this.zacb >= 0) {
            zaj.zaa(lifecycleActivity).zaa(this.zacb);
            return;
        }
        throw new IllegalStateException("Called stopAutoManage but automatic lifecycle management is not enabled.");
    }

    public final boolean isConnected() {
        zabs zabs = this.zagt;
        return zabs != null && zabs.isConnected();
    }

    public final boolean isConnecting() {
        zabs zabs = this.zagt;
        return zabs != null && zabs.isConnecting();
    }

    private final void zae(int i) {
        Integer num = this.zahd;
        if (num == null) {
            this.zahd = Integer.valueOf(i);
        } else if (num.intValue() != i) {
            String zaf = zaf(i);
            String zaf2 = zaf(this.zahd.intValue());
            StringBuilder sb = new StringBuilder(String.valueOf(zaf).length() + 51 + String.valueOf(zaf2).length());
            sb.append("Cannot use sign-in mode: ");
            sb.append(zaf);
            sb.append(". Mode was already set to ");
            sb.append(zaf2);
            throw new IllegalStateException(sb.toString());
        }
        if (this.zagt == null) {
            boolean z = false;
            boolean z2 = false;
            for (Client client : this.zagz.values()) {
                if (client.requiresSignIn()) {
                    z = true;
                }
                if (client.providesSignIn()) {
                    z2 = true;
                }
            }
            int intValue = this.zahd.intValue();
            if (intValue != 1) {
                if (intValue == 2 && z) {
                    if (this.zach) {
                        zax zax = new zax(this.mContext, this.zaeo, this.zabj, this.zacd, this.zagz, this.zaet, this.zaew, this.zace, this.zahc, this, true);
                        this.zagt = zax;
                        return;
                    }
                    this.zagt = zas.zaa(this.mContext, this, this.zaeo, this.zabj, this.zacd, this.zagz, this.zaet, this.zaew, this.zace, this.zahc);
                    return;
                }
            } else if (!z) {
                throw new IllegalStateException("SIGN_IN_MODE_REQUIRED cannot be used on a GoogleApiClient that does not contain any authenticated APIs. Use connect() instead.");
            } else if (z2) {
                throw new IllegalStateException("Cannot use SIGN_IN_MODE_REQUIRED with GOOGLE_SIGN_IN_API. Use connect(SIGN_IN_MODE_OPTIONAL) instead.");
            }
            if (!this.zach || z2) {
                zabe zabe = new zabe(this.mContext, this, this.zaeo, this.zabj, this.zacd, this.zagz, this.zaet, this.zaew, this.zace, this.zahc, this);
                this.zagt = zabe;
                return;
            }
            zax zax2 = new zax(this.mContext, this.zaeo, this.zabj, this.zacd, this.zagz, this.zaet, this.zaew, this.zace, this.zahc, this, false);
            this.zagt = zax2;
        }
    }

    private final void zaau() {
        this.zags.enableCallbacks();
        this.zagt.connect();
    }

    /* access modifiers changed from: private */
    public final void resume() {
        this.zaeo.lock();
        try {
            if (this.zagu) {
                zaau();
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    /* access modifiers changed from: private */
    public final void zaav() {
        this.zaeo.lock();
        try {
            if (zaaw()) {
                zaau();
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    /* access modifiers changed from: 0000 */
    public final boolean zaaw() {
        if (!this.zagu) {
            return false;
        }
        this.zagu = false;
        this.zagx.removeMessages(2);
        this.zagx.removeMessages(1);
        zabq zabq = this.zagy;
        if (zabq != null) {
            zabq.unregister();
            this.zagy = null;
        }
        return true;
    }

    public final void registerConnectionCallbacks(ConnectionCallbacks connectionCallbacks) {
        this.zags.registerConnectionCallbacks(connectionCallbacks);
    }

    public final boolean isConnectionCallbacksRegistered(ConnectionCallbacks connectionCallbacks) {
        return this.zags.isConnectionCallbacksRegistered(connectionCallbacks);
    }

    public final void unregisterConnectionCallbacks(ConnectionCallbacks connectionCallbacks) {
        this.zags.unregisterConnectionCallbacks(connectionCallbacks);
    }

    public final void registerConnectionFailedListener(OnConnectionFailedListener onConnectionFailedListener) {
        this.zags.registerConnectionFailedListener(onConnectionFailedListener);
    }

    public final boolean isConnectionFailedListenerRegistered(OnConnectionFailedListener onConnectionFailedListener) {
        return this.zags.isConnectionFailedListenerRegistered(onConnectionFailedListener);
    }

    public final void unregisterConnectionFailedListener(OnConnectionFailedListener onConnectionFailedListener) {
        this.zags.unregisterConnectionFailedListener(onConnectionFailedListener);
    }

    public final void zab(Bundle bundle) {
        while (!this.zafc.isEmpty()) {
            execute((ApiMethodImpl) this.zafc.remove());
        }
        this.zags.onConnectionSuccess(bundle);
    }

    public final void zac(ConnectionResult connectionResult) {
        if (!this.zacd.isPlayServicesPossiblyUpdating(this.mContext, connectionResult.getErrorCode())) {
            zaaw();
        }
        if (!this.zagu) {
            this.zags.onConnectionFailure(connectionResult);
            this.zags.disableCallbacks();
        }
    }

    public final void zab(int i, boolean z) {
        if (i == 1 && !z && !this.zagu) {
            this.zagu = true;
            if (this.zagy == null && !ClientLibraryUtils.isPackageSide()) {
                this.zagy = this.zacd.zaa(this.mContext.getApplicationContext(), (zabr) new zabc(this));
            }
            zabb zabb = this.zagx;
            zabb.sendMessageDelayed(zabb.obtainMessage(1), this.zagv);
            zabb zabb2 = this.zagx;
            zabb2.sendMessageDelayed(zabb2.obtainMessage(2), this.zagw);
        }
        this.zahf.zabx();
        this.zags.onUnintentionalDisconnection(i);
        this.zags.disableCallbacks();
        if (i == 2) {
            zaau();
        }
    }

    public final Context getContext() {
        return this.mContext;
    }

    public final Looper getLooper() {
        return this.zabj;
    }

    public final boolean maybeSignIn(SignInConnectionListener signInConnectionListener) {
        zabs zabs = this.zagt;
        return zabs != null && zabs.maybeSignIn(signInConnectionListener);
    }

    public final void maybeSignOut() {
        zabs zabs = this.zagt;
        if (zabs != null) {
            zabs.maybeSignOut();
        }
    }

    public final void zaa(zacm zacm) {
        this.zaeo.lock();
        try {
            if (this.zahe == null) {
                this.zahe = new HashSet();
            }
            this.zahe.add(zacm);
        } finally {
            this.zaeo.unlock();
        }
    }

    public final void zab(zacm zacm) {
        this.zaeo.lock();
        try {
            String str = "GoogleApiClientImpl";
            if (this.zahe == null) {
                Log.wtf(str, "Attempted to remove pending transform when no transforms are registered.", new Exception());
            } else if (!this.zahe.remove(zacm)) {
                Log.wtf(str, "Failed to remove pending transform - this may lead to memory leaks!", new Exception());
            } else if (!zaax()) {
                this.zagt.zaw();
            }
        } finally {
            this.zaeo.unlock();
        }
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: 0000 */
    public final boolean zaax() {
        this.zaeo.lock();
        try {
            if (this.zahe == null) {
                this.zaeo.unlock();
                return false;
            }
            boolean z = !this.zahe.isEmpty();
            this.zaeo.unlock();
            return z;
        } catch (Throwable th) {
            this.zaeo.unlock();
            throw th;
        }
    }

    /* access modifiers changed from: 0000 */
    public final String zaay() {
        StringWriter stringWriter = new StringWriter();
        dump("", null, new PrintWriter(stringWriter), null);
        return stringWriter.toString();
    }

    public final void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.append(str).append("mContext=").println(this.mContext);
        printWriter.append(str).append("mResuming=").print(this.zagu);
        printWriter.append(" mWorkQueue.size()=").print(this.zafc.size());
        printWriter.append(" mUnconsumedApiCalls.size()=").println(this.zahf.zakz.size());
        zabs zabs = this.zagt;
        if (zabs != null) {
            zabs.dump(str, fileDescriptor, printWriter, strArr);
        }
    }

    public static int zaa(Iterable<Client> iterable, boolean z) {
        boolean z2 = false;
        boolean z3 = false;
        for (Client client : iterable) {
            if (client.requiresSignIn()) {
                z2 = true;
            }
            if (client.providesSignIn()) {
                z3 = true;
            }
        }
        if (!z2) {
            return 3;
        }
        if (!z3 || !z) {
            return 1;
        }
        return 2;
    }
}
