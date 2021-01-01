package com.google.android.gms.common.api;

import android.accounts.Account;
import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.ApiOptions;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.internal.ApiExceptionMapper;
import com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl;
import com.google.android.gms.common.api.internal.GoogleApiManager;
import com.google.android.gms.common.api.internal.GoogleApiManager.zaa;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.common.api.internal.ListenerHolder.ListenerKey;
import com.google.android.gms.common.api.internal.ListenerHolders;
import com.google.android.gms.common.api.internal.RegisterListenerMethod;
import com.google.android.gms.common.api.internal.RegistrationMethods;
import com.google.android.gms.common.api.internal.StatusExceptionMapper;
import com.google.android.gms.common.api.internal.TaskApiCall;
import com.google.android.gms.common.api.internal.UnregisterListenerMethod;
import com.google.android.gms.common.api.internal.zaae;
import com.google.android.gms.common.api.internal.zabp;
import com.google.android.gms.common.api.internal.zace;
import com.google.android.gms.common.api.internal.zai;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.TaskCompletionSource;

public class GoogleApi<O extends ApiOptions> {
    private final Api<O> mApi;
    private final Context mContext;
    private final int mId;
    private final O zabh;
    private final zai<O> zabi;
    private final Looper zabj;
    private final GoogleApiClient zabk;
    private final StatusExceptionMapper zabl;
    protected final GoogleApiManager zabm;

    public static class Settings {
        public static final Settings DEFAULT_SETTINGS = new Builder().build();
        public final StatusExceptionMapper zabn;
        public final Looper zabo;

        public static class Builder {
            private Looper zabj;
            private StatusExceptionMapper zabl;

            public Builder setMapper(StatusExceptionMapper statusExceptionMapper) {
                Preconditions.checkNotNull(statusExceptionMapper, "StatusExceptionMapper must not be null.");
                this.zabl = statusExceptionMapper;
                return this;
            }

            public Builder setLooper(Looper looper) {
                Preconditions.checkNotNull(looper, "Looper must not be null.");
                this.zabj = looper;
                return this;
            }

            public Settings build() {
                if (this.zabl == null) {
                    this.zabl = new ApiExceptionMapper();
                }
                if (this.zabj == null) {
                    this.zabj = Looper.getMainLooper();
                }
                return new Settings(this.zabl, this.zabj);
            }
        }

        private Settings(StatusExceptionMapper statusExceptionMapper, Account account, Looper looper) {
            this.zabn = statusExceptionMapper;
            this.zabo = looper;
        }
    }

    protected GoogleApi(Context context, Api<O> api, Looper looper) {
        Preconditions.checkNotNull(context, "Null context is not permitted.");
        Preconditions.checkNotNull(api, "Api must not be null.");
        Preconditions.checkNotNull(looper, "Looper must not be null.");
        this.mContext = context.getApplicationContext();
        this.mApi = api;
        this.zabh = null;
        this.zabj = looper;
        this.zabi = zai.zaa(api);
        this.zabk = new zabp(this);
        GoogleApiManager zab = GoogleApiManager.zab(this.mContext);
        this.zabm = zab;
        this.mId = zab.zabd();
        this.zabl = new ApiExceptionMapper();
    }

    @Deprecated
    public GoogleApi(Context context, Api<O> api, O o, Looper looper, StatusExceptionMapper statusExceptionMapper) {
        this(context, api, o, new Builder().setLooper(looper).setMapper(statusExceptionMapper).build());
    }

    public GoogleApi(Activity activity, Api<O> api, O o, Settings settings) {
        Preconditions.checkNotNull(activity, "Null activity is not permitted.");
        Preconditions.checkNotNull(api, "Api must not be null.");
        Preconditions.checkNotNull(settings, "Settings must not be null; use Settings.DEFAULT_SETTINGS instead.");
        this.mContext = activity.getApplicationContext();
        this.mApi = api;
        this.zabh = o;
        this.zabj = settings.zabo;
        this.zabi = zai.zaa(this.mApi, this.zabh);
        this.zabk = new zabp(this);
        GoogleApiManager zab = GoogleApiManager.zab(this.mContext);
        this.zabm = zab;
        this.mId = zab.zabd();
        this.zabl = settings.zabn;
        if (!(activity instanceof GoogleApiActivity)) {
            zaae.zaa(activity, this.zabm, this.zabi);
        }
        this.zabm.zaa(this);
    }

    public GoogleApi(Context context, Api<O> api, O o, Settings settings) {
        Preconditions.checkNotNull(context, "Null context is not permitted.");
        Preconditions.checkNotNull(api, "Api must not be null.");
        Preconditions.checkNotNull(settings, "Settings must not be null; use Settings.DEFAULT_SETTINGS instead.");
        this.mContext = context.getApplicationContext();
        this.mApi = api;
        this.zabh = o;
        this.zabj = settings.zabo;
        this.zabi = zai.zaa(this.mApi, this.zabh);
        this.zabk = new zabp(this);
        GoogleApiManager zab = GoogleApiManager.zab(this.mContext);
        this.zabm = zab;
        this.mId = zab.zabd();
        this.zabl = settings.zabn;
        this.zabm.zaa(this);
    }

    @Deprecated
    public GoogleApi(Activity activity, Api<O> api, O o, StatusExceptionMapper statusExceptionMapper) {
        this(activity, api, o, new Builder().setMapper(statusExceptionMapper).setLooper(activity.getMainLooper()).build());
    }

    @Deprecated
    public GoogleApi(Context context, Api<O> api, O o, StatusExceptionMapper statusExceptionMapper) {
        this(context, api, o, new Builder().setMapper(statusExceptionMapper).build());
    }

    private final <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T zaa(int i, T t) {
        t.zau();
        this.zabm.zaa(this, i, (ApiMethodImpl<? extends Result, AnyClient>) t);
        return t;
    }

    private final <TResult, A extends AnyClient> Task<TResult> zaa(int i, TaskApiCall<A, TResult> taskApiCall) {
        TaskCompletionSource taskCompletionSource = new TaskCompletionSource();
        this.zabm.zaa(this, i, taskApiCall, taskCompletionSource, this.zabl);
        return taskCompletionSource.getTask();
    }

    public <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T doRead(T t) {
        return zaa(0, t);
    }

    public <TResult, A extends AnyClient> Task<TResult> doRead(TaskApiCall<A, TResult> taskApiCall) {
        return zaa(0, taskApiCall);
    }

    public <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T doWrite(T t) {
        return zaa(1, t);
    }

    public <TResult, A extends AnyClient> Task<TResult> doWrite(TaskApiCall<A, TResult> taskApiCall) {
        return zaa(1, taskApiCall);
    }

    public <A extends AnyClient, T extends ApiMethodImpl<? extends Result, A>> T doBestEffortWrite(T t) {
        return zaa(2, t);
    }

    public <TResult, A extends AnyClient> Task<TResult> doBestEffortWrite(TaskApiCall<A, TResult> taskApiCall) {
        return zaa(2, taskApiCall);
    }

    @Deprecated
    public <A extends AnyClient, T extends RegisterListenerMethod<A, ?>, U extends UnregisterListenerMethod<A, ?>> Task<Void> doRegisterEventListener(T t, U u) {
        Preconditions.checkNotNull(t);
        Preconditions.checkNotNull(u);
        String str = "Listener has already been released.";
        Preconditions.checkNotNull(t.getListenerKey(), str);
        Preconditions.checkNotNull(u.getListenerKey(), str);
        Preconditions.checkArgument(t.getListenerKey().equals(u.getListenerKey()), "Listener registration and unregistration methods must be constructed with the same ListenerHolder.");
        return this.zabm.zaa(this, (RegisterListenerMethod<AnyClient, ?>) t, (UnregisterListenerMethod<AnyClient, ?>) u);
    }

    public <A extends AnyClient> Task<Void> doRegisterEventListener(RegistrationMethods<A, ?> registrationMethods) {
        Preconditions.checkNotNull(registrationMethods);
        String str = "Listener has already been released.";
        Preconditions.checkNotNull(registrationMethods.zajz.getListenerKey(), str);
        Preconditions.checkNotNull(registrationMethods.zaka.getListenerKey(), str);
        return this.zabm.zaa(this, registrationMethods.zajz, registrationMethods.zaka);
    }

    public Task<Boolean> doUnregisterEventListener(ListenerKey<?> listenerKey) {
        Preconditions.checkNotNull(listenerKey, "Listener key cannot be null.");
        return this.zabm.zaa(this, listenerKey);
    }

    public <L> ListenerHolder<L> registerListener(L l, String str) {
        return ListenerHolders.createListenerHolder(l, this.zabj, str);
    }

    /* access modifiers changed from: protected */
    public Task<Boolean> disconnectService() {
        return this.zabm.zac(this);
    }

    public Client zaa(Looper looper, zaa<O> zaa) {
        return this.mApi.zai().buildClient(this.mContext, looper, createClientSettingsBuilder().build(), this.zabh, zaa, zaa);
    }

    public final Api<O> getApi() {
        return this.mApi;
    }

    public O getApiOptions() {
        return this.zabh;
    }

    public final zai<O> zak() {
        return this.zabi;
    }

    public final int getInstanceId() {
        return this.mId;
    }

    public GoogleApiClient asGoogleApiClient() {
        return this.zabk;
    }

    public Looper getLooper() {
        return this.zabj;
    }

    public Context getApplicationContext() {
        return this.mContext;
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Removed duplicated region for block: B:11:0x0030  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public com.google.android.gms.common.internal.ClientSettings.Builder createClientSettingsBuilder() {
        /*
            r3 = this;
            com.google.android.gms.common.internal.ClientSettings$Builder r0 = new com.google.android.gms.common.internal.ClientSettings$Builder
            r0.<init>()
            O r1 = r3.zabh
            boolean r2 = r1 instanceof com.google.android.gms.common.api.Api.ApiOptions.HasGoogleSignInAccountOptions
            if (r2 == 0) goto L_0x0018
            com.google.android.gms.common.api.Api$ApiOptions$HasGoogleSignInAccountOptions r1 = (com.google.android.gms.common.api.Api.ApiOptions.HasGoogleSignInAccountOptions) r1
            com.google.android.gms.auth.api.signin.GoogleSignInAccount r1 = r1.getGoogleSignInAccount()
            if (r1 == 0) goto L_0x0018
            android.accounts.Account r1 = r1.getAccount()
            goto L_0x0026
        L_0x0018:
            O r1 = r3.zabh
            boolean r2 = r1 instanceof com.google.android.gms.common.api.Api.ApiOptions.HasAccountOptions
            if (r2 == 0) goto L_0x0025
            com.google.android.gms.common.api.Api$ApiOptions$HasAccountOptions r1 = (com.google.android.gms.common.api.Api.ApiOptions.HasAccountOptions) r1
            android.accounts.Account r1 = r1.getAccount()
            goto L_0x0026
        L_0x0025:
            r1 = 0
        L_0x0026:
            com.google.android.gms.common.internal.ClientSettings$Builder r0 = r0.setAccount(r1)
            O r1 = r3.zabh
            boolean r2 = r1 instanceof com.google.android.gms.common.api.Api.ApiOptions.HasGoogleSignInAccountOptions
            if (r2 == 0) goto L_0x003d
            com.google.android.gms.common.api.Api$ApiOptions$HasGoogleSignInAccountOptions r1 = (com.google.android.gms.common.api.Api.ApiOptions.HasGoogleSignInAccountOptions) r1
            com.google.android.gms.auth.api.signin.GoogleSignInAccount r1 = r1.getGoogleSignInAccount()
            if (r1 == 0) goto L_0x003d
            java.util.Set r1 = r1.getRequestedScopes()
            goto L_0x0041
        L_0x003d:
            java.util.Set r1 = java.util.Collections.emptySet()
        L_0x0041:
            com.google.android.gms.common.internal.ClientSettings$Builder r0 = r0.addAllRequiredScopes(r1)
            android.content.Context r1 = r3.mContext
            java.lang.Class r1 = r1.getClass()
            java.lang.String r1 = r1.getName()
            com.google.android.gms.common.internal.ClientSettings$Builder r0 = r0.setRealClientClassName(r1)
            android.content.Context r1 = r3.mContext
            java.lang.String r1 = r1.getPackageName()
            com.google.android.gms.common.internal.ClientSettings$Builder r0 = r0.setRealClientPackageName(r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.GoogleApi.createClientSettingsBuilder():com.google.android.gms.common.internal.ClientSettings$Builder");
    }

    public zace zaa(Context context, Handler handler) {
        return new zace(context, handler, createClientSettingsBuilder().build());
    }
}
