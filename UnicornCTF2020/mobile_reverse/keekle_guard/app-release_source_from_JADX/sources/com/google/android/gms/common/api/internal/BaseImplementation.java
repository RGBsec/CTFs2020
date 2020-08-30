package com.google.android.gms.common.api.internal;

import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Api.AnyClient;
import com.google.android.gms.common.api.Api.AnyClientKey;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BasePendingResult.CallbackHandler;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.SimpleClientAdapter;

public class BaseImplementation {

    public static abstract class ApiMethodImpl<R extends Result, A extends AnyClient> extends BasePendingResult<R> implements ResultHolder<R> {
        private final Api<?> mApi;
        private final AnyClientKey<A> mClientKey;

        @Deprecated
        protected ApiMethodImpl(AnyClientKey<A> anyClientKey, GoogleApiClient googleApiClient) {
            super((GoogleApiClient) Preconditions.checkNotNull(googleApiClient, "GoogleApiClient must not be null"));
            this.mClientKey = (AnyClientKey) Preconditions.checkNotNull(anyClientKey);
            this.mApi = null;
        }

        /* access modifiers changed from: protected */
        public abstract void doExecute(A a) throws RemoteException;

        /* access modifiers changed from: protected */
        public void onSetFailedResult(R r) {
        }

        protected ApiMethodImpl(Api<?> api, GoogleApiClient googleApiClient) {
            super((GoogleApiClient) Preconditions.checkNotNull(googleApiClient, "GoogleApiClient must not be null"));
            Preconditions.checkNotNull(api, "Api must not be null");
            this.mClientKey = api.getClientKey();
            this.mApi = api;
        }

        protected ApiMethodImpl(CallbackHandler<R> callbackHandler) {
            super(callbackHandler);
            this.mClientKey = null;
            this.mApi = null;
        }

        public final AnyClientKey<A> getClientKey() {
            return this.mClientKey;
        }

        public final Api<?> getApi() {
            return this.mApi;
        }

        public final void run(A a) throws DeadObjectException {
            if (a instanceof SimpleClientAdapter) {
                a = ((SimpleClientAdapter) a).getClient();
            }
            try {
                doExecute(a);
            } catch (DeadObjectException e) {
                setFailedResult((RemoteException) e);
                throw e;
            } catch (RemoteException e2) {
                setFailedResult(e2);
            }
        }

        public final void setFailedResult(Status status) {
            Preconditions.checkArgument(!status.isSuccess(), "Failed result must not be success");
            Result createFailedResult = createFailedResult(status);
            setResult(createFailedResult);
            onSetFailedResult(createFailedResult);
        }

        private void setFailedResult(RemoteException remoteException) {
            setFailedResult(new Status(8, remoteException.getLocalizedMessage(), null));
        }

        public /* bridge */ /* synthetic */ void setResult(Object obj) {
            super.setResult((Result) obj);
        }
    }

    public interface ResultHolder<R> {
        void setFailedResult(Status status);

        void setResult(R r);
    }
}
