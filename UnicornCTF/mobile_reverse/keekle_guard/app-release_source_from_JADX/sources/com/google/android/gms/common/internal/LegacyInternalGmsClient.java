package com.google.android.gms.common.internal;

import android.content.Context;
import android.os.IInterface;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks;
import com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener;

@Deprecated
public abstract class LegacyInternalGmsClient<T extends IInterface> extends GmsClient<T> {
    private final GmsClientEventManager zags;

    public LegacyInternalGmsClient(Context context, int i, ClientSettings clientSettings, ConnectionCallbacks connectionCallbacks, OnConnectionFailedListener onConnectionFailedListener) {
        super(context, context.getMainLooper(), i, clientSettings);
        GmsClientEventManager gmsClientEventManager = new GmsClientEventManager(context.getMainLooper(), this);
        this.zags = gmsClientEventManager;
        gmsClientEventManager.registerConnectionCallbacks(connectionCallbacks);
        this.zags.registerConnectionFailedListener(onConnectionFailedListener);
    }

    public void checkAvailabilityAndConnect() {
        this.zags.enableCallbacks();
        super.checkAvailabilityAndConnect();
    }

    public void disconnect() {
        this.zags.disableCallbacks();
        super.disconnect();
    }

    public void onConnectedLocked(T t) {
        super.onConnectedLocked(t);
        this.zags.onConnectionSuccess(getConnectionHint());
    }

    public void onConnectionSuspended(int i) {
        super.onConnectionSuspended(i);
        this.zags.onUnintentionalDisconnection(i);
    }

    public void onConnectionFailed(ConnectionResult connectionResult) {
        super.onConnectionFailed(connectionResult);
        this.zags.onConnectionFailure(connectionResult);
    }

    public void registerConnectionCallbacks(ConnectionCallbacks connectionCallbacks) {
        this.zags.registerConnectionCallbacks(connectionCallbacks);
    }

    public void registerConnectionFailedListener(OnConnectionFailedListener onConnectionFailedListener) {
        this.zags.registerConnectionFailedListener(onConnectionFailedListener);
    }

    public boolean isConnectionCallbacksRegistered(ConnectionCallbacks connectionCallbacks) {
        return this.zags.isConnectionCallbacksRegistered(connectionCallbacks);
    }

    public void unregisterConnectionCallbacks(ConnectionCallbacks connectionCallbacks) {
        this.zags.unregisterConnectionCallbacks(connectionCallbacks);
    }

    public boolean isConnectionFailedListenerRegistered(OnConnectionFailedListener onConnectionFailedListener) {
        return this.zags.isConnectionFailedListenerRegistered(onConnectionFailedListener);
    }

    public void unregisterConnectionFailedListener(OnConnectionFailedListener onConnectionFailedListener) {
        this.zags.unregisterConnectionFailedListener(onConnectionFailedListener);
    }

    public int getMinApkVersion() {
        return super.getMinApkVersion();
    }
}
