package com.google.android.gms.common.internal;

import android.content.Context;
import android.util.SparseIntArray;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GoogleApiAvailabilityLight;
import com.google.android.gms.common.api.Api.Client;

public class GoogleApiAvailabilityCache {
    private final SparseIntArray zaos;
    private GoogleApiAvailabilityLight zaot;

    public GoogleApiAvailabilityCache() {
        this(GoogleApiAvailability.getInstance());
    }

    public GoogleApiAvailabilityCache(GoogleApiAvailabilityLight googleApiAvailabilityLight) {
        this.zaos = new SparseIntArray();
        Preconditions.checkNotNull(googleApiAvailabilityLight);
        this.zaot = googleApiAvailabilityLight;
    }

    public int getClientAvailability(Context context, Client client) {
        Preconditions.checkNotNull(context);
        Preconditions.checkNotNull(client);
        int i = 0;
        if (!client.requiresGooglePlayServices()) {
            return 0;
        }
        int minApkVersion = client.getMinApkVersion();
        int i2 = this.zaos.get(minApkVersion, -1);
        if (i2 != -1) {
            return i2;
        }
        int i3 = 0;
        while (true) {
            if (i3 >= this.zaos.size()) {
                i = i2;
                break;
            }
            int keyAt = this.zaos.keyAt(i3);
            if (keyAt > minApkVersion && this.zaos.get(keyAt) == 0) {
                break;
            }
            i3++;
        }
        if (i == -1) {
            i = this.zaot.isGooglePlayServicesAvailable(context, minApkVersion);
        }
        this.zaos.put(minApkVersion, i);
        return i;
    }

    public void flush() {
        this.zaos.clear();
    }
}
