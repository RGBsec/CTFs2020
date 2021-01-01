package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.internal.BaseGmsClient.ConnectionProgressReportCallbacks;
import com.google.android.gms.common.internal.GoogleApiAvailabilityCache;
import java.util.ArrayList;
import java.util.Map;

final class zaan extends zaau {
    final /* synthetic */ zaak zagj;
    private final Map<Client, zaam> zagl;

    public zaan(zaak zaak, Map<Client, zaam> map) {
        this.zagj = zaak;
        super(zaak, null);
        this.zagl = map;
    }

    public final void zaan() {
        GoogleApiAvailabilityCache googleApiAvailabilityCache = new GoogleApiAvailabilityCache(this.zagj.zaey);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        for (Client client : this.zagl.keySet()) {
            if (!client.requiresGooglePlayServices() || ((zaam) this.zagl.get(client)).zaec) {
                arrayList2.add(client);
            } else {
                arrayList.add(client);
            }
        }
        int i = -1;
        int i2 = 0;
        if (!arrayList.isEmpty()) {
            ArrayList arrayList3 = arrayList;
            int size = arrayList3.size();
            while (i2 < size) {
                Object obj = arrayList3.get(i2);
                i2++;
                i = googleApiAvailabilityCache.getClientAvailability(this.zagj.mContext, (Client) obj);
                if (i != 0) {
                    break;
                }
            }
        } else {
            ArrayList arrayList4 = arrayList2;
            int size2 = arrayList4.size();
            while (i2 < size2) {
                Object obj2 = arrayList4.get(i2);
                i2++;
                i = googleApiAvailabilityCache.getClientAvailability(this.zagj.mContext, (Client) obj2);
                if (i == 0) {
                    break;
                }
            }
        }
        if (i != 0) {
            this.zagj.zaft.zaa((zabf) new zaao(this, this.zagj, new ConnectionResult(i, null)));
            return;
        }
        if (this.zagj.zagd && this.zagj.zagb != null) {
            this.zagj.zagb.connect();
        }
        for (Client client2 : this.zagl.keySet()) {
            ConnectionProgressReportCallbacks connectionProgressReportCallbacks = (ConnectionProgressReportCallbacks) this.zagl.get(client2);
            if (!client2.requiresGooglePlayServices() || googleApiAvailabilityCache.getClientAvailability(this.zagj.mContext, client2) == 0) {
                client2.connect(connectionProgressReportCallbacks);
            } else {
                this.zagj.zaft.zaa((zabf) new zaap(this, this.zagj, connectionProgressReportCallbacks));
            }
        }
    }
}
