package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Api.Client;
import java.util.ArrayList;

final class zaaq extends zaau {
    private final /* synthetic */ zaak zagj;
    private final ArrayList<Client> zagp;

    public zaaq(zaak zaak, ArrayList<Client> arrayList) {
        this.zagj = zaak;
        super(zaak, null);
        this.zagp = arrayList;
    }

    public final void zaan() {
        this.zagj.zaft.zaee.zaha = this.zagj.zaat();
        ArrayList arrayList = this.zagp;
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            Object obj = arrayList.get(i);
            i++;
            ((Client) obj).getRemoteService(this.zagj.zagf, this.zagj.zaft.zaee.zaha);
        }
    }
}
