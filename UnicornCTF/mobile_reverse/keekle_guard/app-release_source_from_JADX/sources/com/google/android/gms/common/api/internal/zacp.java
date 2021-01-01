package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.api.Api.AnyClientKey;
import com.google.android.gms.common.api.Api.Client;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

public final class zacp {
    public static final Status zakx = new Status(8, "The connection to Google Play services was lost");
    private static final BasePendingResult<?>[] zaky = new BasePendingResult[0];
    private final Map<AnyClientKey<?>, Client> zagz;
    final Set<BasePendingResult<?>> zakz = Collections.synchronizedSet(Collections.newSetFromMap(new WeakHashMap()));
    private final zacs zala = new zacq(this);

    public zacp(Map<AnyClientKey<?>, Client> map) {
        this.zagz = map;
    }

    /* access modifiers changed from: 0000 */
    public final void zab(BasePendingResult<? extends Result> basePendingResult) {
        this.zakz.add(basePendingResult);
        basePendingResult.zaa(this.zala);
    }

    /* JADX WARNING: type inference failed for: r5v0, types: [com.google.android.gms.common.api.ResultCallback, com.google.android.gms.common.api.internal.zacs, com.google.android.gms.common.api.zac, com.google.android.gms.common.api.internal.zacq] */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r5v0, types: [com.google.android.gms.common.api.ResultCallback, com.google.android.gms.common.api.internal.zacs, com.google.android.gms.common.api.zac, com.google.android.gms.common.api.internal.zacq]
      assigns: [?[int, float, boolean, short, byte, char, OBJECT, ARRAY]]
      uses: [com.google.android.gms.common.api.internal.zacs, com.google.android.gms.common.api.ResultCallback, com.google.android.gms.common.api.zac, com.google.android.gms.common.api.internal.zacq]
      mth insns count: 47
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:99)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:92)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.core.ProcessClass.lambda$processDependencies$0(ProcessClass.java:49)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.ProcessClass.processDependencies(ProcessClass.java:49)
    	at jadx.core.ProcessClass.process(ProcessClass.java:35)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:217)
     */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void release() {
        /*
            r8 = this;
            java.util.Set<com.google.android.gms.common.api.internal.BasePendingResult<?>> r0 = r8.zakz
            com.google.android.gms.common.api.internal.BasePendingResult<?>[] r1 = zaky
            java.lang.Object[] r0 = r0.toArray(r1)
            com.google.android.gms.common.api.internal.BasePendingResult[] r0 = (com.google.android.gms.common.api.internal.BasePendingResult[]) r0
            int r1 = r0.length
            r2 = 0
            r3 = r2
        L_0x000d:
            if (r3 >= r1) goto L_0x0088
            r4 = r0[r3]
            r5 = 0
            r4.zaa(r5)
            java.lang.Integer r6 = r4.zam()
            if (r6 != 0) goto L_0x0027
            boolean r5 = r4.zat()
            if (r5 == 0) goto L_0x0085
            java.util.Set<com.google.android.gms.common.api.internal.BasePendingResult<?>> r5 = r8.zakz
            r5.remove(r4)
            goto L_0x0085
        L_0x0027:
            r4.setResultCallback(r5)
            java.util.Map<com.google.android.gms.common.api.Api$AnyClientKey<?>, com.google.android.gms.common.api.Api$Client> r6 = r8.zagz
            r7 = r4
            com.google.android.gms.common.api.internal.BaseImplementation$ApiMethodImpl r7 = (com.google.android.gms.common.api.internal.BaseImplementation.ApiMethodImpl) r7
            com.google.android.gms.common.api.Api$AnyClientKey r7 = r7.getClientKey()
            java.lang.Object r6 = r6.get(r7)
            com.google.android.gms.common.api.Api$Client r6 = (com.google.android.gms.common.api.Api.Client) r6
            android.os.IBinder r6 = r6.getServiceBrokerBinder()
            boolean r7 = r4.isReady()
            if (r7 == 0) goto L_0x004c
            com.google.android.gms.common.api.internal.zacr r7 = new com.google.android.gms.common.api.internal.zacr
            r7.<init>(r4, r5, r6, r5)
            r4.zaa(r7)
            goto L_0x0080
        L_0x004c:
            if (r6 == 0) goto L_0x006f
            boolean r7 = r6.isBinderAlive()
            if (r7 == 0) goto L_0x006f
            com.google.android.gms.common.api.internal.zacr r7 = new com.google.android.gms.common.api.internal.zacr
            r7.<init>(r4, r5, r6, r5)
            r4.zaa(r7)
            r6.linkToDeath(r7, r2)     // Catch:{ RemoteException -> 0x0060 }
            goto L_0x0080
        L_0x0060:
            r4.cancel()
            java.lang.Integer r6 = r4.zam()
            int r6 = r6.intValue()
            r5.remove(r6)
            goto L_0x0080
        L_0x006f:
            r4.zaa(r5)
            r4.cancel()
            java.lang.Integer r6 = r4.zam()
            int r6 = r6.intValue()
            r5.remove(r6)
        L_0x0080:
            java.util.Set<com.google.android.gms.common.api.internal.BasePendingResult<?>> r5 = r8.zakz
            r5.remove(r4)
        L_0x0085:
            int r3 = r3 + 1
            goto L_0x000d
        L_0x0088:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.api.internal.zacp.release():void");
    }

    public final void zabx() {
        for (BasePendingResult zab : (BasePendingResult[]) this.zakz.toArray(zaky)) {
            zab.zab(zakx);
        }
    }
}
