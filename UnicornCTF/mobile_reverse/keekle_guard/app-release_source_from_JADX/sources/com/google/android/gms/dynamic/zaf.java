package com.google.android.gms.dynamic;

final class zaf implements zaa {
    private final /* synthetic */ DeferredLifecycleHelper zarj;

    zaf(DeferredLifecycleHelper deferredLifecycleHelper) {
        this.zarj = deferredLifecycleHelper;
    }

    public final int getState() {
        return 4;
    }

    public final void zaa(LifecycleDelegate lifecycleDelegate) {
        this.zarj.zarf.onStart();
    }
}
