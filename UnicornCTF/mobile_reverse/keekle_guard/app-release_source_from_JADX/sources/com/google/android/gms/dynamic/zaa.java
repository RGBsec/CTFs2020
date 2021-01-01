package com.google.android.gms.dynamic;

import java.util.Iterator;

final class zaa implements OnDelegateCreatedListener<T> {
    private final /* synthetic */ DeferredLifecycleHelper zarj;

    zaa(DeferredLifecycleHelper deferredLifecycleHelper) {
        this.zarj = deferredLifecycleHelper;
    }

    public final void onDelegateCreated(T t) {
        this.zarj.zarf = t;
        Iterator it = this.zarj.zarh.iterator();
        while (it.hasNext()) {
            ((zaa) it.next()).zaa(this.zarj.zarf);
        }
        this.zarj.zarh.clear();
        this.zarj.zarg = null;
    }
}
