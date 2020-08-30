package com.google.android.gms.common.data;

import com.google.android.gms.common.data.DataBufferObserver.Observable;
import java.util.HashSet;
import java.util.Iterator;

public final class DataBufferObserverSet implements DataBufferObserver, Observable {
    private HashSet<DataBufferObserver> zalm = new HashSet<>();

    public final boolean hasObservers() {
        return !this.zalm.isEmpty();
    }

    public final void clear() {
        this.zalm.clear();
    }

    public final void addObserver(DataBufferObserver dataBufferObserver) {
        this.zalm.add(dataBufferObserver);
    }

    public final void removeObserver(DataBufferObserver dataBufferObserver) {
        this.zalm.remove(dataBufferObserver);
    }

    public final void onDataChanged() {
        Iterator it = this.zalm.iterator();
        while (it.hasNext()) {
            ((DataBufferObserver) it.next()).onDataChanged();
        }
    }

    public final void onDataRangeChanged(int i, int i2) {
        Iterator it = this.zalm.iterator();
        while (it.hasNext()) {
            ((DataBufferObserver) it.next()).onDataRangeChanged(i, i2);
        }
    }

    public final void onDataRangeInserted(int i, int i2) {
        Iterator it = this.zalm.iterator();
        while (it.hasNext()) {
            ((DataBufferObserver) it.next()).onDataRangeInserted(i, i2);
        }
    }

    public final void onDataRangeRemoved(int i, int i2) {
        Iterator it = this.zalm.iterator();
        while (it.hasNext()) {
            ((DataBufferObserver) it.next()).onDataRangeRemoved(i, i2);
        }
    }

    public final void onDataRangeMoved(int i, int i2, int i3) {
        Iterator it = this.zalm.iterator();
        while (it.hasNext()) {
            ((DataBufferObserver) it.next()).onDataRangeMoved(i, i2, i3);
        }
    }
}
