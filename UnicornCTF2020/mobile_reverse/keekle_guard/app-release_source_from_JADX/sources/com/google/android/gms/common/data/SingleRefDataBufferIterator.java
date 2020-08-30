package com.google.android.gms.common.data;

import java.util.NoSuchElementException;

public class SingleRefDataBufferIterator<T> extends DataBufferIterator<T> {
    private T zamg;

    public SingleRefDataBufferIterator(DataBuffer<T> dataBuffer) {
        super(dataBuffer);
    }

    public T next() {
        if (hasNext()) {
            this.zall++;
            if (this.zall == 0) {
                T t = this.zalk.get(0);
                this.zamg = t;
                if (!(t instanceof DataBufferRef)) {
                    String valueOf = String.valueOf(this.zamg.getClass());
                    StringBuilder sb = new StringBuilder(String.valueOf(valueOf).length() + 44);
                    sb.append("DataBuffer reference of type ");
                    sb.append(valueOf);
                    sb.append(" is not movable");
                    throw new IllegalStateException(sb.toString());
                }
            } else {
                ((DataBufferRef) this.zamg).zag(this.zall);
            }
            return this.zamg;
        }
        int i = this.zall;
        StringBuilder sb2 = new StringBuilder(46);
        sb2.append("Cannot advance the iterator beyond ");
        sb2.append(i);
        throw new NoSuchElementException(sb2.toString());
    }
}
