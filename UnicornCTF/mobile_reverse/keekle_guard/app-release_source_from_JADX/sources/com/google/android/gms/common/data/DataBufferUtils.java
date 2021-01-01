package com.google.android.gms.common.data;

import android.os.Bundle;
import java.util.ArrayList;

public final class DataBufferUtils {
    public static final String KEY_NEXT_PAGE_TOKEN = "next_page_token";
    public static final String KEY_PREV_PAGE_TOKEN = "prev_page_token";

    private DataBufferUtils() {
    }

    public static <T, E extends Freezable<T>> ArrayList<T> freezeAndClose(DataBuffer<E> dataBuffer) {
        ArrayList<T> arrayList = new ArrayList<>(dataBuffer.getCount());
        try {
            for (E freeze : dataBuffer) {
                arrayList.add(freeze.freeze());
            }
            return arrayList;
        } finally {
            dataBuffer.close();
        }
    }

    public static boolean hasNextPage(DataBuffer<?> dataBuffer) {
        Bundle metadata = dataBuffer.getMetadata();
        return (metadata == null || metadata.getString(KEY_NEXT_PAGE_TOKEN) == null) ? false : true;
    }

    public static boolean hasPrevPage(DataBuffer<?> dataBuffer) {
        Bundle metadata = dataBuffer.getMetadata();
        return (metadata == null || metadata.getString(KEY_PREV_PAGE_TOKEN) == null) ? false : true;
    }

    public static boolean hasData(DataBuffer<?> dataBuffer) {
        return dataBuffer != null && dataBuffer.getCount() > 0;
    }
}
