package com.google.android.gms.common.data;

import android.content.ContentValues;
import com.google.android.gms.common.data.DataHolder.Builder;
import java.util.HashMap;

final class zab extends Builder {
    zab(String[] strArr, String str) {
        super(strArr, null, null);
    }

    public final Builder zaa(HashMap<String, Object> hashMap) {
        throw new UnsupportedOperationException("Cannot add data to empty builder");
    }

    public final Builder withRow(ContentValues contentValues) {
        throw new UnsupportedOperationException("Cannot add data to empty builder");
    }
}
