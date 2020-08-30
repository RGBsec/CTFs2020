package com.google.android.gms.common.server.response;

import com.google.android.gms.common.server.response.FastParser.ParseException;
import java.io.BufferedReader;
import java.io.IOException;

final class zad implements zaa<Double> {
    zad() {
    }

    public final /* synthetic */ Object zah(FastParser fastParser, BufferedReader bufferedReader) throws ParseException, IOException {
        return Double.valueOf(fastParser.zah(bufferedReader));
    }
}
