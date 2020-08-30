package com.google.android.gms.common.server.response;

import com.google.android.gms.common.server.response.FastParser.ParseException;
import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;

final class zag implements zaa<BigInteger> {
    zag() {
    }

    public final /* synthetic */ Object zah(FastParser fastParser, BufferedReader bufferedReader) throws ParseException, IOException {
        return fastParser.zaf(bufferedReader);
    }
}
