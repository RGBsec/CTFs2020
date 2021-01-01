package com.google.android.gms.common.server.response;

import android.util.Log;
import com.google.android.gms.common.server.response.FastJsonResponse;
import com.google.android.gms.common.server.response.FastJsonResponse.Field;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Stack;

public class FastParser<T extends FastJsonResponse> {
    private static final char[] zaqg = {'u', 'l', 'l'};
    private static final char[] zaqh = {'r', 'u', 'e'};
    private static final char[] zaqi = {'r', 'u', 'e', '\"'};
    private static final char[] zaqj = {'a', 'l', 's', 'e'};
    private static final char[] zaqk = {'a', 'l', 's', 'e', '\"'};
    private static final char[] zaql = {10};
    private static final zaa<Integer> zaqn = new zaa();
    private static final zaa<Long> zaqo = new zab();
    private static final zaa<Float> zaqp = new zac();
    private static final zaa<Double> zaqq = new zad();
    private static final zaa<Boolean> zaqr = new zae();
    private static final zaa<String> zaqs = new zaf();
    private static final zaa<BigInteger> zaqt = new zag();
    private static final zaa<BigDecimal> zaqu = new zah();
    private final char[] zaqb = new char[1];
    private final char[] zaqc = new char[32];
    private final char[] zaqd = new char[1024];
    private final StringBuilder zaqe = new StringBuilder(32);
    private final StringBuilder zaqf = new StringBuilder(1024);
    private final Stack<Integer> zaqm = new Stack<>();

    public static class ParseException extends Exception {
        public ParseException(String str) {
            super(str);
        }

        public ParseException(String str, Throwable th) {
            super(str, th);
        }

        public ParseException(Throwable th) {
            super(th);
        }
    }

    private interface zaa<O> {
        O zah(FastParser fastParser, BufferedReader bufferedReader) throws ParseException, IOException;
    }

    public void parse(InputStream inputStream, T t) throws ParseException {
        String str = "Failed to close reader while parsing.";
        String str2 = "FastParser";
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream), 1024);
        try {
            this.zaqm.push(Integer.valueOf(0));
            char zaj = zaj(bufferedReader);
            if (zaj != 0) {
                if (zaj == '[') {
                    this.zaqm.push(Integer.valueOf(5));
                    Map fieldMappings = t.getFieldMappings();
                    if (fieldMappings.size() == 1) {
                        Field field = (Field) ((Entry) fieldMappings.entrySet().iterator().next()).getValue();
                        t.addConcreteTypeArrayInternal(field, field.zapv, zaa(bufferedReader, field));
                    } else {
                        throw new ParseException("Object array response class must have a single Field");
                    }
                } else if (zaj == '{') {
                    this.zaqm.push(Integer.valueOf(1));
                    zaa(bufferedReader, (FastJsonResponse) t);
                } else {
                    StringBuilder sb = new StringBuilder(19);
                    sb.append("Unexpected token: ");
                    sb.append(zaj);
                    throw new ParseException(sb.toString());
                }
                zak(0);
                try {
                    bufferedReader.close();
                } catch (IOException unused) {
                    Log.w(str2, str);
                }
            } else {
                throw new ParseException("No data to parse");
            }
        } catch (IOException e) {
            throw new ParseException((Throwable) e);
        } catch (Throwable th) {
            try {
                bufferedReader.close();
            } catch (IOException unused2) {
                Log.w(str2, str);
            }
            throw th;
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:113:0x026d, code lost:
        r5 = 4;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:114:0x026e, code lost:
        zak(r5);
        zak(2);
        r5 = zaj(r17);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:115:0x0279, code lost:
        if (r5 == ',') goto L_0x0299;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:116:0x027b, code lost:
        if (r5 != '}') goto L_0x0280;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:117:0x027d, code lost:
        r5 = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:118:0x0280, code lost:
        r3 = new java.lang.StringBuilder(55);
        r3.append("Expected end of object or field separator, but found: ");
        r3.append(r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:119:0x0298, code lost:
        throw new com.google.android.gms.common.server.response.FastParser.ParseException(r3.toString());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:120:0x0299, code lost:
        r5 = zaa(r17);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:80:0x01b6, code lost:
        r5 = 4;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private final boolean zaa(java.io.BufferedReader r17, com.google.android.gms.common.server.response.FastJsonResponse r18) throws com.google.android.gms.common.server.response.FastParser.ParseException, java.io.IOException {
        /*
            r16 = this;
            r1 = r16
            r0 = r17
            r2 = r18
            java.lang.String r3 = "Error instantiating inner object"
            java.util.Map r4 = r18.getFieldMappings()
            java.lang.String r5 = r16.zaa(r17)
            r6 = 0
            r7 = 1
            java.lang.Integer r8 = java.lang.Integer.valueOf(r7)
            if (r5 != 0) goto L_0x001c
            r1.zak(r7)
            return r6
        L_0x001c:
            r9 = 0
        L_0x001d:
            if (r5 == 0) goto L_0x029f
            java.lang.Object r5 = r4.get(r5)
            com.google.android.gms.common.server.response.FastJsonResponse$Field r5 = (com.google.android.gms.common.server.response.FastJsonResponse.Field) r5
            if (r5 != 0) goto L_0x002c
            java.lang.String r5 = r16.zab(r17)
            goto L_0x001d
        L_0x002c:
            java.util.Stack<java.lang.Integer> r10 = r1.zaqm
            r11 = 4
            java.lang.Integer r12 = java.lang.Integer.valueOf(r11)
            r10.push(r12)
            int r10 = r5.zapr
            r12 = 123(0x7b, float:1.72E-43)
            r13 = 44
            r14 = 125(0x7d, float:1.75E-43)
            r15 = 110(0x6e, float:1.54E-43)
            switch(r10) {
                case 0: goto L_0x0258;
                case 1: goto L_0x0242;
                case 2: goto L_0x022c;
                case 3: goto L_0x0216;
                case 4: goto L_0x0200;
                case 5: goto L_0x01e8;
                case 6: goto L_0x01d0;
                case 7: goto L_0x01ba;
                case 8: goto L_0x01a5;
                case 9: goto L_0x0193;
                case 10: goto L_0x00d0;
                case 11: goto L_0x005e;
                default: goto L_0x0043;
            }
        L_0x0043:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            int r2 = r5.zapr
            r3 = 30
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>(r3)
            java.lang.String r3 = "Invalid field type "
            r4.append(r3)
            r4.append(r2)
            java.lang.String r2 = r4.toString()
            r0.<init>(r2)
            throw r0
        L_0x005e:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x0093
            char r10 = r16.zaj(r17)
            if (r10 != r15) goto L_0x0073
            char[] r10 = zaqg
            r1.zab(r0, r10)
            java.lang.String r10 = r5.zapv
            r2.addConcreteTypeArrayInternal(r5, r10, r9)
            goto L_0x00a3
        L_0x0073:
            java.util.Stack<java.lang.Integer> r12 = r1.zaqm
            r15 = 5
            java.lang.Integer r15 = java.lang.Integer.valueOf(r15)
            r12.push(r15)
            r12 = 91
            if (r10 != r12) goto L_0x008b
            java.lang.String r10 = r5.zapv
            java.util.ArrayList r12 = r1.zaa(r0, r5)
            r2.addConcreteTypeArrayInternal(r5, r10, r12)
            goto L_0x00a3
        L_0x008b:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "Expected array start"
            r0.<init>(r2)
            throw r0
        L_0x0093:
            char r10 = r16.zaj(r17)
            if (r10 != r15) goto L_0x00a6
            char[] r10 = zaqg
            r1.zab(r0, r10)
            java.lang.String r10 = r5.zapv
            r2.addConcreteTypeInternal(r5, r10, r9)
        L_0x00a3:
            r5 = r11
            goto L_0x026e
        L_0x00a6:
            java.util.Stack<java.lang.Integer> r15 = r1.zaqm
            r15.push(r8)
            if (r10 != r12) goto L_0x00c8
            com.google.android.gms.common.server.response.FastJsonResponse r10 = r5.zacp()     // Catch:{ InstantiationException -> 0x00c1, IllegalAccessException -> 0x00ba }
            r1.zaa(r0, r10)     // Catch:{ InstantiationException -> 0x00c1, IllegalAccessException -> 0x00ba }
            java.lang.String r12 = r5.zapv     // Catch:{ InstantiationException -> 0x00c1, IllegalAccessException -> 0x00ba }
            r2.addConcreteTypeInternal(r5, r12, r10)     // Catch:{ InstantiationException -> 0x00c1, IllegalAccessException -> 0x00ba }
            goto L_0x00a3
        L_0x00ba:
            r0 = move-exception
            com.google.android.gms.common.server.response.FastParser$ParseException r2 = new com.google.android.gms.common.server.response.FastParser$ParseException
            r2.<init>(r3, r0)
            throw r2
        L_0x00c1:
            r0 = move-exception
            com.google.android.gms.common.server.response.FastParser$ParseException r2 = new com.google.android.gms.common.server.response.FastParser$ParseException
            r2.<init>(r3, r0)
            throw r2
        L_0x00c8:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "Expected start of object"
            r0.<init>(r2)
            throw r0
        L_0x00d0:
            char r10 = r16.zaj(r17)
            if (r10 != r15) goto L_0x00de
            char[] r10 = zaqg
            r1.zab(r0, r10)
            r10 = r9
            goto L_0x0162
        L_0x00de:
            if (r10 != r12) goto L_0x018b
            java.util.Stack<java.lang.Integer> r10 = r1.zaqm
            r10.push(r8)
            java.util.HashMap r10 = new java.util.HashMap
            r10.<init>()
        L_0x00ea:
            char r12 = r16.zaj(r17)
            if (r12 == 0) goto L_0x0183
            r15 = 34
            if (r12 == r15) goto L_0x00fc
            if (r12 == r14) goto L_0x00f8
            goto L_0x017f
        L_0x00f8:
            r1.zak(r7)
            goto L_0x0162
        L_0x00fc:
            char[] r12 = r1.zaqc
            java.lang.StringBuilder r11 = r1.zaqe
            java.lang.String r11 = zab(r0, r12, r11, r9)
            char r12 = r16.zaj(r17)
            r6 = 58
            if (r12 == r6) goto L_0x0129
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "No map value found for key "
            java.lang.String r3 = java.lang.String.valueOf(r11)
            int r4 = r3.length()
            if (r4 == 0) goto L_0x011f
            java.lang.String r2 = r2.concat(r3)
            goto L_0x0125
        L_0x011f:
            java.lang.String r3 = new java.lang.String
            r3.<init>(r2)
            r2 = r3
        L_0x0125:
            r0.<init>(r2)
            throw r0
        L_0x0129:
            char r6 = r16.zaj(r17)
            if (r6 == r15) goto L_0x014c
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "Expected String value for key "
            java.lang.String r3 = java.lang.String.valueOf(r11)
            int r4 = r3.length()
            if (r4 == 0) goto L_0x0142
            java.lang.String r2 = r2.concat(r3)
            goto L_0x0148
        L_0x0142:
            java.lang.String r3 = new java.lang.String
            r3.<init>(r2)
            r2 = r3
        L_0x0148:
            r0.<init>(r2)
            throw r0
        L_0x014c:
            char[] r6 = r1.zaqc
            java.lang.StringBuilder r12 = r1.zaqe
            java.lang.String r6 = zab(r0, r6, r12, r9)
            r10.put(r11, r6)
            char r6 = r16.zaj(r17)
            if (r6 == r13) goto L_0x017f
            if (r6 != r14) goto L_0x0166
            r1.zak(r7)
        L_0x0162:
            r2.zaa(r5, r10)
            goto L_0x01b6
        L_0x0166:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            r2 = 48
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            r3.<init>(r2)
            java.lang.String r2 = "Unexpected character while parsing string map: "
            r3.append(r2)
            r3.append(r6)
            java.lang.String r2 = r3.toString()
            r0.<init>(r2)
            throw r0
        L_0x017f:
            r6 = 0
            r11 = 4
            goto L_0x00ea
        L_0x0183:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "Unexpected EOF"
            r0.<init>(r2)
            throw r0
        L_0x018b:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r2 = "Expected start of a map object"
            r0.<init>(r2)
            throw r0
        L_0x0193:
            char[] r6 = r1.zaqd
            java.lang.StringBuilder r10 = r1.zaqf
            char[] r11 = zaql
            java.lang.String r6 = r1.zaa(r0, r6, r10, r11)
            byte[] r6 = com.google.android.gms.common.util.Base64Utils.decodeUrlSafe(r6)
            r2.zaa(r5, r6)
            goto L_0x01b6
        L_0x01a5:
            char[] r6 = r1.zaqd
            java.lang.StringBuilder r10 = r1.zaqf
            char[] r11 = zaql
            java.lang.String r6 = r1.zaa(r0, r6, r10, r11)
            byte[] r6 = com.google.android.gms.common.util.Base64Utils.decode(r6)
            r2.zaa(r5, r6)
        L_0x01b6:
            r5 = 4
            r6 = 0
            goto L_0x026e
        L_0x01ba:
            boolean r6 = r5.zaps
            if (r6 == 0) goto L_0x01c8
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.String> r6 = zaqs
            java.util.ArrayList r6 = r1.zaa(r0, r6)
            r2.zah(r5, r6)
            goto L_0x01b6
        L_0x01c8:
            java.lang.String r6 = r16.zac(r17)
            r2.zaa(r5, r6)
            goto L_0x01b6
        L_0x01d0:
            boolean r6 = r5.zaps
            if (r6 == 0) goto L_0x01de
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.Boolean> r6 = zaqr
            java.util.ArrayList r6 = r1.zaa(r0, r6)
            r2.zag(r5, r6)
            goto L_0x01b6
        L_0x01de:
            r6 = 0
            boolean r10 = r1.zaa(r0, r6)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x01e8:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x01f7
            com.google.android.gms.common.server.response.FastParser$zaa<java.math.BigDecimal> r10 = zaqu
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zaf(r5, r10)
            goto L_0x026d
        L_0x01f7:
            java.math.BigDecimal r10 = r16.zai(r17)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x0200:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x020e
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.Double> r10 = zaqq
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zae(r5, r10)
            goto L_0x026d
        L_0x020e:
            double r10 = r16.zah(r17)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x0216:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x0224
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.Float> r10 = zaqp
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zad(r5, r10)
            goto L_0x026d
        L_0x0224:
            float r10 = r16.zag(r17)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x022c:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x023a
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.Long> r10 = zaqo
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zac(r5, r10)
            goto L_0x026d
        L_0x023a:
            long r10 = r16.zae(r17)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x0242:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x0250
            com.google.android.gms.common.server.response.FastParser$zaa<java.math.BigInteger> r10 = zaqt
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zab(r5, r10)
            goto L_0x026d
        L_0x0250:
            java.math.BigInteger r10 = r16.zaf(r17)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x0258:
            boolean r10 = r5.zaps
            if (r10 == 0) goto L_0x0266
            com.google.android.gms.common.server.response.FastParser$zaa<java.lang.Integer> r10 = zaqn
            java.util.ArrayList r10 = r1.zaa(r0, r10)
            r2.zaa(r5, r10)
            goto L_0x026d
        L_0x0266:
            int r10 = r16.zad(r17)
            r2.zaa(r5, r10)
        L_0x026d:
            r5 = 4
        L_0x026e:
            r1.zak(r5)
            r5 = 2
            r1.zak(r5)
            char r5 = r16.zaj(r17)
            if (r5 == r13) goto L_0x0299
            if (r5 != r14) goto L_0x0280
            r5 = r9
            goto L_0x001d
        L_0x0280:
            com.google.android.gms.common.server.response.FastParser$ParseException r0 = new com.google.android.gms.common.server.response.FastParser$ParseException
            r2 = 55
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            r3.<init>(r2)
            java.lang.String r2 = "Expected end of object or field separator, but found: "
            r3.append(r2)
            r3.append(r5)
            java.lang.String r2 = r3.toString()
            r0.<init>(r2)
            throw r0
        L_0x0299:
            java.lang.String r5 = r16.zaa(r17)
            goto L_0x001d
        L_0x029f:
            r1.zak(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.server.response.FastParser.zaa(java.io.BufferedReader, com.google.android.gms.common.server.response.FastJsonResponse):boolean");
    }

    private final String zaa(BufferedReader bufferedReader) throws ParseException, IOException {
        this.zaqm.push(Integer.valueOf(2));
        char zaj = zaj(bufferedReader);
        if (zaj == '\"') {
            this.zaqm.push(Integer.valueOf(3));
            String zab = zab(bufferedReader, this.zaqc, this.zaqe, null);
            zak(3);
            if (zaj(bufferedReader) == ':') {
                return zab;
            }
            throw new ParseException("Expected key/value separator");
        } else if (zaj == ']') {
            zak(2);
            zak(1);
            zak(5);
            return null;
        } else if (zaj == '}') {
            zak(2);
            return null;
        } else {
            StringBuilder sb = new StringBuilder(19);
            sb.append("Unexpected token: ");
            sb.append(zaj);
            throw new ParseException(sb.toString());
        }
    }

    private final String zab(BufferedReader bufferedReader) throws ParseException, IOException {
        BufferedReader bufferedReader2 = bufferedReader;
        bufferedReader2.mark(1024);
        char zaj = zaj(bufferedReader);
        String str = "Unexpected token ";
        if (zaj == '\"') {
            String str2 = "Unexpected EOF while parsing string";
            if (bufferedReader2.read(this.zaqb) != -1) {
                char c = this.zaqb[0];
                boolean z = false;
                do {
                    if (c != '\"' || z) {
                        z = c == '\\' ? !z : false;
                        if (bufferedReader2.read(this.zaqb) != -1) {
                            c = this.zaqb[0];
                        } else {
                            throw new ParseException(str2);
                        }
                    }
                } while (!Character.isISOControl(c));
                throw new ParseException("Unexpected control character while reading string");
            }
            throw new ParseException(str2);
        } else if (zaj != ',') {
            int i = 1;
            if (zaj == '[') {
                this.zaqm.push(Integer.valueOf(5));
                bufferedReader2.mark(32);
                if (zaj(bufferedReader) == ']') {
                    zak(5);
                } else {
                    bufferedReader.reset();
                    boolean z2 = false;
                    boolean z3 = false;
                    while (i > 0) {
                        char zaj2 = zaj(bufferedReader);
                        if (zaj2 == 0) {
                            throw new ParseException("Unexpected EOF while parsing array");
                        } else if (!Character.isISOControl(zaj2)) {
                            if (zaj2 == '\"' && !z2) {
                                z3 = !z3;
                            }
                            if (zaj2 == '[' && !z3) {
                                i++;
                            }
                            if (zaj2 == ']' && !z3) {
                                i--;
                            }
                            z2 = (zaj2 != '\\' || !z3) ? false : !z2;
                        } else {
                            throw new ParseException("Unexpected control character while reading array");
                        }
                    }
                    zak(5);
                }
            } else if (zaj != '{') {
                bufferedReader.reset();
                zaa(bufferedReader2, this.zaqd);
            } else {
                this.zaqm.push(Integer.valueOf(1));
                bufferedReader2.mark(32);
                char zaj3 = zaj(bufferedReader);
                if (zaj3 == '}') {
                    zak(1);
                } else if (zaj3 == '\"') {
                    bufferedReader.reset();
                    zaa(bufferedReader);
                    do {
                    } while (zab(bufferedReader) != null);
                    zak(1);
                } else {
                    StringBuilder sb = new StringBuilder(18);
                    sb.append(str);
                    sb.append(zaj3);
                    throw new ParseException(sb.toString());
                }
            }
        } else {
            throw new ParseException("Missing value");
        }
        char zaj4 = zaj(bufferedReader);
        if (zaj4 == ',') {
            zak(2);
            return zaa(bufferedReader);
        } else if (zaj4 == '}') {
            zak(2);
            return null;
        } else {
            StringBuilder sb2 = new StringBuilder(18);
            sb2.append(str);
            sb2.append(zaj4);
            throw new ParseException(sb2.toString());
        }
    }

    /* access modifiers changed from: private */
    public final String zac(BufferedReader bufferedReader) throws ParseException, IOException {
        return zaa(bufferedReader, this.zaqc, this.zaqe, null);
    }

    private final <O> ArrayList<O> zaa(BufferedReader bufferedReader, zaa<O> zaa2) throws ParseException, IOException {
        char zaj = zaj(bufferedReader);
        if (zaj == 'n') {
            zab(bufferedReader, zaqg);
            return null;
        } else if (zaj == '[') {
            this.zaqm.push(Integer.valueOf(5));
            ArrayList<O> arrayList = new ArrayList<>();
            while (true) {
                bufferedReader.mark(1024);
                char zaj2 = zaj(bufferedReader);
                if (zaj2 == 0) {
                    throw new ParseException("Unexpected EOF");
                } else if (zaj2 != ',') {
                    if (zaj2 != ']') {
                        bufferedReader.reset();
                        arrayList.add(zaa2.zah(this, bufferedReader));
                    } else {
                        zak(5);
                        return arrayList;
                    }
                }
            }
        } else {
            throw new ParseException("Expected start of array");
        }
    }

    private final String zaa(BufferedReader bufferedReader, char[] cArr, StringBuilder sb, char[] cArr2) throws ParseException, IOException {
        char zaj = zaj(bufferedReader);
        if (zaj == '\"') {
            return zab(bufferedReader, cArr, sb, cArr2);
        }
        if (zaj == 'n') {
            zab(bufferedReader, zaqg);
            return null;
        }
        throw new ParseException("Expected string");
    }

    /* JADX WARNING: Removed duplicated region for block: B:37:0x0030 A[SYNTHETIC] */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static java.lang.String zab(java.io.BufferedReader r9, char[] r10, java.lang.StringBuilder r11, char[] r12) throws com.google.android.gms.common.server.response.FastParser.ParseException, java.io.IOException {
        /*
            r0 = 0
            r11.setLength(r0)
            int r1 = r10.length
            r9.mark(r1)
            r1 = r0
            r2 = r1
        L_0x000a:
            int r3 = r9.read(r10)
            r4 = -1
            if (r3 == r4) goto L_0x006d
            r4 = r0
        L_0x0012:
            if (r4 >= r3) goto L_0x0065
            char r5 = r10[r4]
            boolean r6 = java.lang.Character.isISOControl(r5)
            r7 = 1
            if (r6 == 0) goto L_0x0038
            if (r12 == 0) goto L_0x002c
            r6 = r0
        L_0x0020:
            int r8 = r12.length
            if (r6 >= r8) goto L_0x002c
            char r8 = r12[r6]
            if (r8 != r5) goto L_0x0029
            r6 = r7
            goto L_0x002d
        L_0x0029:
            int r6 = r6 + 1
            goto L_0x0020
        L_0x002c:
            r6 = r0
        L_0x002d:
            if (r6 == 0) goto L_0x0030
            goto L_0x0038
        L_0x0030:
            com.google.android.gms.common.server.response.FastParser$ParseException r9 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r10 = "Unexpected control character while reading string"
            r9.<init>(r10)
            throw r9
        L_0x0038:
            r6 = 34
            if (r5 != r6) goto L_0x0059
            if (r1 != 0) goto L_0x0059
            r11.append(r10, r0, r4)
            r9.reset()
            int r4 = r4 + r7
            long r0 = (long) r4
            r9.skip(r0)
            if (r2 == 0) goto L_0x0054
            java.lang.String r9 = r11.toString()
            java.lang.String r9 = com.google.android.gms.common.util.JsonUtils.unescapeString(r9)
            return r9
        L_0x0054:
            java.lang.String r9 = r11.toString()
            return r9
        L_0x0059:
            r6 = 92
            if (r5 != r6) goto L_0x0061
            r1 = r1 ^ 1
            r2 = r7
            goto L_0x0062
        L_0x0061:
            r1 = r0
        L_0x0062:
            int r4 = r4 + 1
            goto L_0x0012
        L_0x0065:
            r11.append(r10, r0, r3)
            int r3 = r10.length
            r9.mark(r3)
            goto L_0x000a
        L_0x006d:
            com.google.android.gms.common.server.response.FastParser$ParseException r9 = new com.google.android.gms.common.server.response.FastParser$ParseException
            java.lang.String r10 = "Unexpected EOF while parsing string"
            r9.<init>(r10)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.server.response.FastParser.zab(java.io.BufferedReader, char[], java.lang.StringBuilder, char[]):java.lang.String");
    }

    /* access modifiers changed from: private */
    public final int zad(BufferedReader bufferedReader) throws ParseException, IOException {
        int i;
        int i2;
        int zaa2 = zaa(bufferedReader, this.zaqd);
        int i3 = 0;
        if (zaa2 == 0) {
            return 0;
        }
        char[] cArr = this.zaqd;
        if (zaa2 > 0) {
            if (cArr[0] == '-') {
                i2 = Integer.MIN_VALUE;
                i = 1;
            } else {
                i2 = -2147483647;
                i = 0;
            }
            int i4 = i;
            String str = "Unexpected non-digit character";
            if (i < zaa2) {
                int i5 = i + 1;
                int digit = Character.digit(cArr[i], 10);
                if (digit >= 0) {
                    int i6 = -digit;
                    i = i5;
                    i3 = i6;
                } else {
                    throw new ParseException(str);
                }
            }
            while (i < zaa2) {
                int i7 = i + 1;
                int digit2 = Character.digit(cArr[i], 10);
                if (digit2 >= 0) {
                    String str2 = "Number too large";
                    if (i3 >= -214748364) {
                        int i8 = i3 * 10;
                        if (i8 >= i2 + digit2) {
                            i3 = i8 - digit2;
                            i = i7;
                        } else {
                            throw new ParseException(str2);
                        }
                    } else {
                        throw new ParseException(str2);
                    }
                } else {
                    throw new ParseException(str);
                }
            }
            if (i4 == 0) {
                return -i3;
            }
            if (i > 1) {
                return i3;
            }
            throw new ParseException("No digits to parse");
        }
        throw new ParseException("No number to parse");
    }

    /* access modifiers changed from: private */
    public final long zae(BufferedReader bufferedReader) throws ParseException, IOException {
        long j;
        int zaa2 = zaa(bufferedReader, this.zaqd);
        long j2 = 0;
        if (zaa2 == 0) {
            return 0;
        }
        char[] cArr = this.zaqd;
        if (zaa2 > 0) {
            int i = 0;
            if (cArr[0] == '-') {
                j = Long.MIN_VALUE;
                i = 1;
            } else {
                j = -9223372036854775807L;
            }
            int i2 = i;
            String str = "Unexpected non-digit character";
            int i3 = 10;
            if (i < zaa2) {
                int i4 = i + 1;
                int digit = Character.digit(cArr[i], 10);
                if (digit >= 0) {
                    i = i4;
                    j2 = (long) (-digit);
                } else {
                    throw new ParseException(str);
                }
            }
            while (i < zaa2) {
                int i5 = i + 1;
                int digit2 = Character.digit(cArr[i], i3);
                if (digit2 >= 0) {
                    String str2 = "Number too large";
                    if (j2 >= -922337203685477580L) {
                        long j3 = j2 * 10;
                        int i6 = i5;
                        long j4 = (long) digit2;
                        if (j3 >= j + j4) {
                            j2 = j3 - j4;
                            i = i6;
                            i3 = 10;
                        } else {
                            throw new ParseException(str2);
                        }
                    } else {
                        throw new ParseException(str2);
                    }
                } else {
                    throw new ParseException(str);
                }
            }
            if (i2 == 0) {
                return -j2;
            }
            if (i > 1) {
                return j2;
            }
            throw new ParseException("No digits to parse");
        }
        throw new ParseException("No number to parse");
    }

    /* access modifiers changed from: private */
    public final BigInteger zaf(BufferedReader bufferedReader) throws ParseException, IOException {
        int zaa2 = zaa(bufferedReader, this.zaqd);
        if (zaa2 == 0) {
            return null;
        }
        return new BigInteger(new String(this.zaqd, 0, zaa2));
    }

    /* access modifiers changed from: private */
    public final boolean zaa(BufferedReader bufferedReader, boolean z) throws ParseException, IOException {
        while (true) {
            char zaj = zaj(bufferedReader);
            if (zaj != '\"') {
                if (zaj == 'f') {
                    zab(bufferedReader, z ? zaqk : zaqj);
                    return false;
                } else if (zaj == 'n') {
                    zab(bufferedReader, zaqg);
                    return false;
                } else if (zaj == 't') {
                    zab(bufferedReader, z ? zaqi : zaqh);
                    return true;
                } else {
                    StringBuilder sb = new StringBuilder(19);
                    sb.append("Unexpected token: ");
                    sb.append(zaj);
                    throw new ParseException(sb.toString());
                }
            } else if (!z) {
                z = true;
            } else {
                throw new ParseException("No boolean value found in string");
            }
        }
    }

    /* access modifiers changed from: private */
    public final float zag(BufferedReader bufferedReader) throws ParseException, IOException {
        int zaa2 = zaa(bufferedReader, this.zaqd);
        if (zaa2 == 0) {
            return 0.0f;
        }
        return Float.parseFloat(new String(this.zaqd, 0, zaa2));
    }

    /* access modifiers changed from: private */
    public final double zah(BufferedReader bufferedReader) throws ParseException, IOException {
        int zaa2 = zaa(bufferedReader, this.zaqd);
        if (zaa2 == 0) {
            return 0.0d;
        }
        return Double.parseDouble(new String(this.zaqd, 0, zaa2));
    }

    /* access modifiers changed from: private */
    public final BigDecimal zai(BufferedReader bufferedReader) throws ParseException, IOException {
        int zaa2 = zaa(bufferedReader, this.zaqd);
        if (zaa2 == 0) {
            return null;
        }
        return new BigDecimal(new String(this.zaqd, 0, zaa2));
    }

    private final <T extends FastJsonResponse> ArrayList<T> zaa(BufferedReader bufferedReader, Field<?, ?> field) throws ParseException, IOException {
        String str = "Error instantiating inner object";
        ArrayList<T> arrayList = new ArrayList<>();
        char zaj = zaj(bufferedReader);
        if (zaj == ']') {
            zak(5);
            return arrayList;
        } else if (zaj != 'n') {
            String str2 = "Unexpected token: ";
            if (zaj == '{') {
                this.zaqm.push(Integer.valueOf(1));
                while (true) {
                    try {
                        FastJsonResponse zacp = field.zacp();
                        if (!zaa(bufferedReader, zacp)) {
                            return arrayList;
                        }
                        arrayList.add(zacp);
                        char zaj2 = zaj(bufferedReader);
                        if (zaj2 != ',') {
                            if (zaj2 == ']') {
                                zak(5);
                                return arrayList;
                            }
                            StringBuilder sb = new StringBuilder(19);
                            sb.append(str2);
                            sb.append(zaj2);
                            throw new ParseException(sb.toString());
                        } else if (zaj(bufferedReader) == '{') {
                            this.zaqm.push(Integer.valueOf(1));
                        } else {
                            throw new ParseException("Expected start of next object in array");
                        }
                    } catch (InstantiationException e) {
                        throw new ParseException(str, e);
                    } catch (IllegalAccessException e2) {
                        throw new ParseException(str, e2);
                    }
                }
            } else {
                StringBuilder sb2 = new StringBuilder(19);
                sb2.append(str2);
                sb2.append(zaj);
                throw new ParseException(sb2.toString());
            }
        } else {
            zab(bufferedReader, zaqg);
            zak(5);
            return null;
        }
    }

    private final char zaj(BufferedReader bufferedReader) throws ParseException, IOException {
        if (bufferedReader.read(this.zaqb) == -1) {
            return 0;
        }
        while (Character.isWhitespace(this.zaqb[0])) {
            if (bufferedReader.read(this.zaqb) == -1) {
                return 0;
            }
        }
        return this.zaqb[0];
    }

    private final int zaa(BufferedReader bufferedReader, char[] cArr) throws ParseException, IOException {
        int i;
        char zaj = zaj(bufferedReader);
        String str = "Unexpected EOF";
        if (zaj == 0) {
            throw new ParseException(str);
        } else if (zaj == ',') {
            throw new ParseException("Missing value");
        } else if (zaj == 'n') {
            zab(bufferedReader, zaqg);
            return 0;
        } else {
            bufferedReader.mark(1024);
            if (zaj == '\"') {
                i = 0;
                boolean z = false;
                while (i < cArr.length && bufferedReader.read(cArr, i, 1) != -1) {
                    char c = cArr[i];
                    if (Character.isISOControl(c)) {
                        throw new ParseException("Unexpected control character while reading string");
                    } else if (c != '\"' || z) {
                        z = c == '\\' ? !z : false;
                        i++;
                    } else {
                        bufferedReader.reset();
                        bufferedReader.skip((long) (i + 1));
                        return i;
                    }
                }
            } else {
                cArr[0] = zaj;
                int i2 = 1;
                while (i < cArr.length && bufferedReader.read(cArr, i, 1) != -1) {
                    if (cArr[i] == '}' || cArr[i] == ',' || Character.isWhitespace(cArr[i]) || cArr[i] == ']') {
                        bufferedReader.reset();
                        bufferedReader.skip((long) (i - 1));
                        cArr[i] = 0;
                        return i;
                    }
                    i2 = i + 1;
                }
            }
            if (i == cArr.length) {
                throw new ParseException("Absurdly long value");
            }
            throw new ParseException(str);
        }
    }

    private final void zab(BufferedReader bufferedReader, char[] cArr) throws ParseException, IOException {
        int i = 0;
        while (i < cArr.length) {
            int read = bufferedReader.read(this.zaqc, 0, cArr.length - i);
            if (read != -1) {
                int i2 = 0;
                while (i2 < read) {
                    if (cArr[i2 + i] == this.zaqc[i2]) {
                        i2++;
                    } else {
                        throw new ParseException("Unexpected character");
                    }
                }
                i += read;
            } else {
                throw new ParseException("Unexpected EOF");
            }
        }
    }

    private final void zak(int i) throws ParseException {
        String str = "Expected state ";
        if (!this.zaqm.isEmpty()) {
            int intValue = ((Integer) this.zaqm.pop()).intValue();
            if (intValue != i) {
                StringBuilder sb = new StringBuilder(46);
                sb.append(str);
                sb.append(i);
                sb.append(" but had ");
                sb.append(intValue);
                throw new ParseException(sb.toString());
            }
            return;
        }
        StringBuilder sb2 = new StringBuilder(46);
        sb2.append(str);
        sb2.append(i);
        sb2.append(" but had empty stack");
        throw new ParseException(sb2.toString());
    }
}
