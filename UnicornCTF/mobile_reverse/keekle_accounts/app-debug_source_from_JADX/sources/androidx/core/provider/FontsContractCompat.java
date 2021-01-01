package androidx.core.provider;

import android.content.ContentUris;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ProviderInfo;
import android.content.pm.Signature;
import android.content.res.Resources;
import android.database.Cursor;
import android.graphics.Typeface;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.Build.VERSION;
import android.os.CancellationSignal;
import android.os.Handler;
import android.provider.BaseColumns;
import androidx.collection.LruCache;
import androidx.collection.SimpleArrayMap;
import androidx.core.content.res.FontResourcesParserCompat;
import androidx.core.graphics.TypefaceCompat;
import androidx.core.graphics.TypefaceCompatUtil;
import androidx.core.provider.SelfDestructiveThread.ReplyCallback;
import androidx.core.util.Preconditions;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FontsContractCompat {
    private static final int BACKGROUND_THREAD_KEEP_ALIVE_DURATION_MS = 10000;
    public static final String PARCEL_FONT_RESULTS = "font_results";
    static final int RESULT_CODE_PROVIDER_NOT_FOUND = -1;
    static final int RESULT_CODE_WRONG_CERTIFICATES = -2;
    private static final SelfDestructiveThread sBackgroundThread = new SelfDestructiveThread("fonts", 10, BACKGROUND_THREAD_KEEP_ALIVE_DURATION_MS);
    private static final Comparator<byte[]> sByteArrayComparator = new Comparator<byte[]>() {
        public int compare(byte[] l, byte[] r) {
            if (l.length != r.length) {
                return l.length - r.length;
            }
            for (int i = 0; i < l.length; i++) {
                if (l[i] != r[i]) {
                    return l[i] - r[i];
                }
            }
            return 0;
        }
    };
    static final Object sLock = new Object();
    static final SimpleArrayMap<String, ArrayList<ReplyCallback<TypefaceResult>>> sPendingReplies = new SimpleArrayMap<>();
    static final LruCache<String, Typeface> sTypefaceCache = new LruCache<>(16);

    public static final class Columns implements BaseColumns {
        public static final String FILE_ID = "file_id";
        public static final String ITALIC = "font_italic";
        public static final String RESULT_CODE = "result_code";
        public static final int RESULT_CODE_FONT_NOT_FOUND = 1;
        public static final int RESULT_CODE_FONT_UNAVAILABLE = 2;
        public static final int RESULT_CODE_MALFORMED_QUERY = 3;
        public static final int RESULT_CODE_OK = 0;
        public static final String TTC_INDEX = "font_ttc_index";
        public static final String VARIATION_SETTINGS = "font_variation_settings";
        public static final String WEIGHT = "font_weight";
    }

    public static class FontFamilyResult {
        public static final int STATUS_OK = 0;
        public static final int STATUS_UNEXPECTED_DATA_PROVIDED = 2;
        public static final int STATUS_WRONG_CERTIFICATES = 1;
        private final FontInfo[] mFonts;
        private final int mStatusCode;

        public FontFamilyResult(int statusCode, FontInfo[] fonts) {
            this.mStatusCode = statusCode;
            this.mFonts = fonts;
        }

        public int getStatusCode() {
            return this.mStatusCode;
        }

        public FontInfo[] getFonts() {
            return this.mFonts;
        }
    }

    public static class FontInfo {
        private final boolean mItalic;
        private final int mResultCode;
        private final int mTtcIndex;
        private final Uri mUri;
        private final int mWeight;

        public FontInfo(Uri uri, int ttcIndex, int weight, boolean italic, int resultCode) {
            this.mUri = (Uri) Preconditions.checkNotNull(uri);
            this.mTtcIndex = ttcIndex;
            this.mWeight = weight;
            this.mItalic = italic;
            this.mResultCode = resultCode;
        }

        public Uri getUri() {
            return this.mUri;
        }

        public int getTtcIndex() {
            return this.mTtcIndex;
        }

        public int getWeight() {
            return this.mWeight;
        }

        public boolean isItalic() {
            return this.mItalic;
        }

        public int getResultCode() {
            return this.mResultCode;
        }
    }

    public static class FontRequestCallback {
        public static final int FAIL_REASON_FONT_LOAD_ERROR = -3;
        public static final int FAIL_REASON_FONT_NOT_FOUND = 1;
        public static final int FAIL_REASON_FONT_UNAVAILABLE = 2;
        public static final int FAIL_REASON_MALFORMED_QUERY = 3;
        public static final int FAIL_REASON_PROVIDER_NOT_FOUND = -1;
        public static final int FAIL_REASON_SECURITY_VIOLATION = -4;
        public static final int FAIL_REASON_WRONG_CERTIFICATES = -2;
        public static final int RESULT_OK = 0;

        @Retention(RetentionPolicy.SOURCE)
        public @interface FontRequestFailReason {
        }

        public void onTypefaceRetrieved(Typeface typeface) {
        }

        public void onTypefaceRequestFailed(int reason) {
        }
    }

    private static final class TypefaceResult {
        final int mResult;
        final Typeface mTypeface;

        TypefaceResult(Typeface typeface, int result) {
            this.mTypeface = typeface;
            this.mResult = result;
        }
    }

    private FontsContractCompat() {
    }

    static TypefaceResult getFontInternal(Context context, FontRequest request, int style) {
        try {
            FontFamilyResult result = fetchFonts(context, null, request);
            int i = -3;
            if (result.getStatusCode() == 0) {
                Typeface typeface = TypefaceCompat.createFromFontInfo(context, null, result.getFonts(), style);
                if (typeface != null) {
                    i = 0;
                }
                return new TypefaceResult(typeface, i);
            }
            if (result.getStatusCode() == 1) {
                i = -2;
            }
            return new TypefaceResult(null, i);
        } catch (NameNotFoundException e) {
            return new TypefaceResult(null, -1);
        }
    }

    public static void resetCache() {
        sTypefaceCache.evictAll();
    }

    /* JADX WARNING: Code restructure failed: missing block: B:34:0x0076, code lost:
        return r3;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:38:0x0088, code lost:
        sBackgroundThread.postAndReply(r2, new androidx.core.provider.FontsContractCompat.C02163());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x0092, code lost:
        return r3;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static android.graphics.Typeface getFontSync(final android.content.Context r8, final androidx.core.provider.FontRequest r9, final androidx.core.content.res.ResourcesCompat.FontCallback r10, final android.os.Handler r11, boolean r12, int r13, final int r14) {
        /*
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r1 = r9.getIdentifier()
            r0.append(r1)
            java.lang.String r1 = "-"
            r0.append(r1)
            r0.append(r14)
            java.lang.String r0 = r0.toString()
            androidx.collection.LruCache<java.lang.String, android.graphics.Typeface> r1 = sTypefaceCache
            java.lang.Object r1 = r1.get(r0)
            android.graphics.Typeface r1 = (android.graphics.Typeface) r1
            if (r1 == 0) goto L_0x0028
            if (r10 == 0) goto L_0x0027
            r10.onFontRetrieved(r1)
        L_0x0027:
            return r1
        L_0x0028:
            if (r12 == 0) goto L_0x0045
            r2 = -1
            if (r13 != r2) goto L_0x0045
            androidx.core.provider.FontsContractCompat$TypefaceResult r2 = getFontInternal(r8, r9, r14)
            if (r10 == 0) goto L_0x0042
            int r3 = r2.mResult
            if (r3 != 0) goto L_0x003d
            android.graphics.Typeface r3 = r2.mTypeface
            r10.callbackSuccessAsync(r3, r11)
            goto L_0x0042
        L_0x003d:
            int r3 = r2.mResult
            r10.callbackFailAsync(r3, r11)
        L_0x0042:
            android.graphics.Typeface r3 = r2.mTypeface
            return r3
        L_0x0045:
            androidx.core.provider.FontsContractCompat$1 r2 = new androidx.core.provider.FontsContractCompat$1
            r2.<init>(r8, r9, r14, r0)
            r3 = 0
            if (r12 == 0) goto L_0x005a
            androidx.core.provider.SelfDestructiveThread r4 = sBackgroundThread     // Catch:{ InterruptedException -> 0x0058 }
            java.lang.Object r4 = r4.postAndWait(r2, r13)     // Catch:{ InterruptedException -> 0x0058 }
            androidx.core.provider.FontsContractCompat$TypefaceResult r4 = (androidx.core.provider.FontsContractCompat.TypefaceResult) r4     // Catch:{ InterruptedException -> 0x0058 }
            android.graphics.Typeface r3 = r4.mTypeface     // Catch:{ InterruptedException -> 0x0058 }
            return r3
        L_0x0058:
            r4 = move-exception
            return r3
        L_0x005a:
            if (r10 != 0) goto L_0x005e
            r4 = r3
            goto L_0x0063
        L_0x005e:
            androidx.core.provider.FontsContractCompat$2 r4 = new androidx.core.provider.FontsContractCompat$2
            r4.<init>(r10, r11)
        L_0x0063:
            java.lang.Object r5 = sLock
            monitor-enter(r5)
            androidx.collection.SimpleArrayMap<java.lang.String, java.util.ArrayList<androidx.core.provider.SelfDestructiveThread$ReplyCallback<androidx.core.provider.FontsContractCompat$TypefaceResult>>> r6 = sPendingReplies     // Catch:{ all -> 0x0093 }
            java.lang.Object r6 = r6.get(r0)     // Catch:{ all -> 0x0093 }
            java.util.ArrayList r6 = (java.util.ArrayList) r6     // Catch:{ all -> 0x0093 }
            if (r6 == 0) goto L_0x0077
            if (r4 == 0) goto L_0x0075
            r6.add(r4)     // Catch:{ all -> 0x0093 }
        L_0x0075:
            monitor-exit(r5)     // Catch:{ all -> 0x0093 }
            return r3
        L_0x0077:
            if (r4 == 0) goto L_0x0087
            java.util.ArrayList r7 = new java.util.ArrayList     // Catch:{ all -> 0x0093 }
            r7.<init>()     // Catch:{ all -> 0x0093 }
            r6 = r7
            r6.add(r4)     // Catch:{ all -> 0x0093 }
            androidx.collection.SimpleArrayMap<java.lang.String, java.util.ArrayList<androidx.core.provider.SelfDestructiveThread$ReplyCallback<androidx.core.provider.FontsContractCompat$TypefaceResult>>> r7 = sPendingReplies     // Catch:{ all -> 0x0093 }
            r7.put(r0, r6)     // Catch:{ all -> 0x0093 }
        L_0x0087:
            monitor-exit(r5)     // Catch:{ all -> 0x0093 }
            androidx.core.provider.SelfDestructiveThread r5 = sBackgroundThread
            androidx.core.provider.FontsContractCompat$3 r6 = new androidx.core.provider.FontsContractCompat$3
            r6.<init>(r0)
            r5.postAndReply(r2, r6)
            return r3
        L_0x0093:
            r3 = move-exception
            monitor-exit(r5)     // Catch:{ all -> 0x0093 }
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.provider.FontsContractCompat.getFontSync(android.content.Context, androidx.core.provider.FontRequest, androidx.core.content.res.ResourcesCompat$FontCallback, android.os.Handler, boolean, int, int):android.graphics.Typeface");
    }

    public static void requestFont(Context context, FontRequest request, FontRequestCallback callback, Handler handler) {
        requestFontInternal(context.getApplicationContext(), request, callback, handler);
    }

    private static void requestFontInternal(final Context appContext, final FontRequest request, final FontRequestCallback callback, Handler handler) {
        final Handler callerThreadHandler = new Handler();
        handler.post(new Runnable() {
            public void run() {
                try {
                    FontFamilyResult result = FontsContractCompat.fetchFonts(appContext, null, request);
                    if (result.getStatusCode() != 0) {
                        int statusCode = result.getStatusCode();
                        if (statusCode == 1) {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRequestFailed(-2);
                                }
                            });
                        } else if (statusCode != 2) {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRequestFailed(-3);
                                }
                            });
                        } else {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRequestFailed(-3);
                                }
                            });
                        }
                    } else {
                        FontInfo[] fonts = result.getFonts();
                        if (fonts == null || fonts.length == 0) {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRequestFailed(1);
                                }
                            });
                            return;
                        }
                        for (FontInfo font : fonts) {
                            if (font.getResultCode() != 0) {
                                final int resultCode = font.getResultCode();
                                if (resultCode < 0) {
                                    callerThreadHandler.post(new Runnable() {
                                        public void run() {
                                            callback.onTypefaceRequestFailed(-3);
                                        }
                                    });
                                } else {
                                    callerThreadHandler.post(new Runnable() {
                                        public void run() {
                                            callback.onTypefaceRequestFailed(resultCode);
                                        }
                                    });
                                }
                                return;
                            }
                        }
                        final Typeface typeface = FontsContractCompat.buildTypeface(appContext, null, fonts);
                        if (typeface == null) {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRequestFailed(-3);
                                }
                            });
                        } else {
                            callerThreadHandler.post(new Runnable() {
                                public void run() {
                                    callback.onTypefaceRetrieved(typeface);
                                }
                            });
                        }
                    }
                } catch (NameNotFoundException e) {
                    callerThreadHandler.post(new Runnable() {
                        public void run() {
                            callback.onTypefaceRequestFailed(-1);
                        }
                    });
                }
            }
        });
    }

    public static Typeface buildTypeface(Context context, CancellationSignal cancellationSignal, FontInfo[] fonts) {
        return TypefaceCompat.createFromFontInfo(context, cancellationSignal, fonts, 0);
    }

    public static Map<Uri, ByteBuffer> prepareFontData(Context context, FontInfo[] fonts, CancellationSignal cancellationSignal) {
        HashMap<Uri, ByteBuffer> out = new HashMap<>();
        for (FontInfo font : fonts) {
            if (font.getResultCode() == 0) {
                Uri uri = font.getUri();
                if (!out.containsKey(uri)) {
                    out.put(uri, TypefaceCompatUtil.mmap(context, cancellationSignal, uri));
                }
            }
        }
        return Collections.unmodifiableMap(out);
    }

    public static FontFamilyResult fetchFonts(Context context, CancellationSignal cancellationSignal, FontRequest request) throws NameNotFoundException {
        ProviderInfo providerInfo = getProvider(context.getPackageManager(), request, context.getResources());
        if (providerInfo == null) {
            return new FontFamilyResult(1, null);
        }
        return new FontFamilyResult(0, getFontFromProvider(context, request, providerInfo.authority, cancellationSignal));
    }

    public static ProviderInfo getProvider(PackageManager packageManager, FontRequest request, Resources resources) throws NameNotFoundException {
        String providerAuthority = request.getProviderAuthority();
        ProviderInfo info = packageManager.resolveContentProvider(providerAuthority, 0);
        if (info == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("No package found for authority: ");
            sb.append(providerAuthority);
            throw new NameNotFoundException(sb.toString());
        } else if (info.packageName.equals(request.getProviderPackage())) {
            List<byte[]> signatures = convertToByteArrayList(packageManager.getPackageInfo(info.packageName, 64).signatures);
            Collections.sort(signatures, sByteArrayComparator);
            List<List<byte[]>> requestCertificatesList = getCertificates(request, resources);
            for (int i = 0; i < requestCertificatesList.size(); i++) {
                List<byte[]> requestSignatures = new ArrayList<>((Collection) requestCertificatesList.get(i));
                Collections.sort(requestSignatures, sByteArrayComparator);
                if (equalsByteArrayList(signatures, requestSignatures)) {
                    return info;
                }
            }
            return null;
        } else {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Found content provider ");
            sb2.append(providerAuthority);
            sb2.append(", but package was not ");
            sb2.append(request.getProviderPackage());
            throw new NameNotFoundException(sb2.toString());
        }
    }

    private static List<List<byte[]>> getCertificates(FontRequest request, Resources resources) {
        if (request.getCertificates() != null) {
            return request.getCertificates();
        }
        return FontResourcesParserCompat.readCerts(resources, request.getCertificatesArrayResId());
    }

    private static boolean equalsByteArrayList(List<byte[]> signatures, List<byte[]> requestSignatures) {
        if (signatures.size() != requestSignatures.size()) {
            return false;
        }
        for (int i = 0; i < signatures.size(); i++) {
            if (!Arrays.equals((byte[]) signatures.get(i), (byte[]) requestSignatures.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static List<byte[]> convertToByteArrayList(Signature[] signatures) {
        List<byte[]> shas = new ArrayList<>();
        for (Signature byteArray : signatures) {
            shas.add(byteArray.toByteArray());
        }
        return shas;
    }

    /* JADX INFO: finally extract failed */
    static FontInfo[] getFontFromProvider(Context context, FontRequest request, String authority, CancellationSignal cancellationSignal) {
        Cursor cursor;
        Uri fileUri;
        String str = authority;
        ArrayList arrayList = new ArrayList();
        String str2 = "content";
        Uri uri = new Builder().scheme(str2).authority(str).build();
        Uri fileBaseUri = new Builder().scheme(str2).authority(str).appendPath("file").build();
        Cursor cursor2 = null;
        try {
            int i = 0;
            if (VERSION.SDK_INT > 16) {
                cursor = context.getContentResolver().query(uri, new String[]{"_id", Columns.FILE_ID, Columns.TTC_INDEX, Columns.VARIATION_SETTINGS, Columns.WEIGHT, Columns.ITALIC, Columns.RESULT_CODE}, "query = ?", new String[]{request.getQuery()}, null, cancellationSignal);
            } else {
                cursor = context.getContentResolver().query(uri, new String[]{"_id", Columns.FILE_ID, Columns.TTC_INDEX, Columns.VARIATION_SETTINGS, Columns.WEIGHT, Columns.ITALIC, Columns.RESULT_CODE}, "query = ?", new String[]{request.getQuery()}, null);
            }
            if (cursor != null && cursor.getCount() > 0) {
                int resultCodeColumnIndex = cursor.getColumnIndex(Columns.RESULT_CODE);
                arrayList = new ArrayList();
                int idColumnIndex = cursor.getColumnIndex("_id");
                int fileIdColumnIndex = cursor.getColumnIndex(Columns.FILE_ID);
                int ttcIndexColumnIndex = cursor.getColumnIndex(Columns.TTC_INDEX);
                int weightColumnIndex = cursor.getColumnIndex(Columns.WEIGHT);
                int italicColumnIndex = cursor.getColumnIndex(Columns.ITALIC);
                while (cursor.moveToNext()) {
                    int resultCode = resultCodeColumnIndex != -1 ? cursor.getInt(resultCodeColumnIndex) : i;
                    int ttcIndex = ttcIndexColumnIndex != -1 ? cursor.getInt(ttcIndexColumnIndex) : i;
                    if (fileIdColumnIndex == -1) {
                        fileUri = ContentUris.withAppendedId(uri, cursor.getLong(idColumnIndex));
                    } else {
                        fileUri = ContentUris.withAppendedId(fileBaseUri, cursor.getLong(fileIdColumnIndex));
                    }
                    FontInfo fontInfo = new FontInfo(fileUri, ttcIndex, weightColumnIndex != -1 ? cursor.getInt(weightColumnIndex) : 400, italicColumnIndex != -1 && cursor.getInt(italicColumnIndex) == 1, resultCode);
                    arrayList.add(fontInfo);
                    i = 0;
                }
            }
            if (cursor != null) {
                cursor.close();
            }
            return (FontInfo[]) arrayList.toArray(new FontInfo[0]);
        } catch (Throwable th) {
            if (cursor2 != null) {
                cursor2.close();
            }
            throw th;
        }
    }
}
