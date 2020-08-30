package androidx.core.content.res;

import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.util.Base64;
import android.util.TypedValue;
import android.util.Xml;
import androidx.core.C0020R;
import androidx.core.provider.FontRequest;
import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class FontResourcesParserCompat {
    private static final int DEFAULT_TIMEOUT_MILLIS = 500;
    public static final int FETCH_STRATEGY_ASYNC = 1;
    public static final int FETCH_STRATEGY_BLOCKING = 0;
    public static final int INFINITE_TIMEOUT_VALUE = -1;
    private static final int ITALIC = 1;
    private static final int NORMAL_WEIGHT = 400;

    public interface FamilyResourceEntry {
    }

    @Retention(RetentionPolicy.SOURCE)
    public @interface FetchStrategy {
    }

    public static final class FontFamilyFilesResourceEntry implements FamilyResourceEntry {
        private final FontFileResourceEntry[] mEntries;

        public FontFamilyFilesResourceEntry(FontFileResourceEntry[] entries) {
            this.mEntries = entries;
        }

        public FontFileResourceEntry[] getEntries() {
            return this.mEntries;
        }
    }

    public static final class FontFileResourceEntry {
        private final String mFileName;
        private boolean mItalic;
        private int mResourceId;
        private int mTtcIndex;
        private String mVariationSettings;
        private int mWeight;

        public FontFileResourceEntry(String fileName, int weight, boolean italic, String variationSettings, int ttcIndex, int resourceId) {
            this.mFileName = fileName;
            this.mWeight = weight;
            this.mItalic = italic;
            this.mVariationSettings = variationSettings;
            this.mTtcIndex = ttcIndex;
            this.mResourceId = resourceId;
        }

        public String getFileName() {
            return this.mFileName;
        }

        public int getWeight() {
            return this.mWeight;
        }

        public boolean isItalic() {
            return this.mItalic;
        }

        public String getVariationSettings() {
            return this.mVariationSettings;
        }

        public int getTtcIndex() {
            return this.mTtcIndex;
        }

        public int getResourceId() {
            return this.mResourceId;
        }
    }

    public static final class ProviderResourceEntry implements FamilyResourceEntry {
        private final FontRequest mRequest;
        private final int mStrategy;
        private final int mTimeoutMs;

        public ProviderResourceEntry(FontRequest request, int strategy, int timeoutMs) {
            this.mRequest = request;
            this.mStrategy = strategy;
            this.mTimeoutMs = timeoutMs;
        }

        public FontRequest getRequest() {
            return this.mRequest;
        }

        public int getFetchStrategy() {
            return this.mStrategy;
        }

        public int getTimeout() {
            return this.mTimeoutMs;
        }
    }

    public static FamilyResourceEntry parse(XmlPullParser parser, Resources resources) throws XmlPullParserException, IOException {
        int type;
        do {
            int next = parser.next();
            type = next;
            if (next == 2) {
                break;
            }
        } while (type != 1);
        if (type == 2) {
            return readFamilies(parser, resources);
        }
        throw new XmlPullParserException("No start tag found");
    }

    private static FamilyResourceEntry readFamilies(XmlPullParser parser, Resources resources) throws XmlPullParserException, IOException {
        String str = "font-family";
        parser.require(2, null, str);
        if (parser.getName().equals(str)) {
            return readFamily(parser, resources);
        }
        skip(parser);
        return null;
    }

    private static FamilyResourceEntry readFamily(XmlPullParser parser, Resources resources) throws XmlPullParserException, IOException {
        TypedArray array = resources.obtainAttributes(Xml.asAttributeSet(parser), C0020R.styleable.FontFamily);
        String authority = array.getString(C0020R.styleable.FontFamily_fontProviderAuthority);
        String providerPackage = array.getString(C0020R.styleable.FontFamily_fontProviderPackage);
        String query = array.getString(C0020R.styleable.FontFamily_fontProviderQuery);
        int certsId = array.getResourceId(C0020R.styleable.FontFamily_fontProviderCerts, 0);
        int strategy = array.getInteger(C0020R.styleable.FontFamily_fontProviderFetchStrategy, 1);
        int timeoutMs = array.getInteger(C0020R.styleable.FontFamily_fontProviderFetchTimeout, DEFAULT_TIMEOUT_MILLIS);
        array.recycle();
        if (authority == null || providerPackage == null || query == null) {
            List<FontFileResourceEntry> fonts = new ArrayList<>();
            while (parser.next() != 3) {
                if (parser.getEventType() == 2) {
                    if (parser.getName().equals("font")) {
                        fonts.add(readFont(parser, resources));
                    } else {
                        skip(parser);
                    }
                }
            }
            if (fonts.isEmpty()) {
                return null;
            }
            return new FontFamilyFilesResourceEntry((FontFileResourceEntry[]) fonts.toArray(new FontFileResourceEntry[fonts.size()]));
        }
        while (parser.next() != 3) {
            skip(parser);
        }
        return new ProviderResourceEntry(new FontRequest(authority, providerPackage, query, readCerts(resources, certsId)), strategy, timeoutMs);
    }

    private static int getType(TypedArray typedArray, int index) {
        if (VERSION.SDK_INT >= 21) {
            return typedArray.getType(index);
        }
        TypedValue tv = new TypedValue();
        typedArray.getValue(index, tv);
        return tv.type;
    }

    public static List<List<byte[]>> readCerts(Resources resources, int certsId) {
        if (certsId == 0) {
            return Collections.emptyList();
        }
        TypedArray typedArray = resources.obtainTypedArray(certsId);
        try {
            if (typedArray.length() == 0) {
                return Collections.emptyList();
            }
            List<List<byte[]>> result = new ArrayList<>();
            if (getType(typedArray, 0) == 1) {
                for (int i = 0; i < typedArray.length(); i++) {
                    int certId = typedArray.getResourceId(i, 0);
                    if (certId != 0) {
                        result.add(toByteArrayList(resources.getStringArray(certId)));
                    }
                }
            } else {
                result.add(toByteArrayList(resources.getStringArray(certsId)));
            }
            typedArray.recycle();
            return result;
        } finally {
            typedArray.recycle();
        }
    }

    private static List<byte[]> toByteArrayList(String[] stringArray) {
        List<byte[]> result = new ArrayList<>();
        for (String item : stringArray) {
            result.add(Base64.decode(item, 0));
        }
        return result;
    }

    private static FontFileResourceEntry readFont(XmlPullParser parser, Resources resources) throws XmlPullParserException, IOException {
        TypedArray array = resources.obtainAttributes(Xml.asAttributeSet(parser), C0020R.styleable.FontFamilyFont);
        int weight = array.getInt(array.hasValue(C0020R.styleable.FontFamilyFont_fontWeight) ? C0020R.styleable.FontFamilyFont_fontWeight : C0020R.styleable.FontFamilyFont_android_fontWeight, NORMAL_WEIGHT);
        boolean isItalic = 1 == array.getInt(array.hasValue(C0020R.styleable.FontFamilyFont_fontStyle) ? C0020R.styleable.FontFamilyFont_fontStyle : C0020R.styleable.FontFamilyFont_android_fontStyle, 0);
        int ttcIndexAttr = array.hasValue(C0020R.styleable.FontFamilyFont_ttcIndex) ? C0020R.styleable.FontFamilyFont_ttcIndex : C0020R.styleable.FontFamilyFont_android_ttcIndex;
        String variationSettings = array.getString(array.hasValue(C0020R.styleable.FontFamilyFont_fontVariationSettings) ? C0020R.styleable.FontFamilyFont_fontVariationSettings : C0020R.styleable.FontFamilyFont_android_fontVariationSettings);
        int ttcIndex = array.getInt(ttcIndexAttr, 0);
        int resourceAttr = array.hasValue(C0020R.styleable.FontFamilyFont_font) ? C0020R.styleable.FontFamilyFont_font : C0020R.styleable.FontFamilyFont_android_font;
        int resourceId = array.getResourceId(resourceAttr, 0);
        String filename = array.getString(resourceAttr);
        array.recycle();
        while (parser.next() != 3) {
            skip(parser);
        }
        int i = resourceAttr;
        FontFileResourceEntry fontFileResourceEntry = new FontFileResourceEntry(filename, weight, isItalic, variationSettings, ttcIndex, resourceId);
        return fontFileResourceEntry;
    }

    private static void skip(XmlPullParser parser) throws XmlPullParserException, IOException {
        int depth = 1;
        while (depth > 0) {
            int next = parser.next();
            if (next == 2) {
                depth++;
            } else if (next == 3) {
                depth--;
            }
        }
    }

    private FontResourcesParserCompat() {
    }
}
