package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.os.Build.VERSION;
import android.os.CancellationSignal;
import android.os.Handler;
import androidx.collection.LruCache;
import androidx.core.content.res.FontResourcesParserCompat.FamilyResourceEntry;
import androidx.core.content.res.FontResourcesParserCompat.FontFamilyFilesResourceEntry;
import androidx.core.content.res.FontResourcesParserCompat.ProviderResourceEntry;
import androidx.core.content.res.ResourcesCompat.FontCallback;
import androidx.core.provider.FontsContractCompat;
import androidx.core.provider.FontsContractCompat.FontInfo;

public class TypefaceCompat {
    private static final LruCache<String, Typeface> sTypefaceCache = new LruCache<>(16);
    private static final TypefaceCompatBaseImpl sTypefaceCompatImpl;

    static {
        if (VERSION.SDK_INT >= 28) {
            sTypefaceCompatImpl = new TypefaceCompatApi28Impl();
        } else if (VERSION.SDK_INT >= 26) {
            sTypefaceCompatImpl = new TypefaceCompatApi26Impl();
        } else if (VERSION.SDK_INT >= 24 && TypefaceCompatApi24Impl.isUsable()) {
            sTypefaceCompatImpl = new TypefaceCompatApi24Impl();
        } else if (VERSION.SDK_INT >= 21) {
            sTypefaceCompatImpl = new TypefaceCompatApi21Impl();
        } else {
            sTypefaceCompatImpl = new TypefaceCompatBaseImpl();
        }
    }

    private TypefaceCompat() {
    }

    public static Typeface findFromCache(Resources resources, int id, int style) {
        return (Typeface) sTypefaceCache.get(createResourceUid(resources, id, style));
    }

    private static String createResourceUid(Resources resources, int id, int style) {
        StringBuilder sb = new StringBuilder();
        sb.append(resources.getResourcePackageName(id));
        String str = "-";
        sb.append(str);
        sb.append(id);
        sb.append(str);
        sb.append(style);
        return sb.toString();
    }

    public static Typeface createFromResourcesFamilyXml(Context context, FamilyResourceEntry entry, Resources resources, int id, int style, FontCallback fontCallback, Handler handler, boolean isRequestFromLayoutInflator) {
        Typeface typeface;
        FamilyResourceEntry familyResourceEntry = entry;
        FontCallback fontCallback2 = fontCallback;
        Handler handler2 = handler;
        if (familyResourceEntry instanceof ProviderResourceEntry) {
            ProviderResourceEntry providerEntry = (ProviderResourceEntry) familyResourceEntry;
            typeface = FontsContractCompat.getFontSync(context, providerEntry.getRequest(), fontCallback, handler, !isRequestFromLayoutInflator ? fontCallback2 == null : providerEntry.getFetchStrategy() == 0, isRequestFromLayoutInflator ? providerEntry.getTimeout() : -1, style);
            Context context2 = context;
            Resources resources2 = resources;
            int i = style;
        } else {
            Context context3 = context;
            Resources resources3 = resources;
            int i2 = style;
            typeface = sTypefaceCompatImpl.createFromFontFamilyFilesResourceEntry(context, (FontFamilyFilesResourceEntry) familyResourceEntry, resources, style);
            if (fontCallback2 != null) {
                if (typeface != null) {
                    fontCallback2.callbackSuccessAsync(typeface, handler2);
                } else {
                    fontCallback2.callbackFailAsync(-3, handler2);
                }
            }
        }
        if (typeface != null) {
            sTypefaceCache.put(createResourceUid(resources, id, style), typeface);
        }
        return typeface;
    }

    public static Typeface createFromResourcesFontFile(Context context, Resources resources, int id, String path, int style) {
        Typeface typeface = sTypefaceCompatImpl.createFromResourcesFontFile(context, resources, id, path, style);
        if (typeface != null) {
            sTypefaceCache.put(createResourceUid(resources, id, style), typeface);
        }
        return typeface;
    }

    public static Typeface createFromFontInfo(Context context, CancellationSignal cancellationSignal, FontInfo[] fonts, int style) {
        return sTypefaceCompatImpl.createFromFontInfo(context, cancellationSignal, fonts, style);
    }

    private static Typeface getBestFontFromFamily(Context context, Typeface typeface, int style) {
        FontFamilyFilesResourceEntry families = sTypefaceCompatImpl.getFontFamily(typeface);
        if (families == null) {
            return null;
        }
        return sTypefaceCompatImpl.createFromFontFamilyFilesResourceEntry(context, families, context.getResources(), style);
    }

    public static Typeface create(Context context, Typeface family, int style) {
        if (context != null) {
            if (VERSION.SDK_INT < 21) {
                Typeface typefaceFromFamily = getBestFontFromFamily(context, family, style);
                if (typefaceFromFamily != null) {
                    return typefaceFromFamily;
                }
            }
            return Typeface.create(family, style);
        }
        throw new IllegalArgumentException("Context cannot be null");
    }
}
