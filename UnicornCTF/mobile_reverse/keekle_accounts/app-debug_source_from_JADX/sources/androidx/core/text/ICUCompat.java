package androidx.core.text;

import android.icu.util.ULocale;
import android.os.Build.VERSION;
import android.util.Log;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Locale;

public final class ICUCompat {
    private static final String TAG = "ICUCompat";
    private static Method sAddLikelySubtagsMethod;
    private static Method sGetScriptMethod;

    static {
        String str = "addLikelySubtags";
        String str2 = "libcore.icu.ICU";
        if (VERSION.SDK_INT < 21) {
            try {
                Class<?> clazz = Class.forName(str2);
                if (clazz != null) {
                    sGetScriptMethod = clazz.getMethod("getScript", new Class[]{String.class});
                    sAddLikelySubtagsMethod = clazz.getMethod(str, new Class[]{String.class});
                }
            } catch (Exception e) {
                sGetScriptMethod = null;
                sAddLikelySubtagsMethod = null;
                Log.w(TAG, e);
            }
        } else if (VERSION.SDK_INT < 24) {
            try {
                sAddLikelySubtagsMethod = Class.forName(str2).getMethod(str, new Class[]{Locale.class});
            } catch (Exception e2) {
                throw new IllegalStateException(e2);
            }
        }
    }

    public static String maximizeAndGetScript(Locale locale) {
        String str = TAG;
        if (VERSION.SDK_INT >= 24) {
            return ULocale.addLikelySubtags(ULocale.forLocale(locale)).getScript();
        }
        if (VERSION.SDK_INT >= 21) {
            try {
                return ((Locale) sAddLikelySubtagsMethod.invoke(null, new Object[]{locale})).getScript();
            } catch (InvocationTargetException e) {
                Log.w(str, e);
                return locale.getScript();
            } catch (IllegalAccessException e2) {
                Log.w(str, e2);
                return locale.getScript();
            }
        } else {
            String localeWithSubtags = addLikelySubtags(locale);
            if (localeWithSubtags != null) {
                return getScript(localeWithSubtags);
            }
            return null;
        }
    }

    private static String getScript(String localeStr) {
        String str = TAG;
        try {
            if (sGetScriptMethod != null) {
                return (String) sGetScriptMethod.invoke(null, new Object[]{localeStr});
            }
        } catch (IllegalAccessException e) {
            Log.w(str, e);
        } catch (InvocationTargetException e2) {
            Log.w(str, e2);
        }
        return null;
    }

    private static String addLikelySubtags(Locale locale) {
        String str = TAG;
        String localeStr = locale.toString();
        try {
            if (sAddLikelySubtagsMethod != null) {
                return (String) sAddLikelySubtagsMethod.invoke(null, new Object[]{localeStr});
            }
        } catch (IllegalAccessException e) {
            Log.w(str, e);
        } catch (InvocationTargetException e2) {
            Log.w(str, e2);
        }
        return localeStr;
    }

    private ICUCompat() {
    }
}
