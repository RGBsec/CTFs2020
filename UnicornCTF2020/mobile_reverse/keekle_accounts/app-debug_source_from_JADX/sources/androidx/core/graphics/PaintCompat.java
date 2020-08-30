package androidx.core.graphics;

import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Build.VERSION;
import androidx.core.util.Pair;

public final class PaintCompat {
    private static final String EM_STRING = "m";
    private static final String TOFU_STRING = "󟿽";
    private static final ThreadLocal<Pair<Rect, Rect>> sRectThreadLocal = new ThreadLocal<>();

    public static boolean hasGlyph(Paint paint, String string) {
        if (VERSION.SDK_INT >= 23) {
            return paint.hasGlyph(string);
        }
        int length = string.length();
        if (length == 1 && Character.isWhitespace(string.charAt(0))) {
            return true;
        }
        String str = TOFU_STRING;
        float missingGlyphWidth = paint.measureText(str);
        float emGlyphWidth = paint.measureText(EM_STRING);
        float width = paint.measureText(string);
        if (width == 0.0f) {
            return false;
        }
        if (string.codePointCount(0, string.length()) > 1) {
            if (width > 2.0f * emGlyphWidth) {
                return false;
            }
            float sumWidth = 0.0f;
            int i = 0;
            while (i < length) {
                int charCount = Character.charCount(string.codePointAt(i));
                sumWidth += paint.measureText(string, i, i + charCount);
                i += charCount;
            }
            if (width >= sumWidth) {
                return false;
            }
        }
        if (width != missingGlyphWidth) {
            return true;
        }
        Pair<Rect, Rect> rects = obtainEmptyRects();
        paint.getTextBounds(str, 0, str.length(), (Rect) rects.first);
        paint.getTextBounds(string, 0, length, (Rect) rects.second);
        return true ^ ((Rect) rects.first).equals(rects.second);
    }

    private static Pair<Rect, Rect> obtainEmptyRects() {
        Pair<Rect, Rect> rects = (Pair) sRectThreadLocal.get();
        if (rects == null) {
            Pair pair = new Pair(new Rect(), new Rect());
            sRectThreadLocal.set(pair);
            return pair;
        }
        ((Rect) rects.first).setEmpty();
        ((Rect) rects.second).setEmpty();
        return rects;
    }

    private PaintCompat() {
    }
}
