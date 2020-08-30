package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Typeface;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import androidx.core.content.res.FontResourcesParserCompat.FontFamilyFilesResourceEntry;
import androidx.core.content.res.FontResourcesParserCompat.FontFileResourceEntry;
import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

class TypefaceCompatApi21Impl extends TypefaceCompatBaseImpl {
    private static final String ADD_FONT_WEIGHT_STYLE_METHOD = "addFontWeightStyle";
    private static final String CREATE_FROM_FAMILIES_WITH_DEFAULT_METHOD = "createFromFamiliesWithDefault";
    private static final String FONT_FAMILY_CLASS = "android.graphics.FontFamily";
    private static final String TAG = "TypefaceCompatApi21Impl";
    private static Method sAddFontWeightStyle;
    private static Method sCreateFromFamiliesWithDefault;
    private static Class sFontFamily;
    private static Constructor sFontFamilyCtor;
    private static boolean sHasInitBeenCalled = false;

    TypefaceCompatApi21Impl() {
    }

    private static void init() {
        Method addFontMethod;
        Constructor fontFamilyCtor;
        Class fontFamilyClass;
        Method createFromFamiliesWithDefaultMethod;
        if (!sHasInitBeenCalled) {
            sHasInitBeenCalled = true;
            try {
                fontFamilyClass = Class.forName(FONT_FAMILY_CLASS);
                fontFamilyCtor = fontFamilyClass.getConstructor(new Class[0]);
                addFontMethod = fontFamilyClass.getMethod(ADD_FONT_WEIGHT_STYLE_METHOD, new Class[]{String.class, Integer.TYPE, Boolean.TYPE});
                Object familyArray = Array.newInstance(fontFamilyClass, 1);
                createFromFamiliesWithDefaultMethod = Typeface.class.getMethod(CREATE_FROM_FAMILIES_WITH_DEFAULT_METHOD, new Class[]{familyArray.getClass()});
            } catch (ClassNotFoundException | NoSuchMethodException e) {
                Log.e(TAG, e.getClass().getName(), e);
                fontFamilyClass = null;
                fontFamilyCtor = null;
                addFontMethod = null;
                createFromFamiliesWithDefaultMethod = null;
            }
            sFontFamilyCtor = fontFamilyCtor;
            sFontFamily = fontFamilyClass;
            sAddFontWeightStyle = addFontMethod;
            sCreateFromFamiliesWithDefault = createFromFamiliesWithDefaultMethod;
        }
    }

    private File getFile(ParcelFileDescriptor fd) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("/proc/self/fd/");
            sb.append(fd.getFd());
            String path = Os.readlink(sb.toString());
            if (OsConstants.S_ISREG(Os.stat(path).st_mode)) {
                return new File(path);
            }
            return null;
        } catch (ErrnoException e) {
            return null;
        }
    }

    private static Object newFamily() {
        init();
        try {
            return sFontFamilyCtor.newInstance(new Object[0]);
        } catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static Typeface createFromFamiliesWithDefault(Object family) {
        init();
        try {
            Object familyArray = Array.newInstance(sFontFamily, 1);
            Array.set(familyArray, 0, family);
            return (Typeface) sCreateFromFamiliesWithDefault.invoke(null, new Object[]{familyArray});
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean addFontWeightStyle(Object family, String name, int weight, boolean style) {
        init();
        try {
            return ((Boolean) sAddFontWeightStyle.invoke(family, new Object[]{name, Integer.valueOf(weight), Boolean.valueOf(style)})).booleanValue();
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:34:0x0052, code lost:
        r7 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:36:?, code lost:
        r5.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x0057, code lost:
        r8 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:?, code lost:
        r6.addSuppressed(r8);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:40:0x005b, code lost:
        throw r7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:44:0x005e, code lost:
        r5 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:45:0x005f, code lost:
        if (r3 != null) goto L_0x0061;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:47:?, code lost:
        r3.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:51:0x0069, code lost:
        throw r5;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public android.graphics.Typeface createFromFontInfo(android.content.Context r10, android.os.CancellationSignal r11, androidx.core.provider.FontsContractCompat.FontInfo[] r12, int r13) {
        /*
            r9 = this;
            int r0 = r12.length
            r1 = 0
            r2 = 1
            if (r0 >= r2) goto L_0x0006
            return r1
        L_0x0006:
            androidx.core.provider.FontsContractCompat$FontInfo r0 = r9.findBestInfo(r12, r13)
            android.content.ContentResolver r2 = r10.getContentResolver()
            android.net.Uri r3 = r0.getUri()     // Catch:{ IOException -> 0x006a }
            java.lang.String r4 = "r"
            android.os.ParcelFileDescriptor r3 = r2.openFileDescriptor(r3, r4, r11)     // Catch:{ IOException -> 0x006a }
            if (r3 != 0) goto L_0x0023
            if (r3 == 0) goto L_0x0022
            r3.close()     // Catch:{ IOException -> 0x006a }
        L_0x0022:
            return r1
        L_0x0023:
            java.io.File r4 = r9.getFile(r3)     // Catch:{ all -> 0x005c }
            if (r4 == 0) goto L_0x003a
            boolean r5 = r4.canRead()     // Catch:{ all -> 0x005c }
            if (r5 != 0) goto L_0x0030
            goto L_0x003a
        L_0x0030:
            android.graphics.Typeface r5 = android.graphics.Typeface.createFromFile(r4)     // Catch:{ all -> 0x005c }
            if (r3 == 0) goto L_0x0039
            r3.close()     // Catch:{ IOException -> 0x006a }
        L_0x0039:
            return r5
        L_0x003a:
            java.io.FileInputStream r5 = new java.io.FileInputStream     // Catch:{ all -> 0x005c }
            java.io.FileDescriptor r6 = r3.getFileDescriptor()     // Catch:{ all -> 0x005c }
            r5.<init>(r6)     // Catch:{ all -> 0x005c }
            android.graphics.Typeface r6 = super.createFromInputStream(r10, r5)     // Catch:{ all -> 0x0050 }
            r5.close()     // Catch:{ all -> 0x005c }
            if (r3 == 0) goto L_0x004f
            r3.close()     // Catch:{ IOException -> 0x006a }
        L_0x004f:
            return r6
        L_0x0050:
            r6 = move-exception
            throw r6     // Catch:{ all -> 0x0052 }
        L_0x0052:
            r7 = move-exception
            r5.close()     // Catch:{ all -> 0x0057 }
            goto L_0x005b
        L_0x0057:
            r8 = move-exception
            r6.addSuppressed(r8)     // Catch:{ all -> 0x005c }
        L_0x005b:
            throw r7     // Catch:{ all -> 0x005c }
        L_0x005c:
            r4 = move-exception
            throw r4     // Catch:{ all -> 0x005e }
        L_0x005e:
            r5 = move-exception
            if (r3 == 0) goto L_0x0069
            r3.close()     // Catch:{ all -> 0x0065 }
            goto L_0x0069
        L_0x0065:
            r6 = move-exception
            r4.addSuppressed(r6)     // Catch:{ IOException -> 0x006a }
        L_0x0069:
            throw r5     // Catch:{ IOException -> 0x006a }
        L_0x006a:
            r3 = move-exception
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.TypefaceCompatApi21Impl.createFromFontInfo(android.content.Context, android.os.CancellationSignal, androidx.core.provider.FontsContractCompat$FontInfo[], int):android.graphics.Typeface");
    }

    public Typeface createFromFontFamilyFilesResourceEntry(Context context, FontFamilyFilesResourceEntry entry, Resources resources, int style) {
        Object family = newFamily();
        FontFileResourceEntry[] entries = entry.getEntries();
        int length = entries.length;
        int i = 0;
        while (i < length) {
            FontFileResourceEntry e = entries[i];
            File tmpFile = TypefaceCompatUtil.getTempFile(context);
            if (tmpFile == null) {
                return null;
            }
            try {
                if (!TypefaceCompatUtil.copyToFile(tmpFile, resources, e.getResourceId())) {
                    tmpFile.delete();
                    return null;
                } else if (!addFontWeightStyle(family, tmpFile.getPath(), e.getWeight(), e.isItalic())) {
                    return null;
                } else {
                    tmpFile.delete();
                    i++;
                }
            } catch (RuntimeException e2) {
                return null;
            } finally {
                tmpFile.delete();
            }
        }
        return createFromFamiliesWithDefault(family);
    }
}
