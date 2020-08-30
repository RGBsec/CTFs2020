package androidx.core.graphics;

import android.content.Context;
import android.content.res.Resources;
import android.os.Process;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import android.util.Log;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class TypefaceCompatUtil {
    private static final String CACHE_FILE_PREFIX = ".font";
    private static final String TAG = "TypefaceCompatUtil";

    private TypefaceCompatUtil() {
    }

    public static File getTempFile(Context context) {
        File cacheDir = context.getCacheDir();
        if (cacheDir == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(CACHE_FILE_PREFIX);
        sb.append(Process.myPid());
        String str = "-";
        sb.append(str);
        sb.append(Process.myTid());
        sb.append(str);
        String prefix = sb.toString();
        int i = 0;
        while (i < 100) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(prefix);
            sb2.append(i);
            File file = new File(cacheDir, sb2.toString());
            try {
                if (file.createNewFile()) {
                    return file;
                }
                i++;
            } catch (IOException e) {
            }
        }
        return null;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:10:0x001b, code lost:
        r2 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:?, code lost:
        r0.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x0024, code lost:
        throw r2;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static java.nio.ByteBuffer mmap(java.io.File r7) {
        /*
            java.io.FileInputStream r0 = new java.io.FileInputStream     // Catch:{ IOException -> 0x0025 }
            r0.<init>(r7)     // Catch:{ IOException -> 0x0025 }
            java.nio.channels.FileChannel r1 = r0.getChannel()     // Catch:{ all -> 0x0019 }
            long r5 = r1.size()     // Catch:{ all -> 0x0019 }
            java.nio.channels.FileChannel$MapMode r2 = java.nio.channels.FileChannel.MapMode.READ_ONLY     // Catch:{ all -> 0x0019 }
            r3 = 0
            java.nio.MappedByteBuffer r2 = r1.map(r2, r3, r5)     // Catch:{ all -> 0x0019 }
            r0.close()     // Catch:{ IOException -> 0x0025 }
            return r2
        L_0x0019:
            r1 = move-exception
            throw r1     // Catch:{ all -> 0x001b }
        L_0x001b:
            r2 = move-exception
            r0.close()     // Catch:{ all -> 0x0020 }
            goto L_0x0024
        L_0x0020:
            r3 = move-exception
            r1.addSuppressed(r3)     // Catch:{ IOException -> 0x0025 }
        L_0x0024:
            throw r2     // Catch:{ IOException -> 0x0025 }
        L_0x0025:
            r0 = move-exception
            r1 = 0
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.TypefaceCompatUtil.mmap(java.io.File):java.nio.ByteBuffer");
    }

    /* JADX WARNING: Code restructure failed: missing block: B:20:0x0038, code lost:
        r5 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:?, code lost:
        r3.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x003d, code lost:
        r6 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:?, code lost:
        r4.addSuppressed(r6);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0041, code lost:
        throw r5;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x0044, code lost:
        r4 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:0x0045, code lost:
        if (r2 != null) goto L_0x0047;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:?, code lost:
        r2.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x004f, code lost:
        throw r4;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static java.nio.ByteBuffer mmap(android.content.Context r10, android.os.CancellationSignal r11, android.net.Uri r12) {
        /*
            android.content.ContentResolver r0 = r10.getContentResolver()
            r1 = 0
            java.lang.String r2 = "r"
            android.os.ParcelFileDescriptor r2 = r0.openFileDescriptor(r12, r2, r11)     // Catch:{ IOException -> 0x0050 }
            if (r2 != 0) goto L_0x0014
            if (r2 == 0) goto L_0x0013
            r2.close()     // Catch:{ IOException -> 0x0050 }
        L_0x0013:
            return r1
        L_0x0014:
            java.io.FileInputStream r3 = new java.io.FileInputStream     // Catch:{ all -> 0x0042 }
            java.io.FileDescriptor r4 = r2.getFileDescriptor()     // Catch:{ all -> 0x0042 }
            r3.<init>(r4)     // Catch:{ all -> 0x0042 }
            java.nio.channels.FileChannel r4 = r3.getChannel()     // Catch:{ all -> 0x0036 }
            long r8 = r4.size()     // Catch:{ all -> 0x0036 }
            java.nio.channels.FileChannel$MapMode r5 = java.nio.channels.FileChannel.MapMode.READ_ONLY     // Catch:{ all -> 0x0036 }
            r6 = 0
            java.nio.MappedByteBuffer r5 = r4.map(r5, r6, r8)     // Catch:{ all -> 0x0036 }
            r3.close()     // Catch:{ all -> 0x0042 }
            if (r2 == 0) goto L_0x0035
            r2.close()     // Catch:{ IOException -> 0x0050 }
        L_0x0035:
            return r5
        L_0x0036:
            r4 = move-exception
            throw r4     // Catch:{ all -> 0x0038 }
        L_0x0038:
            r5 = move-exception
            r3.close()     // Catch:{ all -> 0x003d }
            goto L_0x0041
        L_0x003d:
            r6 = move-exception
            r4.addSuppressed(r6)     // Catch:{ all -> 0x0042 }
        L_0x0041:
            throw r5     // Catch:{ all -> 0x0042 }
        L_0x0042:
            r3 = move-exception
            throw r3     // Catch:{ all -> 0x0044 }
        L_0x0044:
            r4 = move-exception
            if (r2 == 0) goto L_0x004f
            r2.close()     // Catch:{ all -> 0x004b }
            goto L_0x004f
        L_0x004b:
            r5 = move-exception
            r3.addSuppressed(r5)     // Catch:{ IOException -> 0x0050 }
        L_0x004f:
            throw r4     // Catch:{ IOException -> 0x0050 }
        L_0x0050:
            r2 = move-exception
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.graphics.TypefaceCompatUtil.mmap(android.content.Context, android.os.CancellationSignal, android.net.Uri):java.nio.ByteBuffer");
    }

    public static ByteBuffer copyToDirectBuffer(Context context, Resources res, int id) {
        File tmpFile = getTempFile(context);
        if (tmpFile == null) {
            return null;
        }
        try {
            if (!copyToFile(tmpFile, res, id)) {
                return null;
            }
            ByteBuffer mmap = mmap(tmpFile);
            tmpFile.delete();
            return mmap;
        } finally {
            tmpFile.delete();
        }
    }

    public static boolean copyToFile(File file, InputStream is) {
        FileOutputStream os = null;
        ThreadPolicy old = StrictMode.allowThreadDiskWrites();
        try {
            os = new FileOutputStream(file, false);
            byte[] buffer = new byte[1024];
            while (true) {
                int read = is.read(buffer);
                int readLen = read;
                if (read != -1) {
                    os.write(buffer, 0, readLen);
                } else {
                    return true;
                }
            }
        } catch (IOException e) {
            String str = TAG;
            StringBuilder sb = new StringBuilder();
            sb.append("Error copying resource contents to temp file: ");
            sb.append(e.getMessage());
            Log.e(str, sb.toString());
            return false;
        } finally {
            closeQuietly(os);
            StrictMode.setThreadPolicy(old);
        }
    }

    public static boolean copyToFile(File file, Resources res, int id) {
        InputStream is = null;
        try {
            is = res.openRawResource(id);
            return copyToFile(file, is);
        } finally {
            closeQuietly(is);
        }
    }

    public static void closeQuietly(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException e) {
            }
        }
    }
}
