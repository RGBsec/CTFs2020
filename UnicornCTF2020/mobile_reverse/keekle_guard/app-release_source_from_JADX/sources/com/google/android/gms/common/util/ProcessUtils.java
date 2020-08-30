package com.google.android.gms.common.util;

import android.os.Process;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.FileReader;
import java.io.IOException;
import javax.annotation.Nullable;

public class ProcessUtils {
    private static String zzhf;
    private static int zzhg;

    private ProcessUtils() {
    }

    @Nullable
    public static String getMyProcessName() {
        if (zzhf == null) {
            if (zzhg == 0) {
                zzhg = Process.myPid();
            }
            zzhf = zzd(zzhg);
        }
        return zzhf;
    }

    @Nullable
    private static String zzd(int i) {
        BufferedReader bufferedReader;
        Throwable th;
        String str = null;
        if (i <= 0) {
            return null;
        }
        try {
            StringBuilder sb = new StringBuilder(25);
            sb.append("/proc/");
            sb.append(i);
            sb.append("/cmdline");
            bufferedReader = zzk(sb.toString());
            try {
                str = bufferedReader.readLine().trim();
                IOUtils.closeQuietly((Closeable) bufferedReader);
            } catch (IOException unused) {
                IOUtils.closeQuietly((Closeable) bufferedReader);
                return str;
            } catch (Throwable th2) {
                th = th2;
                IOUtils.closeQuietly((Closeable) bufferedReader);
                throw th;
            }
        } catch (IOException unused2) {
            bufferedReader = null;
            IOUtils.closeQuietly((Closeable) bufferedReader);
            return str;
        } catch (Throwable th3) {
            th = th3;
            bufferedReader = null;
            IOUtils.closeQuietly((Closeable) bufferedReader);
            throw th;
        }
        return str;
    }

    private static BufferedReader zzk(String str) throws IOException {
        ThreadPolicy allowThreadDiskReads = StrictMode.allowThreadDiskReads();
        try {
            return new BufferedReader(new FileReader(str));
        } finally {
            StrictMode.setThreadPolicy(allowThreadDiskReads);
        }
    }
}
