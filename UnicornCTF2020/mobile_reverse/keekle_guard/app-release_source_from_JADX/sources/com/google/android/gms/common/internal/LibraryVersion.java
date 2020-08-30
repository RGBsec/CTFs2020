package com.google.android.gms.common.internal;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

public class LibraryVersion {
    private static final GmsLogger zzel = new GmsLogger("LibraryVersion", "");
    private static LibraryVersion zzem = new LibraryVersion();
    private ConcurrentHashMap<String, String> zzen = new ConcurrentHashMap<>();

    public static LibraryVersion getInstance() {
        return zzem;
    }

    protected LibraryVersion() {
    }

    public String getVersion(String str) {
        String str2 = "Failed to get app version for libraryName: ";
        String str3 = "LibraryVersion";
        Preconditions.checkNotEmpty(str, "Please provide a valid libraryName");
        if (this.zzen.containsKey(str)) {
            return (String) this.zzen.get(str);
        }
        Properties properties = new Properties();
        String str4 = null;
        try {
            InputStream resourceAsStream = LibraryVersion.class.getResourceAsStream(String.format("/%s.properties", new Object[]{str}));
            if (resourceAsStream != null) {
                properties.load(resourceAsStream);
                str4 = properties.getProperty("version", null);
                GmsLogger gmsLogger = zzel;
                StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 12 + String.valueOf(str4).length());
                sb.append(str);
                sb.append(" version is ");
                sb.append(str4);
                gmsLogger.mo6746v(str3, sb.toString());
            } else {
                GmsLogger gmsLogger2 = zzel;
                String valueOf = String.valueOf(str);
                gmsLogger2.mo6739e(str3, valueOf.length() != 0 ? str2.concat(valueOf) : new String(str2));
            }
        } catch (IOException e) {
            GmsLogger gmsLogger3 = zzel;
            String valueOf2 = String.valueOf(str);
            gmsLogger3.mo6740e(str3, valueOf2.length() != 0 ? str2.concat(valueOf2) : new String(str2), e);
        }
        if (str4 == null) {
            zzel.mo6737d(str3, ".properties file is dropped during release process. Failure to read app version isexpected druing Google internal testing where locally-built libraries are used");
            str4 = "UNKNOWN";
        }
        this.zzen.put(str, str4);
        return str4;
    }
}
