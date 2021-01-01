package com.google.android.gms.auth.api.signin.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.internal.Preconditions;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;
import org.json.JSONException;

public class Storage {
    private static final Lock zaaj = new ReentrantLock();
    private static Storage zaak;
    private final Lock zaal = new ReentrantLock();
    private final SharedPreferences zaam;

    public static Storage getInstance(Context context) {
        Preconditions.checkNotNull(context);
        zaaj.lock();
        try {
            if (zaak == null) {
                zaak = new Storage(context.getApplicationContext());
            }
            return zaak;
        } finally {
            zaaj.unlock();
        }
    }

    private Storage(Context context) {
        this.zaam = context.getSharedPreferences("com.google.android.gms.signin", 0);
    }

    public void saveDefaultGoogleSignInAccount(GoogleSignInAccount googleSignInAccount, GoogleSignInOptions googleSignInOptions) {
        Preconditions.checkNotNull(googleSignInAccount);
        Preconditions.checkNotNull(googleSignInOptions);
        zaa("defaultGoogleSignInAccount", googleSignInAccount.zab());
        Preconditions.checkNotNull(googleSignInAccount);
        Preconditions.checkNotNull(googleSignInOptions);
        String zab = googleSignInAccount.zab();
        zaa(zab("googleSignInAccount", zab), googleSignInAccount.zac());
        zaa(zab("googleSignInOptions", zab), googleSignInOptions.zae());
    }

    private final void zaa(String str, String str2) {
        this.zaal.lock();
        try {
            this.zaam.edit().putString(str, str2).apply();
        } finally {
            this.zaal.unlock();
        }
    }

    @Nullable
    public GoogleSignInAccount getSavedDefaultGoogleSignInAccount() {
        return zad(zaf("defaultGoogleSignInAccount"));
    }

    @Nullable
    private final GoogleSignInAccount zad(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        String zaf = zaf(zab("googleSignInAccount", str));
        if (zaf != null) {
            try {
                return GoogleSignInAccount.zaa(zaf);
            } catch (JSONException unused) {
            }
        }
        return null;
    }

    @Nullable
    public GoogleSignInOptions getSavedDefaultGoogleSignInOptions() {
        return zae(zaf("defaultGoogleSignInAccount"));
    }

    @Nullable
    private final GoogleSignInOptions zae(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        String zaf = zaf(zab("googleSignInOptions", str));
        if (zaf != null) {
            try {
                return GoogleSignInOptions.zab(zaf);
            } catch (JSONException unused) {
            }
        }
        return null;
    }

    @Nullable
    public String getSavedRefreshToken() {
        return zaf("refreshToken");
    }

    @Nullable
    private final String zaf(String str) {
        this.zaal.lock();
        try {
            return this.zaam.getString(str, null);
        } finally {
            this.zaal.unlock();
        }
    }

    public final void zaf() {
        String str = "defaultGoogleSignInAccount";
        String zaf = zaf(str);
        zag(str);
        if (!TextUtils.isEmpty(zaf)) {
            zag(zab("googleSignInAccount", zaf));
            zag(zab("googleSignInOptions", zaf));
        }
    }

    private final void zag(String str) {
        this.zaal.lock();
        try {
            this.zaam.edit().remove(str).apply();
        } finally {
            this.zaal.unlock();
        }
    }

    public void clear() {
        this.zaal.lock();
        try {
            this.zaam.edit().clear().apply();
        } finally {
            this.zaal.unlock();
        }
    }

    private static String zab(String str, String str2) {
        StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 1 + String.valueOf(str2).length());
        sb.append(str);
        sb.append(":");
        sb.append(str2);
        return sb.toString();
    }
}
