package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.os.Binder;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.internal.IAccountAccessor.Stub;

public class AccountAccessor extends Stub {
    public static Account getAccountBinderSafe(IAccountAccessor iAccountAccessor) {
        if (iAccountAccessor != null) {
            long clearCallingIdentity = Binder.clearCallingIdentity();
            try {
                return iAccountAccessor.getAccount();
            } catch (RemoteException unused) {
                Log.w("AccountAccessor", "Remote account accessor probably died");
            } finally {
                Binder.restoreCallingIdentity(clearCallingIdentity);
            }
        }
        return null;
    }

    public final Account getAccount() {
        throw new NoSuchMethodError();
    }

    public boolean equals(Object obj) {
        throw new NoSuchMethodError();
    }
}
