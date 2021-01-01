package com.google.android.gms.common.api;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.common.internal.ReflectedParcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;

public final class Scope extends AbstractSafeParcelable implements ReflectedParcelable {
    public static final Creator<Scope> CREATOR = new zza();
    private final String zzaq;
    private final int zzg;

    Scope(int i, String str) {
        Preconditions.checkNotEmpty(str, "scopeUri must not be null or empty");
        this.zzg = i;
        this.zzaq = str;
    }

    public Scope(String str) {
        this(1, str);
    }

    public final String getScopeUri() {
        return this.zzaq;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Scope)) {
            return false;
        }
        return this.zzaq.equals(((Scope) obj).zzaq);
    }

    public final int hashCode() {
        return this.zzaq.hashCode();
    }

    public final String toString() {
        return this.zzaq;
    }

    public final void writeToParcel(Parcel parcel, int i) {
        int beginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeInt(parcel, 1, this.zzg);
        SafeParcelWriter.writeString(parcel, 2, getScopeUri(), false);
        SafeParcelWriter.finishObjectHeader(parcel, beginObjectHeader);
    }
}
