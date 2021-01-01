package com.google.android.gms.auth.api.signin;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader;
import java.util.List;

public final class zab implements Creator<GoogleSignInAccount> {
    public final /* synthetic */ Object[] newArray(int i) {
        return new GoogleSignInAccount[i];
    }

    public final /* synthetic */ Object createFromParcel(Parcel parcel) {
        Parcel parcel2 = parcel;
        int validateObjectHeader = SafeParcelReader.validateObjectHeader(parcel);
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Uri uri = null;
        String str5 = null;
        String str6 = null;
        List list = null;
        String str7 = null;
        String str8 = null;
        int i = 0;
        long j = 0;
        while (parcel.dataPosition() < validateObjectHeader) {
            int readHeader = SafeParcelReader.readHeader(parcel);
            switch (SafeParcelReader.getFieldId(readHeader)) {
                case 1:
                    i = SafeParcelReader.readInt(parcel2, readHeader);
                    break;
                case 2:
                    str = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 3:
                    str2 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 4:
                    str3 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 5:
                    str4 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 6:
                    uri = (Uri) SafeParcelReader.createParcelable(parcel2, readHeader, Uri.CREATOR);
                    break;
                case 7:
                    str5 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 8:
                    j = SafeParcelReader.readLong(parcel2, readHeader);
                    break;
                case 9:
                    str6 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 10:
                    list = SafeParcelReader.createTypedList(parcel2, readHeader, Scope.CREATOR);
                    break;
                case 11:
                    str7 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 12:
                    str8 = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                default:
                    SafeParcelReader.skipUnknownField(parcel2, readHeader);
                    break;
            }
        }
        SafeParcelReader.ensureAtEnd(parcel2, validateObjectHeader);
        GoogleSignInAccount googleSignInAccount = new GoogleSignInAccount(i, str, str2, str3, str4, uri, str5, j, str6, list, str7, str8);
        return googleSignInAccount;
    }
}
