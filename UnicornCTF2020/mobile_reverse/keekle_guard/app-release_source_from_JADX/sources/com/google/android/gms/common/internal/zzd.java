package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.safeparcel.SafeParcelReader;

public final class zzd implements Creator<GetServiceRequest> {
    public final /* synthetic */ Object[] newArray(int i) {
        return new GetServiceRequest[i];
    }

    public final /* synthetic */ Object createFromParcel(Parcel parcel) {
        Parcel parcel2 = parcel;
        int validateObjectHeader = SafeParcelReader.validateObjectHeader(parcel);
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        boolean z = false;
        String str = null;
        IBinder iBinder = null;
        Scope[] scopeArr = null;
        Bundle bundle = null;
        Account account = null;
        Feature[] featureArr = null;
        Feature[] featureArr2 = null;
        while (parcel.dataPosition() < validateObjectHeader) {
            int readHeader = SafeParcelReader.readHeader(parcel);
            switch (SafeParcelReader.getFieldId(readHeader)) {
                case 1:
                    i = SafeParcelReader.readInt(parcel2, readHeader);
                    break;
                case 2:
                    i2 = SafeParcelReader.readInt(parcel2, readHeader);
                    break;
                case 3:
                    i3 = SafeParcelReader.readInt(parcel2, readHeader);
                    break;
                case 4:
                    str = SafeParcelReader.createString(parcel2, readHeader);
                    break;
                case 5:
                    iBinder = SafeParcelReader.readIBinder(parcel2, readHeader);
                    break;
                case 6:
                    scopeArr = (Scope[]) SafeParcelReader.createTypedArray(parcel2, readHeader, Scope.CREATOR);
                    break;
                case 7:
                    bundle = SafeParcelReader.createBundle(parcel2, readHeader);
                    break;
                case 8:
                    account = (Account) SafeParcelReader.createParcelable(parcel2, readHeader, Account.CREATOR);
                    break;
                case 10:
                    featureArr = (Feature[]) SafeParcelReader.createTypedArray(parcel2, readHeader, Feature.CREATOR);
                    break;
                case 11:
                    featureArr2 = (Feature[]) SafeParcelReader.createTypedArray(parcel2, readHeader, Feature.CREATOR);
                    break;
                case 12:
                    z = SafeParcelReader.readBoolean(parcel2, readHeader);
                    break;
                default:
                    SafeParcelReader.skipUnknownField(parcel2, readHeader);
                    break;
            }
        }
        SafeParcelReader.ensureAtEnd(parcel2, validateObjectHeader);
        GetServiceRequest getServiceRequest = new GetServiceRequest(i, i2, i3, str, iBinder, scopeArr, bundle, account, featureArr, featureArr2, z);
        return getServiceRequest;
    }
}
