package com.google.android.gms.internal.maps;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.IObjectWrapper.Stub;
import com.google.android.gms.maps.model.Cap;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.PatternItem;
import java.util.ArrayList;
import java.util.List;

public final class zzab extends zza implements zzz {
    zzab(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.model.internal.IPolylineDelegate");
    }

    public final void remove() throws RemoteException {
        zzb(1, zza());
    }

    public final String getId() throws RemoteException {
        Parcel zza = zza(2, zza());
        String readString = zza.readString();
        zza.recycle();
        return readString;
    }

    public final void setPoints(List<LatLng> list) throws RemoteException {
        Parcel zza = zza();
        zza.writeTypedList(list);
        zzb(3, zza);
    }

    public final List<LatLng> getPoints() throws RemoteException {
        Parcel zza = zza(4, zza());
        ArrayList createTypedArrayList = zza.createTypedArrayList(LatLng.CREATOR);
        zza.recycle();
        return createTypedArrayList;
    }

    public final void setWidth(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(5, zza);
    }

    public final float getWidth() throws RemoteException {
        Parcel zza = zza(6, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }

    public final void setColor(int i) throws RemoteException {
        Parcel zza = zza();
        zza.writeInt(i);
        zzb(7, zza);
    }

    public final int getColor() throws RemoteException {
        Parcel zza = zza(8, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final void setZIndex(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(9, zza);
    }

    public final float getZIndex() throws RemoteException {
        Parcel zza = zza(10, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }

    public final void setVisible(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(11, zza);
    }

    public final boolean isVisible() throws RemoteException {
        Parcel zza = zza(12, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setGeodesic(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(13, zza);
    }

    public final boolean isGeodesic() throws RemoteException {
        Parcel zza = zza(14, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean zzb(zzz zzz) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzz);
        Parcel zza2 = zza(15, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final int zzj() throws RemoteException {
        Parcel zza = zza(16, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final void setClickable(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(17, zza);
    }

    public final boolean isClickable() throws RemoteException {
        Parcel zza = zza(18, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setStartCap(Cap cap) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) cap);
        zzb(19, zza);
    }

    public final Cap getStartCap() throws RemoteException {
        Parcel zza = zza(20, zza());
        Cap cap = (Cap) zzc.zza(zza, Cap.CREATOR);
        zza.recycle();
        return cap;
    }

    public final void setEndCap(Cap cap) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) cap);
        zzb(21, zza);
    }

    public final Cap getEndCap() throws RemoteException {
        Parcel zza = zza(22, zza());
        Cap cap = (Cap) zzc.zza(zza, Cap.CREATOR);
        zza.recycle();
        return cap;
    }

    public final void setJointType(int i) throws RemoteException {
        Parcel zza = zza();
        zza.writeInt(i);
        zzb(23, zza);
    }

    public final int getJointType() throws RemoteException {
        Parcel zza = zza(24, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final void setPattern(List<PatternItem> list) throws RemoteException {
        Parcel zza = zza();
        zza.writeTypedList(list);
        zzb(25, zza);
    }

    public final List<PatternItem> getPattern() throws RemoteException {
        Parcel zza = zza(26, zza());
        ArrayList createTypedArrayList = zza.createTypedArrayList(PatternItem.CREATOR);
        zza.recycle();
        return createTypedArrayList;
    }

    public final void zze(IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzb(27, zza);
    }

    public final IObjectWrapper zzk() throws RemoteException {
        Parcel zza = zza(28, zza());
        IObjectWrapper asInterface = Stub.asInterface(zza.readStrongBinder());
        zza.recycle();
        return asInterface;
    }
}
