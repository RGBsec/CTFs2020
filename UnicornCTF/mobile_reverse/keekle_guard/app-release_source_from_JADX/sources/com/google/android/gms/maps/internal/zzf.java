package com.google.android.gms.maps.internal;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzc;
import com.google.android.gms.internal.maps.zze;
import com.google.android.gms.maps.GoogleMapOptions;
import com.google.android.gms.maps.StreetViewPanoramaOptions;

public final class zzf extends zza implements zze {
    zzf(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.ICreator");
    }

    public final IMapFragmentDelegate zzc(IObjectWrapper iObjectWrapper) throws RemoteException {
        IMapFragmentDelegate iMapFragmentDelegate;
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        Parcel zza2 = zza(2, zza);
        IBinder readStrongBinder = zza2.readStrongBinder();
        if (readStrongBinder == null) {
            iMapFragmentDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IMapFragmentDelegate");
            if (queryLocalInterface instanceof IMapFragmentDelegate) {
                iMapFragmentDelegate = (IMapFragmentDelegate) queryLocalInterface;
            } else {
                iMapFragmentDelegate = new zzj(readStrongBinder);
            }
        }
        zza2.recycle();
        return iMapFragmentDelegate;
    }

    public final IMapViewDelegate zza(IObjectWrapper iObjectWrapper, GoogleMapOptions googleMapOptions) throws RemoteException {
        IMapViewDelegate iMapViewDelegate;
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzc.zza(zza, (Parcelable) googleMapOptions);
        Parcel zza2 = zza(3, zza);
        IBinder readStrongBinder = zza2.readStrongBinder();
        if (readStrongBinder == null) {
            iMapViewDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IMapViewDelegate");
            if (queryLocalInterface instanceof IMapViewDelegate) {
                iMapViewDelegate = (IMapViewDelegate) queryLocalInterface;
            } else {
                iMapViewDelegate = new zzk(readStrongBinder);
            }
        }
        zza2.recycle();
        return iMapViewDelegate;
    }

    public final ICameraUpdateFactoryDelegate zze() throws RemoteException {
        ICameraUpdateFactoryDelegate iCameraUpdateFactoryDelegate;
        Parcel zza = zza(4, zza());
        IBinder readStrongBinder = zza.readStrongBinder();
        if (readStrongBinder == null) {
            iCameraUpdateFactoryDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.ICameraUpdateFactoryDelegate");
            if (queryLocalInterface instanceof ICameraUpdateFactoryDelegate) {
                iCameraUpdateFactoryDelegate = (ICameraUpdateFactoryDelegate) queryLocalInterface;
            } else {
                iCameraUpdateFactoryDelegate = new zzb(readStrongBinder);
            }
        }
        zza.recycle();
        return iCameraUpdateFactoryDelegate;
    }

    public final zze zzf() throws RemoteException {
        Parcel zza = zza(5, zza());
        zze zzb = com.google.android.gms.internal.maps.zzf.zzb(zza.readStrongBinder());
        zza.recycle();
        return zzb;
    }

    public final void zza(IObjectWrapper iObjectWrapper, int i) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zza.writeInt(i);
        zzb(6, zza);
    }

    public final IStreetViewPanoramaViewDelegate zza(IObjectWrapper iObjectWrapper, StreetViewPanoramaOptions streetViewPanoramaOptions) throws RemoteException {
        IStreetViewPanoramaViewDelegate iStreetViewPanoramaViewDelegate;
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzc.zza(zza, (Parcelable) streetViewPanoramaOptions);
        Parcel zza2 = zza(7, zza);
        IBinder readStrongBinder = zza2.readStrongBinder();
        if (readStrongBinder == null) {
            iStreetViewPanoramaViewDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IStreetViewPanoramaViewDelegate");
            if (queryLocalInterface instanceof IStreetViewPanoramaViewDelegate) {
                iStreetViewPanoramaViewDelegate = (IStreetViewPanoramaViewDelegate) queryLocalInterface;
            } else {
                iStreetViewPanoramaViewDelegate = new zzbw(readStrongBinder);
            }
        }
        zza2.recycle();
        return iStreetViewPanoramaViewDelegate;
    }

    public final IStreetViewPanoramaFragmentDelegate zzd(IObjectWrapper iObjectWrapper) throws RemoteException {
        IStreetViewPanoramaFragmentDelegate iStreetViewPanoramaFragmentDelegate;
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        Parcel zza2 = zza(8, zza);
        IBinder readStrongBinder = zza2.readStrongBinder();
        if (readStrongBinder == null) {
            iStreetViewPanoramaFragmentDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IStreetViewPanoramaFragmentDelegate");
            if (queryLocalInterface instanceof IStreetViewPanoramaFragmentDelegate) {
                iStreetViewPanoramaFragmentDelegate = (IStreetViewPanoramaFragmentDelegate) queryLocalInterface;
            } else {
                iStreetViewPanoramaFragmentDelegate = new zzbv(readStrongBinder);
            }
        }
        zza2.recycle();
        return iStreetViewPanoramaFragmentDelegate;
    }
}
