package com.google.android.gms.maps.internal;

import android.location.Location;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.internal.maps.zza;
import com.google.android.gms.internal.maps.zzaa;
import com.google.android.gms.internal.maps.zzac;
import com.google.android.gms.internal.maps.zzad;
import com.google.android.gms.internal.maps.zzc;
import com.google.android.gms.internal.maps.zzh;
import com.google.android.gms.internal.maps.zzi;
import com.google.android.gms.internal.maps.zzk;
import com.google.android.gms.internal.maps.zzl;
import com.google.android.gms.internal.maps.zzn;
import com.google.android.gms.internal.maps.zzo;
import com.google.android.gms.internal.maps.zzt;
import com.google.android.gms.internal.maps.zzu;
import com.google.android.gms.internal.maps.zzw;
import com.google.android.gms.internal.maps.zzx;
import com.google.android.gms.internal.maps.zzz;
import com.google.android.gms.maps.model.CameraPosition;
import com.google.android.gms.maps.model.CircleOptions;
import com.google.android.gms.maps.model.GroundOverlayOptions;
import com.google.android.gms.maps.model.LatLngBounds;
import com.google.android.gms.maps.model.MapStyleOptions;
import com.google.android.gms.maps.model.MarkerOptions;
import com.google.android.gms.maps.model.PolygonOptions;
import com.google.android.gms.maps.model.PolylineOptions;
import com.google.android.gms.maps.model.TileOverlayOptions;

public final class zzg extends zza implements IGoogleMapDelegate {
    zzg(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.maps.internal.IGoogleMapDelegate");
    }

    public final CameraPosition getCameraPosition() throws RemoteException {
        Parcel zza = zza(1, zza());
        CameraPosition cameraPosition = (CameraPosition) zzc.zza(zza, CameraPosition.CREATOR);
        zza.recycle();
        return cameraPosition;
    }

    public final float getMaxZoomLevel() throws RemoteException {
        Parcel zza = zza(2, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }

    public final float getMinZoomLevel() throws RemoteException {
        Parcel zza = zza(3, zza());
        float readFloat = zza.readFloat();
        zza.recycle();
        return readFloat;
    }

    public final void moveCamera(IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzb(4, zza);
    }

    public final void animateCamera(IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzb(5, zza);
    }

    public final void animateCameraWithCallback(IObjectWrapper iObjectWrapper, zzc zzc) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzc.zza(zza, (IInterface) zzc);
        zzb(6, zza);
    }

    public final void animateCameraWithDurationAndCallback(IObjectWrapper iObjectWrapper, int i, zzc zzc) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zza.writeInt(i);
        zzc.zza(zza, (IInterface) zzc);
        zzb(7, zza);
    }

    public final void stopAnimation() throws RemoteException {
        zzb(8, zza());
    }

    public final zzz addPolyline(PolylineOptions polylineOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) polylineOptions);
        Parcel zza2 = zza(9, zza);
        zzz zzi = zzaa.zzi(zza2.readStrongBinder());
        zza2.recycle();
        return zzi;
    }

    public final zzw addPolygon(PolygonOptions polygonOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) polygonOptions);
        Parcel zza2 = zza(10, zza);
        zzw zzh = zzx.zzh(zza2.readStrongBinder());
        zza2.recycle();
        return zzh;
    }

    public final zzt addMarker(MarkerOptions markerOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) markerOptions);
        Parcel zza2 = zza(11, zza);
        zzt zzg = zzu.zzg(zza2.readStrongBinder());
        zza2.recycle();
        return zzg;
    }

    public final zzk addGroundOverlay(GroundOverlayOptions groundOverlayOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) groundOverlayOptions);
        Parcel zza2 = zza(12, zza);
        zzk zzd = zzl.zzd(zza2.readStrongBinder());
        zza2.recycle();
        return zzd;
    }

    public final zzac addTileOverlay(TileOverlayOptions tileOverlayOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) tileOverlayOptions);
        Parcel zza2 = zza(13, zza);
        zzac zzj = zzad.zzj(zza2.readStrongBinder());
        zza2.recycle();
        return zzj;
    }

    public final void clear() throws RemoteException {
        zzb(14, zza());
    }

    public final int getMapType() throws RemoteException {
        Parcel zza = zza(15, zza());
        int readInt = zza.readInt();
        zza.recycle();
        return readInt;
    }

    public final void setMapType(int i) throws RemoteException {
        Parcel zza = zza();
        zza.writeInt(i);
        zzb(16, zza);
    }

    public final boolean isTrafficEnabled() throws RemoteException {
        Parcel zza = zza(17, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setTrafficEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(18, zza);
    }

    public final boolean isIndoorEnabled() throws RemoteException {
        Parcel zza = zza(19, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final boolean setIndoorEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        Parcel zza2 = zza(20, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final boolean isMyLocationEnabled() throws RemoteException {
        Parcel zza = zza(21, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setMyLocationEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(22, zza);
    }

    public final Location getMyLocation() throws RemoteException {
        Parcel zza = zza(23, zza());
        Location location = (Location) zzc.zza(zza, Location.CREATOR);
        zza.recycle();
        return location;
    }

    public final void setLocationSource(ILocationSourceDelegate iLocationSourceDelegate) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) iLocationSourceDelegate);
        zzb(24, zza);
    }

    public final IUiSettingsDelegate getUiSettings() throws RemoteException {
        IUiSettingsDelegate iUiSettingsDelegate;
        Parcel zza = zza(25, zza());
        IBinder readStrongBinder = zza.readStrongBinder();
        if (readStrongBinder == null) {
            iUiSettingsDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IUiSettingsDelegate");
            if (queryLocalInterface instanceof IUiSettingsDelegate) {
                iUiSettingsDelegate = (IUiSettingsDelegate) queryLocalInterface;
            } else {
                iUiSettingsDelegate = new zzbx(readStrongBinder);
            }
        }
        zza.recycle();
        return iUiSettingsDelegate;
    }

    public final IProjectionDelegate getProjection() throws RemoteException {
        IProjectionDelegate iProjectionDelegate;
        Parcel zza = zza(26, zza());
        IBinder readStrongBinder = zza.readStrongBinder();
        if (readStrongBinder == null) {
            iProjectionDelegate = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("com.google.android.gms.maps.internal.IProjectionDelegate");
            if (queryLocalInterface instanceof IProjectionDelegate) {
                iProjectionDelegate = (IProjectionDelegate) queryLocalInterface;
            } else {
                iProjectionDelegate = new zzbr(readStrongBinder);
            }
        }
        zza.recycle();
        return iProjectionDelegate;
    }

    public final void setOnCameraChangeListener(zzl zzl) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzl);
        zzb(27, zza);
    }

    public final void setOnMapClickListener(zzaj zzaj) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzaj);
        zzb(28, zza);
    }

    public final void setOnMapLongClickListener(zzan zzan) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzan);
        zzb(29, zza);
    }

    public final void setOnMarkerClickListener(zzar zzar) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzar);
        zzb(30, zza);
    }

    public final void setOnMarkerDragListener(zzat zzat) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzat);
        zzb(31, zza);
    }

    public final void setOnInfoWindowClickListener(zzab zzab) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzab);
        zzb(32, zza);
    }

    public final void setInfoWindowAdapter(zzh zzh) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzh);
        zzb(33, zza);
    }

    public final zzh addCircle(CircleOptions circleOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) circleOptions);
        Parcel zza2 = zza(35, zza);
        zzh zzc = zzi.zzc(zza2.readStrongBinder());
        zza2.recycle();
        return zzc;
    }

    public final void setOnMyLocationChangeListener(zzax zzax) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzax);
        zzb(36, zza);
    }

    public final void setOnMyLocationButtonClickListener(zzav zzav) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzav);
        zzb(37, zza);
    }

    public final void snapshot(zzbs zzbs, IObjectWrapper iObjectWrapper) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbs);
        zzc.zza(zza, (IInterface) iObjectWrapper);
        zzb(38, zza);
    }

    public final void setPadding(int i, int i2, int i3, int i4) throws RemoteException {
        Parcel zza = zza();
        zza.writeInt(i);
        zza.writeInt(i2);
        zza.writeInt(i3);
        zza.writeInt(i4);
        zzb(39, zza);
    }

    public final boolean isBuildingsEnabled() throws RemoteException {
        Parcel zza = zza(40, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void setBuildingsEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(41, zza);
    }

    public final void setOnMapLoadedCallback(zzal zzal) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzal);
        zzb(42, zza);
    }

    public final zzn getFocusedBuilding() throws RemoteException {
        Parcel zza = zza(44, zza());
        zzn zze = zzo.zze(zza.readStrongBinder());
        zza.recycle();
        return zze;
    }

    public final void setOnIndoorStateChangeListener(zzz zzz) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzz);
        zzb(45, zza);
    }

    public final void setWatermarkEnabled(boolean z) throws RemoteException {
        Parcel zza = zza();
        zzc.writeBoolean(zza, z);
        zzb(51, zza);
    }

    public final void getMapAsync(zzap zzap) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzap);
        zzb(53, zza);
    }

    public final void onCreate(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        zzb(54, zza);
    }

    public final void onResume() throws RemoteException {
        zzb(55, zza());
    }

    public final void onPause() throws RemoteException {
        zzb(56, zza());
    }

    public final void onDestroy() throws RemoteException {
        zzb(57, zza());
    }

    public final void onLowMemory() throws RemoteException {
        zzb(58, zza());
    }

    public final boolean useViewLifecycleWhenInFragment() throws RemoteException {
        Parcel zza = zza(59, zza());
        boolean zza2 = zzc.zza(zza);
        zza.recycle();
        return zza2;
    }

    public final void onSaveInstanceState(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        Parcel zza2 = zza(60, zza);
        if (zza2.readInt() != 0) {
            bundle.readFromParcel(zza2);
        }
        zza2.recycle();
    }

    public final void setContentDescription(String str) throws RemoteException {
        Parcel zza = zza();
        zza.writeString(str);
        zzb(61, zza);
    }

    public final void snapshotForTest(zzbs zzbs) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbs);
        zzb(71, zza);
    }

    public final void setOnPoiClickListener(zzbb zzbb) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbb);
        zzb(80, zza);
    }

    public final void onEnterAmbient(Bundle bundle) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) bundle);
        zzb(81, zza);
    }

    public final void onExitAmbient() throws RemoteException {
        zzb(82, zza());
    }

    public final void setOnGroundOverlayClickListener(zzx zzx) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzx);
        zzb(83, zza);
    }

    public final void setOnInfoWindowLongClickListener(zzaf zzaf) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzaf);
        zzb(84, zza);
    }

    public final void setOnPolygonClickListener(zzbd zzbd) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbd);
        zzb(85, zza);
    }

    public final void setOnInfoWindowCloseListener(zzad zzad) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzad);
        zzb(86, zza);
    }

    public final void setOnPolylineClickListener(zzbf zzbf) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzbf);
        zzb(87, zza);
    }

    public final void setOnCircleClickListener(zzv zzv) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzv);
        zzb(89, zza);
    }

    public final void setMinZoomPreference(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(92, zza);
    }

    public final void setMaxZoomPreference(float f) throws RemoteException {
        Parcel zza = zza();
        zza.writeFloat(f);
        zzb(93, zza);
    }

    public final void resetMinMaxZoomPreference() throws RemoteException {
        zzb(94, zza());
    }

    public final void setLatLngBoundsForCameraTarget(LatLngBounds latLngBounds) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) latLngBounds);
        zzb(95, zza);
    }

    public final void setOnCameraMoveStartedListener(zzt zzt) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzt);
        zzb(96, zza);
    }

    public final void setOnCameraMoveListener(zzr zzr) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzr);
        zzb(97, zza);
    }

    public final void setOnCameraMoveCanceledListener(zzp zzp) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzp);
        zzb(98, zza);
    }

    public final void setOnCameraIdleListener(zzn zzn) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzn);
        zzb(99, zza);
    }

    public final boolean setMapStyle(MapStyleOptions mapStyleOptions) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (Parcelable) mapStyleOptions);
        Parcel zza2 = zza(91, zza);
        boolean zza3 = zzc.zza(zza2);
        zza2.recycle();
        return zza3;
    }

    public final void onStart() throws RemoteException {
        zzb(101, zza());
    }

    public final void onStop() throws RemoteException {
        zzb(102, zza());
    }

    public final void setOnMyLocationClickListener(zzaz zzaz) throws RemoteException {
        Parcel zza = zza();
        zzc.zza(zza, (IInterface) zzaz);
        zzb(107, zza);
    }
}
