package com.google.android.gms.maps.internal;

import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.maps.model.StreetViewPanoramaOrientation;

public interface zzbn extends IInterface {
    void onStreetViewPanoramaLongClick(StreetViewPanoramaOrientation streetViewPanoramaOrientation) throws RemoteException;
}
