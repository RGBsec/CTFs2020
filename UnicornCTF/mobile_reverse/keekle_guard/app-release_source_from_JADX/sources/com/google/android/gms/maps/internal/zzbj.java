package com.google.android.gms.maps.internal;

import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.maps.model.StreetViewPanoramaLocation;

public interface zzbj extends IInterface {
    void onStreetViewPanoramaChange(StreetViewPanoramaLocation streetViewPanoramaLocation) throws RemoteException;
}
