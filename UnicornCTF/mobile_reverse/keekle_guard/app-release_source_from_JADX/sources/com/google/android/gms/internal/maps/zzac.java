package com.google.android.gms.internal.maps;

import android.os.IInterface;
import android.os.RemoteException;

public interface zzac extends IInterface {
    void clearTileCache() throws RemoteException;

    boolean getFadeIn() throws RemoteException;

    String getId() throws RemoteException;

    float getTransparency() throws RemoteException;

    float getZIndex() throws RemoteException;

    boolean isVisible() throws RemoteException;

    void remove() throws RemoteException;

    void setFadeIn(boolean z) throws RemoteException;

    void setTransparency(float f) throws RemoteException;

    void setVisible(boolean z) throws RemoteException;

    void setZIndex(float f) throws RemoteException;

    boolean zza(zzac zzac) throws RemoteException;

    int zzj() throws RemoteException;
}
