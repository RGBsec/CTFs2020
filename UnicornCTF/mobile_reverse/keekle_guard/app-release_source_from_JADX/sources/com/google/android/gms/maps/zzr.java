package com.google.android.gms.maps;

import android.graphics.Bitmap;
import android.os.RemoteException;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.ObjectWrapper;
import com.google.android.gms.maps.GoogleMap.SnapshotReadyCallback;
import com.google.android.gms.maps.internal.zzbt;

final class zzr extends zzbt {
    private final /* synthetic */ SnapshotReadyCallback zzz;

    zzr(GoogleMap googleMap, SnapshotReadyCallback snapshotReadyCallback) {
        this.zzz = snapshotReadyCallback;
    }

    public final void onSnapshotReady(Bitmap bitmap) throws RemoteException {
        this.zzz.onSnapshotReady(bitmap);
    }

    public final void zzb(IObjectWrapper iObjectWrapper) throws RemoteException {
        this.zzz.onSnapshotReady((Bitmap) ObjectWrapper.unwrap(iObjectWrapper));
    }
}
