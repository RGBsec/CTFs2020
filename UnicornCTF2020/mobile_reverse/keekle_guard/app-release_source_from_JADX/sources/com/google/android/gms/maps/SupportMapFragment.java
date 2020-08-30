package com.google.android.gms.maps;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import android.os.StrictMode.ThreadPolicy.Builder;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.dynamic.DeferredLifecycleHelper;
import com.google.android.gms.dynamic.IObjectWrapper;
import com.google.android.gms.dynamic.ObjectWrapper;
import com.google.android.gms.dynamic.OnDelegateCreatedListener;
import com.google.android.gms.maps.internal.IMapFragmentDelegate;
import com.google.android.gms.maps.internal.MapLifecycleDelegate;
import com.google.android.gms.maps.internal.zzby;
import com.google.android.gms.maps.internal.zzbz;
import com.google.android.gms.maps.model.RuntimeRemoteException;
import java.util.ArrayList;
import java.util.List;

public class SupportMapFragment extends Fragment {
    private final zzb zzch = new zzb(this);

    static class zza implements MapLifecycleDelegate {
        private final Fragment fragment;
        private final IMapFragmentDelegate zzbb;

        public zza(Fragment fragment2, IMapFragmentDelegate iMapFragmentDelegate) {
            this.zzbb = (IMapFragmentDelegate) Preconditions.checkNotNull(iMapFragmentDelegate);
            this.fragment = (Fragment) Preconditions.checkNotNull(fragment2);
        }

        public final void onInflate(Activity activity, Bundle bundle, Bundle bundle2) {
            GoogleMapOptions googleMapOptions = (GoogleMapOptions) bundle.getParcelable("MapOptions");
            try {
                Bundle bundle3 = new Bundle();
                zzby.zza(bundle2, bundle3);
                this.zzbb.onInflate(ObjectWrapper.wrap(activity), googleMapOptions, bundle3);
                zzby.zza(bundle3, bundle2);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onCreate(Bundle bundle) {
            String str = "MapOptions";
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                Bundle arguments = this.fragment.getArguments();
                if (arguments != null && arguments.containsKey(str)) {
                    zzby.zza(bundle2, str, arguments.getParcelable(str));
                }
                this.zzbb.onCreate(bundle2);
                zzby.zza(bundle2, bundle);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                IObjectWrapper onCreateView = this.zzbb.onCreateView(ObjectWrapper.wrap(layoutInflater), ObjectWrapper.wrap(viewGroup), bundle2);
                zzby.zza(bundle2, bundle);
                return (View) ObjectWrapper.unwrap(onCreateView);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onStart() {
            try {
                this.zzbb.onStart();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onResume() {
            try {
                this.zzbb.onResume();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onPause() {
            try {
                this.zzbb.onPause();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onStop() {
            try {
                this.zzbb.onStop();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onDestroyView() {
            try {
                this.zzbb.onDestroyView();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onDestroy() {
            try {
                this.zzbb.onDestroy();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onLowMemory() {
            try {
                this.zzbb.onLowMemory();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onSaveInstanceState(Bundle bundle) {
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                this.zzbb.onSaveInstanceState(bundle2);
                zzby.zza(bundle2, bundle);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void getMapAsync(OnMapReadyCallback onMapReadyCallback) {
            try {
                this.zzbb.getMapAsync(new zzak(this, onMapReadyCallback));
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onEnterAmbient(Bundle bundle) {
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                this.zzbb.onEnterAmbient(bundle2);
                zzby.zza(bundle2, bundle);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onExitAmbient() {
            try {
                this.zzbb.onExitAmbient();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }
    }

    static class zzb extends DeferredLifecycleHelper<zza> {
        private final Fragment fragment;
        private OnDelegateCreatedListener<zza> zzbd;
        private Activity zzbe;
        private final List<OnMapReadyCallback> zzbf = new ArrayList();

        zzb(Fragment fragment2) {
            this.fragment = fragment2;
        }

        /* access modifiers changed from: protected */
        public final void createDelegate(OnDelegateCreatedListener<zza> onDelegateCreatedListener) {
            this.zzbd = onDelegateCreatedListener;
            zzd();
        }

        private final void zzd() {
            if (!(this.zzbe == null || this.zzbd == null || getDelegate() != null)) {
                try {
                    MapsInitializer.initialize(this.zzbe);
                    IMapFragmentDelegate zzc = zzbz.zza((Context) this.zzbe).zzc(ObjectWrapper.wrap(this.zzbe));
                    if (zzc != null) {
                        this.zzbd.onDelegateCreated(new zza(this.fragment, zzc));
                        for (OnMapReadyCallback mapAsync : this.zzbf) {
                            ((zza) getDelegate()).getMapAsync(mapAsync);
                        }
                        this.zzbf.clear();
                    }
                } catch (RemoteException e) {
                    throw new RuntimeRemoteException(e);
                } catch (GooglePlayServicesNotAvailableException unused) {
                }
            }
        }

        /* access modifiers changed from: private */
        public final void setActivity(Activity activity) {
            this.zzbe = activity;
            zzd();
        }

        public final void getMapAsync(OnMapReadyCallback onMapReadyCallback) {
            if (getDelegate() != null) {
                ((zza) getDelegate()).getMapAsync(onMapReadyCallback);
            } else {
                this.zzbf.add(onMapReadyCallback);
            }
        }
    }

    public static SupportMapFragment newInstance() {
        return new SupportMapFragment();
    }

    public static SupportMapFragment newInstance(GoogleMapOptions googleMapOptions) {
        SupportMapFragment supportMapFragment = new SupportMapFragment();
        Bundle bundle = new Bundle();
        bundle.putParcelable("MapOptions", googleMapOptions);
        supportMapFragment.setArguments(bundle);
        return supportMapFragment;
    }

    public void onAttach(Activity activity) {
        super.onAttach(activity);
        this.zzch.setActivity(activity);
    }

    public void onInflate(Activity activity, AttributeSet attributeSet, Bundle bundle) {
        ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new Builder(threadPolicy).permitAll().build());
        try {
            super.onInflate(activity, attributeSet, bundle);
            this.zzch.setActivity(activity);
            GoogleMapOptions createFromAttributes = GoogleMapOptions.createFromAttributes(activity, attributeSet);
            Bundle bundle2 = new Bundle();
            bundle2.putParcelable("MapOptions", createFromAttributes);
            this.zzch.onInflate(activity, bundle2, bundle);
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.zzch.onCreate(bundle);
    }

    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        View onCreateView = this.zzch.onCreateView(layoutInflater, viewGroup, bundle);
        onCreateView.setClickable(true);
        return onCreateView;
    }

    public void onResume() {
        super.onResume();
        this.zzch.onResume();
    }

    public void onPause() {
        this.zzch.onPause();
        super.onPause();
    }

    public void onStart() {
        super.onStart();
        this.zzch.onStart();
    }

    public void onStop() {
        this.zzch.onStop();
        super.onStop();
    }

    public void onDestroyView() {
        this.zzch.onDestroyView();
        super.onDestroyView();
    }

    public void onDestroy() {
        this.zzch.onDestroy();
        super.onDestroy();
    }

    public void onLowMemory() {
        this.zzch.onLowMemory();
        super.onLowMemory();
    }

    public void onActivityCreated(Bundle bundle) {
        if (bundle != null) {
            bundle.setClassLoader(SupportMapFragment.class.getClassLoader());
        }
        super.onActivityCreated(bundle);
    }

    public void onSaveInstanceState(Bundle bundle) {
        if (bundle != null) {
            bundle.setClassLoader(SupportMapFragment.class.getClassLoader());
        }
        super.onSaveInstanceState(bundle);
        this.zzch.onSaveInstanceState(bundle);
    }

    public final void onEnterAmbient(Bundle bundle) {
        Preconditions.checkMainThread("onEnterAmbient must be called on the main thread.");
        zzb zzb2 = this.zzch;
        if (zzb2.getDelegate() != null) {
            ((zza) zzb2.getDelegate()).onEnterAmbient(bundle);
        }
    }

    public final void onExitAmbient() {
        Preconditions.checkMainThread("onExitAmbient must be called on the main thread.");
        zzb zzb2 = this.zzch;
        if (zzb2.getDelegate() != null) {
            ((zza) zzb2.getDelegate()).onExitAmbient();
        }
    }

    public void getMapAsync(OnMapReadyCallback onMapReadyCallback) {
        Preconditions.checkMainThread("getMapAsync must be called on the main thread.");
        this.zzch.getMapAsync(onMapReadyCallback);
    }

    public void setArguments(Bundle bundle) {
        super.setArguments(bundle);
    }
}
