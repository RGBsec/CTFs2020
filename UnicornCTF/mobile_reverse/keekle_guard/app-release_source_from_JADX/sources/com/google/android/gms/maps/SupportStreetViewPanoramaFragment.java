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
import com.google.android.gms.maps.internal.IStreetViewPanoramaFragmentDelegate;
import com.google.android.gms.maps.internal.StreetViewLifecycleDelegate;
import com.google.android.gms.maps.internal.zzby;
import com.google.android.gms.maps.internal.zzbz;
import com.google.android.gms.maps.model.RuntimeRemoteException;
import java.util.ArrayList;
import java.util.List;

public class SupportStreetViewPanoramaFragment extends Fragment {
    private final zzb zzci = new zzb(this);

    static class zza implements StreetViewLifecycleDelegate {
        private final Fragment fragment;
        private final IStreetViewPanoramaFragmentDelegate zzbu;

        public zza(Fragment fragment2, IStreetViewPanoramaFragmentDelegate iStreetViewPanoramaFragmentDelegate) {
            this.zzbu = (IStreetViewPanoramaFragmentDelegate) Preconditions.checkNotNull(iStreetViewPanoramaFragmentDelegate);
            this.fragment = (Fragment) Preconditions.checkNotNull(fragment2);
        }

        public final void onInflate(Activity activity, Bundle bundle, Bundle bundle2) {
            try {
                Bundle bundle3 = new Bundle();
                zzby.zza(bundle2, bundle3);
                this.zzbu.onInflate(ObjectWrapper.wrap(activity), null, bundle3);
                zzby.zza(bundle3, bundle2);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onCreate(Bundle bundle) {
            String str = "StreetViewPanoramaOptions";
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                Bundle arguments = this.fragment.getArguments();
                if (arguments != null && arguments.containsKey(str)) {
                    zzby.zza(bundle2, str, arguments.getParcelable(str));
                }
                this.zzbu.onCreate(bundle2);
                zzby.zza(bundle2, bundle);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                IObjectWrapper onCreateView = this.zzbu.onCreateView(ObjectWrapper.wrap(layoutInflater), ObjectWrapper.wrap(viewGroup), bundle2);
                zzby.zza(bundle2, bundle);
                return (View) ObjectWrapper.unwrap(onCreateView);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onStart() {
            try {
                this.zzbu.onStart();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onResume() {
            try {
                this.zzbu.onResume();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onPause() {
            try {
                this.zzbu.onPause();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onStop() {
            try {
                this.zzbu.onStop();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onDestroyView() {
            try {
                this.zzbu.onDestroyView();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onDestroy() {
            try {
                this.zzbu.onDestroy();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onLowMemory() {
            try {
                this.zzbu.onLowMemory();
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void onSaveInstanceState(Bundle bundle) {
            try {
                Bundle bundle2 = new Bundle();
                zzby.zza(bundle, bundle2);
                this.zzbu.onSaveInstanceState(bundle2);
                zzby.zza(bundle2, bundle);
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }

        public final void getStreetViewPanoramaAsync(OnStreetViewPanoramaReadyCallback onStreetViewPanoramaReadyCallback) {
            try {
                this.zzbu.getStreetViewPanoramaAsync(new zzal(this, onStreetViewPanoramaReadyCallback));
            } catch (RemoteException e) {
                throw new RuntimeRemoteException(e);
            }
        }
    }

    static class zzb extends DeferredLifecycleHelper<zza> {
        private final Fragment fragment;
        private OnDelegateCreatedListener<zza> zzbd;
        private Activity zzbe;
        private final List<OnStreetViewPanoramaReadyCallback> zzbw = new ArrayList();

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
                    this.zzbd.onDelegateCreated(new zza(this.fragment, zzbz.zza((Context) this.zzbe).zzd(ObjectWrapper.wrap(this.zzbe))));
                    for (OnStreetViewPanoramaReadyCallback streetViewPanoramaAsync : this.zzbw) {
                        ((zza) getDelegate()).getStreetViewPanoramaAsync(streetViewPanoramaAsync);
                    }
                    this.zzbw.clear();
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

        public final void getStreetViewPanoramaAsync(OnStreetViewPanoramaReadyCallback onStreetViewPanoramaReadyCallback) {
            if (getDelegate() != null) {
                ((zza) getDelegate()).getStreetViewPanoramaAsync(onStreetViewPanoramaReadyCallback);
            } else {
                this.zzbw.add(onStreetViewPanoramaReadyCallback);
            }
        }
    }

    public static SupportStreetViewPanoramaFragment newInstance() {
        return new SupportStreetViewPanoramaFragment();
    }

    public static SupportStreetViewPanoramaFragment newInstance(StreetViewPanoramaOptions streetViewPanoramaOptions) {
        SupportStreetViewPanoramaFragment supportStreetViewPanoramaFragment = new SupportStreetViewPanoramaFragment();
        Bundle bundle = new Bundle();
        bundle.putParcelable("StreetViewPanoramaOptions", streetViewPanoramaOptions);
        supportStreetViewPanoramaFragment.setArguments(bundle);
        return supportStreetViewPanoramaFragment;
    }

    public void onAttach(Activity activity) {
        super.onAttach(activity);
        this.zzci.setActivity(activity);
    }

    public void onInflate(Activity activity, AttributeSet attributeSet, Bundle bundle) {
        ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new Builder(threadPolicy).permitAll().build());
        try {
            super.onInflate(activity, attributeSet, bundle);
            this.zzci.setActivity(activity);
            this.zzci.onInflate(activity, new Bundle(), bundle);
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.zzci.onCreate(bundle);
    }

    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        return this.zzci.onCreateView(layoutInflater, viewGroup, bundle);
    }

    public void onStart() {
        super.onStart();
        this.zzci.onStart();
    }

    public void onResume() {
        super.onResume();
        this.zzci.onResume();
    }

    public void onPause() {
        this.zzci.onPause();
        super.onPause();
    }

    public void onStop() {
        this.zzci.onStop();
        super.onStop();
    }

    public void onDestroyView() {
        this.zzci.onDestroyView();
        super.onDestroyView();
    }

    public void onDestroy() {
        this.zzci.onDestroy();
        super.onDestroy();
    }

    public void onLowMemory() {
        this.zzci.onLowMemory();
        super.onLowMemory();
    }

    public void onActivityCreated(Bundle bundle) {
        if (bundle != null) {
            bundle.setClassLoader(SupportStreetViewPanoramaFragment.class.getClassLoader());
        }
        super.onActivityCreated(bundle);
    }

    public void onSaveInstanceState(Bundle bundle) {
        if (bundle != null) {
            bundle.setClassLoader(SupportStreetViewPanoramaFragment.class.getClassLoader());
        }
        super.onSaveInstanceState(bundle);
        this.zzci.onSaveInstanceState(bundle);
    }

    public void setArguments(Bundle bundle) {
        super.setArguments(bundle);
    }

    public void getStreetViewPanoramaAsync(OnStreetViewPanoramaReadyCallback onStreetViewPanoramaReadyCallback) {
        Preconditions.checkMainThread("getStreetViewPanoramaAsync() must be called on the main thread");
        this.zzci.getStreetViewPanoramaAsync(onStreetViewPanoramaReadyCallback);
    }
}
