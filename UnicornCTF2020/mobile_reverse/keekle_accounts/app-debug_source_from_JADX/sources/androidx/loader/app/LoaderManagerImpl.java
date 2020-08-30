package androidx.loader.app;

import android.os.Bundle;
import android.os.Looper;
import android.util.Log;
import androidx.collection.SparseArrayCompat;
import androidx.core.util.DebugUtils;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelProvider.Factory;
import androidx.lifecycle.ViewModelStore;
import androidx.loader.app.LoaderManager.LoaderCallbacks;
import androidx.loader.content.Loader;
import androidx.loader.content.Loader.OnLoadCompleteListener;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.Modifier;

class LoaderManagerImpl extends LoaderManager {
    static boolean DEBUG = false;
    static final String TAG = "LoaderManager";
    private final LifecycleOwner mLifecycleOwner;
    private final LoaderViewModel mLoaderViewModel;

    public static class LoaderInfo<D> extends MutableLiveData<D> implements OnLoadCompleteListener<D> {
        private final Bundle mArgs;
        private final int mId;
        private LifecycleOwner mLifecycleOwner;
        private final Loader<D> mLoader;
        private LoaderObserver<D> mObserver;
        private Loader<D> mPriorLoader;

        LoaderInfo(int id, Bundle args, Loader<D> loader, Loader<D> priorLoader) {
            this.mId = id;
            this.mArgs = args;
            this.mLoader = loader;
            this.mPriorLoader = priorLoader;
            loader.registerListener(id, this);
        }

        /* access modifiers changed from: 0000 */
        public Loader<D> getLoader() {
            return this.mLoader;
        }

        /* access modifiers changed from: protected */
        public void onActive() {
            if (LoaderManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("  Starting: ");
                sb.append(this);
                Log.v(LoaderManagerImpl.TAG, sb.toString());
            }
            this.mLoader.startLoading();
        }

        /* access modifiers changed from: protected */
        public void onInactive() {
            if (LoaderManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("  Stopping: ");
                sb.append(this);
                Log.v(LoaderManagerImpl.TAG, sb.toString());
            }
            this.mLoader.stopLoading();
        }

        /* access modifiers changed from: 0000 */
        public Loader<D> setCallback(LifecycleOwner owner, LoaderCallbacks<D> callback) {
            LoaderObserver<D> observer = new LoaderObserver<>(this.mLoader, callback);
            observe(owner, observer);
            LoaderObserver<D> loaderObserver = this.mObserver;
            if (loaderObserver != null) {
                removeObserver(loaderObserver);
            }
            this.mLifecycleOwner = owner;
            this.mObserver = observer;
            return this.mLoader;
        }

        /* access modifiers changed from: 0000 */
        public void markForRedelivery() {
            LifecycleOwner lifecycleOwner = this.mLifecycleOwner;
            LoaderObserver<D> observer = this.mObserver;
            if (lifecycleOwner != null && observer != null) {
                super.removeObserver(observer);
                observe(lifecycleOwner, observer);
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean isCallbackWaitingForData() {
            boolean z = false;
            if (!hasActiveObservers()) {
                return false;
            }
            LoaderObserver<D> loaderObserver = this.mObserver;
            if (loaderObserver != null && !loaderObserver.hasDeliveredData()) {
                z = true;
            }
            return z;
        }

        public void removeObserver(Observer<? super D> observer) {
            super.removeObserver(observer);
            this.mLifecycleOwner = null;
            this.mObserver = null;
        }

        /* access modifiers changed from: 0000 */
        public Loader<D> destroy(boolean reset) {
            if (LoaderManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("  Destroying: ");
                sb.append(this);
                Log.v(LoaderManagerImpl.TAG, sb.toString());
            }
            this.mLoader.cancelLoad();
            this.mLoader.abandon();
            LoaderObserver<D> observer = this.mObserver;
            if (observer != null) {
                removeObserver(observer);
                if (reset) {
                    observer.reset();
                }
            }
            this.mLoader.unregisterListener(this);
            if ((observer == null || observer.hasDeliveredData()) && !reset) {
                return this.mLoader;
            }
            this.mLoader.reset();
            return this.mPriorLoader;
        }

        public void onLoadComplete(Loader<D> loader, D data) {
            boolean z = LoaderManagerImpl.DEBUG;
            String str = LoaderManagerImpl.TAG;
            if (z) {
                StringBuilder sb = new StringBuilder();
                sb.append("onLoadComplete: ");
                sb.append(this);
                Log.v(str, sb.toString());
            }
            if (Looper.myLooper() == Looper.getMainLooper()) {
                setValue(data);
                return;
            }
            if (LoaderManagerImpl.DEBUG) {
                Log.w(str, "onLoadComplete was incorrectly called on a background thread");
            }
            postValue(data);
        }

        public void setValue(D value) {
            super.setValue(value);
            Loader<D> loader = this.mPriorLoader;
            if (loader != null) {
                loader.reset();
                this.mPriorLoader = null;
            }
        }

        public String toString() {
            StringBuilder sb = new StringBuilder(64);
            sb.append("LoaderInfo{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" #");
            sb.append(this.mId);
            sb.append(" : ");
            DebugUtils.buildShortClassTag(this.mLoader, sb);
            sb.append("}}");
            return sb.toString();
        }

        public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
            writer.print(prefix);
            writer.print("mId=");
            writer.print(this.mId);
            writer.print(" mArgs=");
            writer.println(this.mArgs);
            writer.print(prefix);
            writer.print("mLoader=");
            writer.println(this.mLoader);
            Loader<D> loader = this.mLoader;
            StringBuilder sb = new StringBuilder();
            sb.append(prefix);
            String str = "  ";
            sb.append(str);
            loader.dump(sb.toString(), fd, writer, args);
            if (this.mObserver != null) {
                writer.print(prefix);
                writer.print("mCallbacks=");
                writer.println(this.mObserver);
                LoaderObserver<D> loaderObserver = this.mObserver;
                StringBuilder sb2 = new StringBuilder();
                sb2.append(prefix);
                sb2.append(str);
                loaderObserver.dump(sb2.toString(), writer);
            }
            writer.print(prefix);
            writer.print("mData=");
            writer.println(getLoader().dataToString(getValue()));
            writer.print(prefix);
            writer.print("mStarted=");
            writer.println(hasActiveObservers());
        }
    }

    static class LoaderObserver<D> implements Observer<D> {
        private final LoaderCallbacks<D> mCallback;
        private boolean mDeliveredData = false;
        private final Loader<D> mLoader;

        LoaderObserver(Loader<D> loader, LoaderCallbacks<D> callback) {
            this.mLoader = loader;
            this.mCallback = callback;
        }

        public void onChanged(D data) {
            if (LoaderManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("  onLoadFinished in ");
                sb.append(this.mLoader);
                sb.append(": ");
                sb.append(this.mLoader.dataToString(data));
                Log.v(LoaderManagerImpl.TAG, sb.toString());
            }
            this.mCallback.onLoadFinished(this.mLoader, data);
            this.mDeliveredData = true;
        }

        /* access modifiers changed from: 0000 */
        public boolean hasDeliveredData() {
            return this.mDeliveredData;
        }

        /* access modifiers changed from: 0000 */
        public void reset() {
            if (this.mDeliveredData) {
                if (LoaderManagerImpl.DEBUG) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("  Resetting: ");
                    sb.append(this.mLoader);
                    Log.v(LoaderManagerImpl.TAG, sb.toString());
                }
                this.mCallback.onLoaderReset(this.mLoader);
            }
        }

        public String toString() {
            return this.mCallback.toString();
        }

        public void dump(String prefix, PrintWriter writer) {
            writer.print(prefix);
            writer.print("mDeliveredData=");
            writer.println(this.mDeliveredData);
        }
    }

    static class LoaderViewModel extends ViewModel {
        private static final Factory FACTORY = new Factory() {
            public <T extends ViewModel> T create(Class<T> cls) {
                return new LoaderViewModel();
            }
        };
        private boolean mCreatingLoader = false;
        private SparseArrayCompat<LoaderInfo> mLoaders = new SparseArrayCompat<>();

        LoaderViewModel() {
        }

        static LoaderViewModel getInstance(ViewModelStore viewModelStore) {
            return (LoaderViewModel) new ViewModelProvider(viewModelStore, FACTORY).get(LoaderViewModel.class);
        }

        /* access modifiers changed from: 0000 */
        public void startCreatingLoader() {
            this.mCreatingLoader = true;
        }

        /* access modifiers changed from: 0000 */
        public boolean isCreatingLoader() {
            return this.mCreatingLoader;
        }

        /* access modifiers changed from: 0000 */
        public void finishCreatingLoader() {
            this.mCreatingLoader = false;
        }

        /* access modifiers changed from: 0000 */
        public void putLoader(int id, LoaderInfo info) {
            this.mLoaders.put(id, info);
        }

        /* access modifiers changed from: 0000 */
        public <D> LoaderInfo<D> getLoader(int id) {
            return (LoaderInfo) this.mLoaders.get(id);
        }

        /* access modifiers changed from: 0000 */
        public void removeLoader(int id) {
            this.mLoaders.remove(id);
        }

        /* access modifiers changed from: 0000 */
        public boolean hasRunningLoaders() {
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                if (((LoaderInfo) this.mLoaders.valueAt(index)).isCallbackWaitingForData()) {
                    return true;
                }
            }
            return false;
        }

        /* access modifiers changed from: 0000 */
        public void markForRedelivery() {
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                ((LoaderInfo) this.mLoaders.valueAt(index)).markForRedelivery();
            }
        }

        /* access modifiers changed from: protected */
        public void onCleared() {
            super.onCleared();
            int size = this.mLoaders.size();
            for (int index = 0; index < size; index++) {
                ((LoaderInfo) this.mLoaders.valueAt(index)).destroy(true);
            }
            this.mLoaders.clear();
        }

        public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
            if (this.mLoaders.size() > 0) {
                writer.print(prefix);
                writer.println("Loaders:");
                StringBuilder sb = new StringBuilder();
                sb.append(prefix);
                sb.append("    ");
                String innerPrefix = sb.toString();
                for (int i = 0; i < this.mLoaders.size(); i++) {
                    LoaderInfo info = (LoaderInfo) this.mLoaders.valueAt(i);
                    writer.print(prefix);
                    writer.print("  #");
                    writer.print(this.mLoaders.keyAt(i));
                    writer.print(": ");
                    writer.println(info.toString());
                    info.dump(innerPrefix, fd, writer, args);
                }
            }
        }
    }

    LoaderManagerImpl(LifecycleOwner lifecycleOwner, ViewModelStore viewModelStore) {
        this.mLifecycleOwner = lifecycleOwner;
        this.mLoaderViewModel = LoaderViewModel.getInstance(viewModelStore);
    }

    private <D> Loader<D> createAndInstallLoader(int id, Bundle args, LoaderCallbacks<D> callback, Loader<D> priorLoader) {
        try {
            this.mLoaderViewModel.startCreatingLoader();
            Loader<D> loader = callback.onCreateLoader(id, args);
            if (loader != null) {
                if (loader.getClass().isMemberClass()) {
                    if (!Modifier.isStatic(loader.getClass().getModifiers())) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Object returned from onCreateLoader must not be a non-static inner member class: ");
                        sb.append(loader);
                        throw new IllegalArgumentException(sb.toString());
                    }
                }
                LoaderInfo loaderInfo = new LoaderInfo(id, args, loader, priorLoader);
                try {
                    if (DEBUG) {
                        String str = TAG;
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("  Created new loader ");
                        sb2.append(loaderInfo);
                        Log.v(str, sb2.toString());
                    }
                    this.mLoaderViewModel.putLoader(id, loaderInfo);
                    this.mLoaderViewModel.finishCreatingLoader();
                    return loaderInfo.setCallback(this.mLifecycleOwner, callback);
                } catch (Throwable th) {
                    th = th;
                    this.mLoaderViewModel.finishCreatingLoader();
                    throw th;
                }
            } else {
                throw new IllegalArgumentException("Object returned from onCreateLoader must not be null");
            }
        } catch (Throwable th2) {
            th = th2;
            this.mLoaderViewModel.finishCreatingLoader();
            throw th;
        }
    }

    public <D> Loader<D> initLoader(int id, Bundle args, LoaderCallbacks<D> callback) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        } else if (Looper.getMainLooper() == Looper.myLooper()) {
            LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
            boolean z = DEBUG;
            String str = TAG;
            if (z) {
                StringBuilder sb = new StringBuilder();
                sb.append("initLoader in ");
                sb.append(this);
                sb.append(": args=");
                sb.append(args);
                Log.v(str, sb.toString());
            }
            if (info == null) {
                return createAndInstallLoader(id, args, callback, null);
            }
            if (DEBUG) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("  Re-using existing loader ");
                sb2.append(info);
                Log.v(str, sb2.toString());
            }
            return info.setCallback(this.mLifecycleOwner, callback);
        } else {
            throw new IllegalStateException("initLoader must be called on the main thread");
        }
    }

    public <D> Loader<D> restartLoader(int id, Bundle args, LoaderCallbacks<D> callback) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        } else if (Looper.getMainLooper() == Looper.myLooper()) {
            if (DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("restartLoader in ");
                sb.append(this);
                sb.append(": args=");
                sb.append(args);
                Log.v(TAG, sb.toString());
            }
            LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
            Loader<D> priorLoader = null;
            if (info != null) {
                priorLoader = info.destroy(false);
            }
            return createAndInstallLoader(id, args, callback, priorLoader);
        } else {
            throw new IllegalStateException("restartLoader must be called on the main thread");
        }
    }

    public void destroyLoader(int id) {
        if (this.mLoaderViewModel.isCreatingLoader()) {
            throw new IllegalStateException("Called while creating a loader");
        } else if (Looper.getMainLooper() == Looper.myLooper()) {
            if (DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("destroyLoader in ");
                sb.append(this);
                sb.append(" of ");
                sb.append(id);
                Log.v(TAG, sb.toString());
            }
            LoaderInfo info = this.mLoaderViewModel.getLoader(id);
            if (info != null) {
                info.destroy(true);
                this.mLoaderViewModel.removeLoader(id);
            }
        } else {
            throw new IllegalStateException("destroyLoader must be called on the main thread");
        }
    }

    public <D> Loader<D> getLoader(int id) {
        if (!this.mLoaderViewModel.isCreatingLoader()) {
            LoaderInfo<D> info = this.mLoaderViewModel.getLoader(id);
            if (info != null) {
                return info.getLoader();
            }
            return null;
        }
        throw new IllegalStateException("Called while creating a loader");
    }

    public void markForRedelivery() {
        this.mLoaderViewModel.markForRedelivery();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("LoaderManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        DebugUtils.buildShortClassTag(this.mLifecycleOwner, sb);
        sb.append("}}");
        return sb.toString();
    }

    @Deprecated
    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        this.mLoaderViewModel.dump(prefix, fd, writer, args);
    }

    public boolean hasRunningLoaders() {
        return this.mLoaderViewModel.hasRunningLoaders();
    }
}
