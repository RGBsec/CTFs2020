package androidx.fragment.app;

import android.util.Log;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelProvider.Factory;
import androidx.lifecycle.ViewModelStore;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

class FragmentManagerViewModel extends ViewModel {
    private static final Factory FACTORY = new Factory() {
        public <T extends ViewModel> T create(Class<T> cls) {
            return new FragmentManagerViewModel(true);
        }
    };
    private final HashMap<String, FragmentManagerViewModel> mChildNonConfigs = new HashMap<>();
    private boolean mHasBeenCleared = false;
    private boolean mHasSavedSnapshot = false;
    private final HashSet<Fragment> mRetainedFragments = new HashSet<>();
    private final boolean mStateAutomaticallySaved;
    private final HashMap<String, ViewModelStore> mViewModelStores = new HashMap<>();

    static FragmentManagerViewModel getInstance(ViewModelStore viewModelStore) {
        return (FragmentManagerViewModel) new ViewModelProvider(viewModelStore, FACTORY).get(FragmentManagerViewModel.class);
    }

    FragmentManagerViewModel(boolean stateAutomaticallySaved) {
        this.mStateAutomaticallySaved = stateAutomaticallySaved;
    }

    /* access modifiers changed from: protected */
    public void onCleared() {
        if (FragmentManagerImpl.DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("onCleared called for ");
            sb.append(this);
            Log.d("FragmentManager", sb.toString());
        }
        this.mHasBeenCleared = true;
    }

    /* access modifiers changed from: 0000 */
    public boolean isCleared() {
        return this.mHasBeenCleared;
    }

    /* access modifiers changed from: 0000 */
    public boolean addRetainedFragment(Fragment fragment) {
        return this.mRetainedFragments.add(fragment);
    }

    /* access modifiers changed from: 0000 */
    public Collection<Fragment> getRetainedFragments() {
        return this.mRetainedFragments;
    }

    /* access modifiers changed from: 0000 */
    public boolean shouldDestroy(Fragment fragment) {
        if (!this.mRetainedFragments.contains(fragment)) {
            return true;
        }
        if (this.mStateAutomaticallySaved) {
            return this.mHasBeenCleared;
        }
        return !this.mHasSavedSnapshot;
    }

    /* access modifiers changed from: 0000 */
    public boolean removeRetainedFragment(Fragment fragment) {
        return this.mRetainedFragments.remove(fragment);
    }

    /* access modifiers changed from: 0000 */
    public FragmentManagerViewModel getChildNonConfig(Fragment f) {
        FragmentManagerViewModel childNonConfig = (FragmentManagerViewModel) this.mChildNonConfigs.get(f.mWho);
        if (childNonConfig != null) {
            return childNonConfig;
        }
        FragmentManagerViewModel childNonConfig2 = new FragmentManagerViewModel(this.mStateAutomaticallySaved);
        this.mChildNonConfigs.put(f.mWho, childNonConfig2);
        return childNonConfig2;
    }

    /* access modifiers changed from: 0000 */
    public ViewModelStore getViewModelStore(Fragment f) {
        ViewModelStore viewModelStore = (ViewModelStore) this.mViewModelStores.get(f.mWho);
        if (viewModelStore != null) {
            return viewModelStore;
        }
        ViewModelStore viewModelStore2 = new ViewModelStore();
        this.mViewModelStores.put(f.mWho, viewModelStore2);
        return viewModelStore2;
    }

    /* access modifiers changed from: 0000 */
    public void clearNonConfigState(Fragment f) {
        if (FragmentManagerImpl.DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("Clearing non-config state for ");
            sb.append(f);
            Log.d("FragmentManager", sb.toString());
        }
        FragmentManagerViewModel childNonConfig = (FragmentManagerViewModel) this.mChildNonConfigs.get(f.mWho);
        if (childNonConfig != null) {
            childNonConfig.onCleared();
            this.mChildNonConfigs.remove(f.mWho);
        }
        ViewModelStore viewModelStore = (ViewModelStore) this.mViewModelStores.get(f.mWho);
        if (viewModelStore != null) {
            viewModelStore.clear();
            this.mViewModelStores.remove(f.mWho);
        }
    }

    /* access modifiers changed from: 0000 */
    @Deprecated
    public void restoreFromSnapshot(FragmentManagerNonConfig nonConfig) {
        this.mRetainedFragments.clear();
        this.mChildNonConfigs.clear();
        this.mViewModelStores.clear();
        if (nonConfig != null) {
            Collection<Fragment> fragments = nonConfig.getFragments();
            if (fragments != null) {
                this.mRetainedFragments.addAll(fragments);
            }
            Map<String, FragmentManagerNonConfig> childNonConfigs = nonConfig.getChildNonConfigs();
            if (childNonConfigs != null) {
                for (Entry<String, FragmentManagerNonConfig> entry : childNonConfigs.entrySet()) {
                    FragmentManagerViewModel childViewModel = new FragmentManagerViewModel(this.mStateAutomaticallySaved);
                    childViewModel.restoreFromSnapshot((FragmentManagerNonConfig) entry.getValue());
                    this.mChildNonConfigs.put(entry.getKey(), childViewModel);
                }
            }
            Map<String, ViewModelStore> viewModelStores = nonConfig.getViewModelStores();
            if (viewModelStores != null) {
                this.mViewModelStores.putAll(viewModelStores);
            }
        }
        this.mHasSavedSnapshot = false;
    }

    /* access modifiers changed from: 0000 */
    @Deprecated
    public FragmentManagerNonConfig getSnapshot() {
        if (this.mRetainedFragments.isEmpty() && this.mChildNonConfigs.isEmpty() && this.mViewModelStores.isEmpty()) {
            return null;
        }
        HashMap<String, FragmentManagerNonConfig> childNonConfigs = new HashMap<>();
        for (Entry<String, FragmentManagerViewModel> entry : this.mChildNonConfigs.entrySet()) {
            FragmentManagerNonConfig childNonConfig = ((FragmentManagerViewModel) entry.getValue()).getSnapshot();
            if (childNonConfig != null) {
                childNonConfigs.put(entry.getKey(), childNonConfig);
            }
        }
        this.mHasSavedSnapshot = true;
        if (!this.mRetainedFragments.isEmpty() || !childNonConfigs.isEmpty() || !this.mViewModelStores.isEmpty()) {
            return new FragmentManagerNonConfig(new ArrayList(this.mRetainedFragments), childNonConfigs, new HashMap(this.mViewModelStores));
        }
        return null;
    }

    public boolean equals(Object o) {
        boolean z = true;
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FragmentManagerViewModel that = (FragmentManagerViewModel) o;
        if (!this.mRetainedFragments.equals(that.mRetainedFragments) || !this.mChildNonConfigs.equals(that.mChildNonConfigs) || !this.mViewModelStores.equals(that.mViewModelStores)) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        return (((this.mRetainedFragments.hashCode() * 31) + this.mChildNonConfigs.hashCode()) * 31) + this.mViewModelStores.hashCode();
    }

    public String toString() {
        String str;
        StringBuilder sb = new StringBuilder("FragmentManagerViewModel{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("} Fragments (");
        Iterator<Fragment> fragmentIterator = this.mRetainedFragments.iterator();
        while (true) {
            str = ", ";
            if (!fragmentIterator.hasNext()) {
                break;
            }
            sb.append(fragmentIterator.next());
            if (fragmentIterator.hasNext()) {
                sb.append(str);
            }
        }
        sb.append(") Child Non Config (");
        Iterator<String> childNonConfigIterator = this.mChildNonConfigs.keySet().iterator();
        while (childNonConfigIterator.hasNext()) {
            sb.append((String) childNonConfigIterator.next());
            if (childNonConfigIterator.hasNext()) {
                sb.append(str);
            }
        }
        sb.append(") ViewModelStores (");
        Iterator<String> viewModelStoreIterator = this.mViewModelStores.keySet().iterator();
        while (viewModelStoreIterator.hasNext()) {
            sb.append((String) viewModelStoreIterator.next());
            if (viewModelStoreIterator.hasNext()) {
                sb.append(str);
            }
        }
        sb.append(')');
        return sb.toString();
    }
}
