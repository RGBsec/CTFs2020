package androidx.lifecycle;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class ViewModelStore {
    private final HashMap<String, ViewModel> mMap = new HashMap<>();

    /* access modifiers changed from: 0000 */
    public final void put(String key, ViewModel viewModel) {
        ViewModel oldViewModel = (ViewModel) this.mMap.put(key, viewModel);
        if (oldViewModel != null) {
            oldViewModel.onCleared();
        }
    }

    /* access modifiers changed from: 0000 */
    public final ViewModel get(String key) {
        return (ViewModel) this.mMap.get(key);
    }

    /* access modifiers changed from: 0000 */
    public Set<String> keys() {
        return new HashSet(this.mMap.keySet());
    }

    public final void clear() {
        for (ViewModel vm : this.mMap.values()) {
            vm.clear();
        }
        this.mMap.clear();
    }
}
