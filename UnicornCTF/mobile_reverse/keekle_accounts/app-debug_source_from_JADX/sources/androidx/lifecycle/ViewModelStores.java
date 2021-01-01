package androidx.lifecycle;

import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

@Deprecated
public class ViewModelStores {
    private ViewModelStores() {
    }

    @Deprecated
    /* renamed from: of */
    public static ViewModelStore m13of(FragmentActivity activity) {
        return activity.getViewModelStore();
    }

    @Deprecated
    /* renamed from: of */
    public static ViewModelStore m12of(Fragment fragment) {
        return fragment.getViewModelStore();
    }
}
