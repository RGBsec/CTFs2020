package androidx.transition;

import android.view.View;
import android.view.ViewGroup;

interface GhostViewImpl {
    void reserveEndViewTransition(ViewGroup viewGroup, View view);

    void setVisibility(int i);
}
