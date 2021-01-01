package androidx.core.widget;

import android.os.Build.VERSION;
import android.view.View;
import android.widget.ListView;

public final class ListViewCompat {
    public static void scrollListBy(ListView listView, int y) {
        if (VERSION.SDK_INT >= 19) {
            listView.scrollListBy(y);
        } else {
            int firstPosition = listView.getFirstVisiblePosition();
            if (firstPosition != -1) {
                View firstView = listView.getChildAt(0);
                if (firstView != null) {
                    listView.setSelectionFromTop(firstPosition, firstView.getTop() - y);
                }
            }
        }
    }

    public static boolean canScrollList(ListView listView, int direction) {
        if (VERSION.SDK_INT >= 19) {
            return listView.canScrollList(direction);
        }
        int childCount = listView.getChildCount();
        boolean z = false;
        if (childCount == 0) {
            return false;
        }
        int firstPosition = listView.getFirstVisiblePosition();
        if (direction > 0) {
            int lastBottom = listView.getChildAt(childCount - 1).getBottom();
            if (firstPosition + childCount < listView.getCount() || lastBottom > listView.getHeight() - listView.getListPaddingBottom()) {
                z = true;
            }
            return z;
        }
        int firstTop = listView.getChildAt(0).getTop();
        if (firstPosition > 0 || firstTop < listView.getListPaddingTop()) {
            z = true;
        }
        return z;
    }

    private ListViewCompat() {
    }
}
