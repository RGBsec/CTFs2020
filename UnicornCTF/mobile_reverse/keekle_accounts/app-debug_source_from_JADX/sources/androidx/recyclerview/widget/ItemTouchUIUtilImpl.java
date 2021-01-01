package androidx.recyclerview.widget;

import android.graphics.Canvas;
import android.os.Build.VERSION;
import android.view.View;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.C0055R;

class ItemTouchUIUtilImpl implements ItemTouchUIUtil {
    static final ItemTouchUIUtil INSTANCE = new ItemTouchUIUtilImpl();

    ItemTouchUIUtilImpl() {
    }

    public void onDraw(Canvas c, RecyclerView recyclerView, View view, float dX, float dY, int actionState, boolean isCurrentlyActive) {
        if (VERSION.SDK_INT >= 21 && isCurrentlyActive && view.getTag(C0055R.C0057id.item_touch_helper_previous_elevation) == null) {
            Object originalElevation = Float.valueOf(ViewCompat.getElevation(view));
            ViewCompat.setElevation(view, findMaxElevation(recyclerView, view) + 1.0f);
            view.setTag(C0055R.C0057id.item_touch_helper_previous_elevation, originalElevation);
        }
        view.setTranslationX(dX);
        view.setTranslationY(dY);
    }

    private static float findMaxElevation(RecyclerView recyclerView, View itemView) {
        int childCount = recyclerView.getChildCount();
        float max = 0.0f;
        for (int i = 0; i < childCount; i++) {
            View child = recyclerView.getChildAt(i);
            if (child != itemView) {
                float elevation = ViewCompat.getElevation(child);
                if (elevation > max) {
                    max = elevation;
                }
            }
        }
        return max;
    }

    public void onDrawOver(Canvas c, RecyclerView recyclerView, View view, float dX, float dY, int actionState, boolean isCurrentlyActive) {
    }

    public void clearView(View view) {
        if (VERSION.SDK_INT >= 21) {
            Object tag = view.getTag(C0055R.C0057id.item_touch_helper_previous_elevation);
            if (tag != null && (tag instanceof Float)) {
                ViewCompat.setElevation(view, ((Float) tag).floatValue());
            }
            view.setTag(C0055R.C0057id.item_touch_helper_previous_elevation, null);
        }
        view.setTranslationX(0.0f);
        view.setTranslationY(0.0f);
    }

    public void onSelected(View view) {
    }
}
