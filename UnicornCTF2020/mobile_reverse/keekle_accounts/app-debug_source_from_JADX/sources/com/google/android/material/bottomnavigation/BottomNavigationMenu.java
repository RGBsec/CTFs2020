package com.google.android.material.bottomnavigation;

import android.content.Context;
import android.view.MenuItem;
import android.view.SubMenu;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuItemImpl;

public final class BottomNavigationMenu extends MenuBuilder {
    public static final int MAX_ITEM_COUNT = 5;

    public BottomNavigationMenu(Context context) {
        super(context);
    }

    public SubMenu addSubMenu(int group, int id, int categoryOrder, CharSequence title) {
        throw new UnsupportedOperationException("BottomNavigationView does not support submenus");
    }

    /* access modifiers changed from: protected */
    public MenuItem addInternal(int group, int id, int categoryOrder, CharSequence title) {
        if (size() + 1 <= 5) {
            stopDispatchingItemsChanged();
            MenuItem item = super.addInternal(group, id, categoryOrder, title);
            if (item instanceof MenuItemImpl) {
                ((MenuItemImpl) item).setExclusiveCheckable(true);
            }
            startDispatchingItemsChanged();
            return item;
        }
        throw new IllegalArgumentException("Maximum number of items supported by BottomNavigationView is 5. Limit can be checked with BottomNavigationView#getMaxItemCount()");
    }
}
