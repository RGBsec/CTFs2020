package com.google.android.material.internal;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.SubMenu;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuItemImpl;
import androidx.appcompat.view.menu.MenuPresenter;
import androidx.appcompat.view.menu.MenuPresenter.Callback;
import androidx.appcompat.view.menu.MenuView;
import androidx.appcompat.view.menu.SubMenuBuilder;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.RecyclerView.Adapter;
import com.google.android.material.C0078R;
import java.util.ArrayList;

public class NavigationMenuPresenter implements MenuPresenter {
    private static final String STATE_ADAPTER = "android:menu:adapter";
    private static final String STATE_HEADER = "android:menu:header";
    private static final String STATE_HIERARCHY = "android:menu:list";
    NavigationMenuAdapter adapter;
    private Callback callback;
    LinearLayout headerLayout;
    ColorStateList iconTintList;

    /* renamed from: id */
    private int f50id;
    Drawable itemBackground;
    int itemHorizontalPadding;
    int itemIconPadding;
    LayoutInflater layoutInflater;
    MenuBuilder menu;
    private NavigationMenuView menuView;
    final OnClickListener onClickListener = new OnClickListener() {
        public void onClick(View v) {
            NavigationMenuItemView itemView = (NavigationMenuItemView) v;
            NavigationMenuPresenter.this.setUpdateSuspended(true);
            MenuItemImpl item = itemView.getItemData();
            boolean result = NavigationMenuPresenter.this.menu.performItemAction(item, NavigationMenuPresenter.this, 0);
            if (item != null && item.isCheckable() && result) {
                NavigationMenuPresenter.this.adapter.setCheckedItem(item);
            }
            NavigationMenuPresenter.this.setUpdateSuspended(false);
            NavigationMenuPresenter.this.updateMenuView(false);
        }
    };
    int paddingSeparator;
    private int paddingTopDefault;
    int textAppearance;
    boolean textAppearanceSet;
    ColorStateList textColor;

    private static class HeaderViewHolder extends ViewHolder {
        public HeaderViewHolder(View itemView) {
            super(itemView);
        }
    }

    private class NavigationMenuAdapter extends Adapter<ViewHolder> {
        private static final String STATE_ACTION_VIEWS = "android:menu:action_views";
        private static final String STATE_CHECKED_ITEM = "android:menu:checked";
        private static final int VIEW_TYPE_HEADER = 3;
        private static final int VIEW_TYPE_NORMAL = 0;
        private static final int VIEW_TYPE_SEPARATOR = 2;
        private static final int VIEW_TYPE_SUBHEADER = 1;
        private MenuItemImpl checkedItem;
        private final ArrayList<NavigationMenuItem> items = new ArrayList<>();
        private boolean updateSuspended;

        NavigationMenuAdapter() {
            prepareMenuItems();
        }

        public long getItemId(int position) {
            return (long) position;
        }

        public int getItemCount() {
            return this.items.size();
        }

        public int getItemViewType(int position) {
            NavigationMenuItem item = (NavigationMenuItem) this.items.get(position);
            if (item instanceof NavigationMenuSeparatorItem) {
                return 2;
            }
            if (item instanceof NavigationMenuHeaderItem) {
                return 3;
            }
            if (!(item instanceof NavigationMenuTextItem)) {
                throw new RuntimeException("Unknown item type.");
            } else if (((NavigationMenuTextItem) item).getMenuItem().hasSubMenu()) {
                return 1;
            } else {
                return 0;
            }
        }

        public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                return new NormalViewHolder(NavigationMenuPresenter.this.layoutInflater, parent, NavigationMenuPresenter.this.onClickListener);
            }
            if (viewType == 1) {
                return new SubheaderViewHolder(NavigationMenuPresenter.this.layoutInflater, parent);
            }
            if (viewType == 2) {
                return new SeparatorViewHolder(NavigationMenuPresenter.this.layoutInflater, parent);
            }
            if (viewType != 3) {
                return null;
            }
            return new HeaderViewHolder(NavigationMenuPresenter.this.headerLayout);
        }

        public void onBindViewHolder(ViewHolder holder, int position) {
            int itemViewType = getItemViewType(position);
            if (itemViewType == 0) {
                NavigationMenuItemView itemView = (NavigationMenuItemView) holder.itemView;
                itemView.setIconTintList(NavigationMenuPresenter.this.iconTintList);
                if (NavigationMenuPresenter.this.textAppearanceSet) {
                    itemView.setTextAppearance(NavigationMenuPresenter.this.textAppearance);
                }
                if (NavigationMenuPresenter.this.textColor != null) {
                    itemView.setTextColor(NavigationMenuPresenter.this.textColor);
                }
                ViewCompat.setBackground(itemView, NavigationMenuPresenter.this.itemBackground != null ? NavigationMenuPresenter.this.itemBackground.getConstantState().newDrawable() : null);
                NavigationMenuTextItem item = (NavigationMenuTextItem) this.items.get(position);
                itemView.setNeedsEmptyIcon(item.needsEmptyIcon);
                itemView.setHorizontalPadding(NavigationMenuPresenter.this.itemHorizontalPadding);
                itemView.setIconPadding(NavigationMenuPresenter.this.itemIconPadding);
                itemView.initialize(item.getMenuItem(), 0);
            } else if (itemViewType == 1) {
                ((TextView) holder.itemView).setText(((NavigationMenuTextItem) this.items.get(position)).getMenuItem().getTitle());
            } else if (itemViewType == 2) {
                NavigationMenuSeparatorItem item2 = (NavigationMenuSeparatorItem) this.items.get(position);
                holder.itemView.setPadding(0, item2.getPaddingTop(), 0, item2.getPaddingBottom());
            }
        }

        public void onViewRecycled(ViewHolder holder) {
            if (holder instanceof NormalViewHolder) {
                ((NavigationMenuItemView) holder.itemView).recycle();
            }
        }

        public void update() {
            prepareMenuItems();
            notifyDataSetChanged();
        }

        private void prepareMenuItems() {
            if (!this.updateSuspended) {
                this.updateSuspended = true;
                this.items.clear();
                this.items.add(new NavigationMenuHeaderItem());
                int currentGroupId = -1;
                int currentGroupStart = 0;
                boolean currentGroupHasIcon = false;
                int i = 0;
                int totalSize = NavigationMenuPresenter.this.menu.getVisibleItems().size();
                while (true) {
                    boolean z = false;
                    if (i < totalSize) {
                        MenuItemImpl item = (MenuItemImpl) NavigationMenuPresenter.this.menu.getVisibleItems().get(i);
                        if (item.isChecked()) {
                            setCheckedItem(item);
                        }
                        if (item.isCheckable()) {
                            item.setExclusiveCheckable(false);
                        }
                        if (item.hasSubMenu()) {
                            SubMenu subMenu = item.getSubMenu();
                            if (subMenu.hasVisibleItems()) {
                                if (i != 0) {
                                    this.items.add(new NavigationMenuSeparatorItem(NavigationMenuPresenter.this.paddingSeparator, 0));
                                }
                                this.items.add(new NavigationMenuTextItem(item));
                                boolean subMenuHasIcon = false;
                                int subMenuStart = this.items.size();
                                int size = subMenu.size();
                                for (int j = 0; j < size; j++) {
                                    MenuItemImpl subMenuItem = (MenuItemImpl) subMenu.getItem(j);
                                    if (subMenuItem.isVisible()) {
                                        if (!subMenuHasIcon && subMenuItem.getIcon() != null) {
                                            subMenuHasIcon = true;
                                        }
                                        if (subMenuItem.isCheckable()) {
                                            subMenuItem.setExclusiveCheckable(false);
                                        }
                                        if (item.isChecked()) {
                                            setCheckedItem(item);
                                        }
                                        this.items.add(new NavigationMenuTextItem(subMenuItem));
                                    }
                                }
                                if (subMenuHasIcon) {
                                    appendTransparentIconIfMissing(subMenuStart, this.items.size());
                                }
                            }
                        } else {
                            int groupId = item.getGroupId();
                            if (groupId != currentGroupId) {
                                currentGroupStart = this.items.size();
                                if (item.getIcon() != null) {
                                    z = true;
                                }
                                currentGroupHasIcon = z;
                                if (i != 0) {
                                    currentGroupStart++;
                                    this.items.add(new NavigationMenuSeparatorItem(NavigationMenuPresenter.this.paddingSeparator, NavigationMenuPresenter.this.paddingSeparator));
                                }
                            } else if (!currentGroupHasIcon && item.getIcon() != null) {
                                currentGroupHasIcon = true;
                                appendTransparentIconIfMissing(currentGroupStart, this.items.size());
                            }
                            NavigationMenuTextItem textItem = new NavigationMenuTextItem(item);
                            textItem.needsEmptyIcon = currentGroupHasIcon;
                            this.items.add(textItem);
                            currentGroupId = groupId;
                        }
                        i++;
                    } else {
                        this.updateSuspended = false;
                        return;
                    }
                }
            }
        }

        private void appendTransparentIconIfMissing(int startIndex, int endIndex) {
            for (int i = startIndex; i < endIndex; i++) {
                ((NavigationMenuTextItem) this.items.get(i)).needsEmptyIcon = true;
            }
        }

        public void setCheckedItem(MenuItemImpl checkedItem2) {
            if (this.checkedItem != checkedItem2 && checkedItem2.isCheckable()) {
                MenuItemImpl menuItemImpl = this.checkedItem;
                if (menuItemImpl != null) {
                    menuItemImpl.setChecked(false);
                }
                this.checkedItem = checkedItem2;
                checkedItem2.setChecked(true);
            }
        }

        public MenuItemImpl getCheckedItem() {
            return this.checkedItem;
        }

        public Bundle createInstanceState() {
            Bundle state = new Bundle();
            MenuItemImpl menuItemImpl = this.checkedItem;
            if (menuItemImpl != null) {
                state.putInt(STATE_CHECKED_ITEM, menuItemImpl.getItemId());
            }
            SparseArray<ParcelableSparseArray> actionViewStates = new SparseArray<>();
            int size = this.items.size();
            for (int i = 0; i < size; i++) {
                NavigationMenuItem navigationMenuItem = (NavigationMenuItem) this.items.get(i);
                if (navigationMenuItem instanceof NavigationMenuTextItem) {
                    MenuItemImpl item = ((NavigationMenuTextItem) navigationMenuItem).getMenuItem();
                    View actionView = item != null ? item.getActionView() : null;
                    if (actionView != null) {
                        ParcelableSparseArray container = new ParcelableSparseArray();
                        actionView.saveHierarchyState(container);
                        actionViewStates.put(item.getItemId(), container);
                    }
                }
            }
            state.putSparseParcelableArray(STATE_ACTION_VIEWS, actionViewStates);
            return state;
        }

        public void restoreInstanceState(Bundle state) {
            int checkedItem2 = state.getInt(STATE_CHECKED_ITEM, 0);
            if (checkedItem2 != 0) {
                this.updateSuspended = true;
                int i = 0;
                int size = this.items.size();
                while (true) {
                    if (i >= size) {
                        break;
                    }
                    NavigationMenuItem item = (NavigationMenuItem) this.items.get(i);
                    if (item instanceof NavigationMenuTextItem) {
                        MenuItemImpl menuItem = ((NavigationMenuTextItem) item).getMenuItem();
                        if (menuItem != null && menuItem.getItemId() == checkedItem2) {
                            setCheckedItem(menuItem);
                            break;
                        }
                    }
                    i++;
                }
                this.updateSuspended = false;
                prepareMenuItems();
            }
            SparseArray<ParcelableSparseArray> actionViewStates = state.getSparseParcelableArray(STATE_ACTION_VIEWS);
            if (actionViewStates != null) {
                int size2 = this.items.size();
                for (int i2 = 0; i2 < size2; i2++) {
                    NavigationMenuItem navigationMenuItem = (NavigationMenuItem) this.items.get(i2);
                    if (navigationMenuItem instanceof NavigationMenuTextItem) {
                        MenuItemImpl item2 = ((NavigationMenuTextItem) navigationMenuItem).getMenuItem();
                        if (item2 != null) {
                            View actionView = item2.getActionView();
                            if (actionView != null) {
                                ParcelableSparseArray container = (ParcelableSparseArray) actionViewStates.get(item2.getItemId());
                                if (container != null) {
                                    actionView.restoreHierarchyState(container);
                                }
                            }
                        }
                    }
                }
            }
        }

        public void setUpdateSuspended(boolean updateSuspended2) {
            this.updateSuspended = updateSuspended2;
        }
    }

    private static class NavigationMenuHeaderItem implements NavigationMenuItem {
        NavigationMenuHeaderItem() {
        }
    }

    private interface NavigationMenuItem {
    }

    private static class NavigationMenuSeparatorItem implements NavigationMenuItem {
        private final int paddingBottom;
        private final int paddingTop;

        public NavigationMenuSeparatorItem(int paddingTop2, int paddingBottom2) {
            this.paddingTop = paddingTop2;
            this.paddingBottom = paddingBottom2;
        }

        public int getPaddingTop() {
            return this.paddingTop;
        }

        public int getPaddingBottom() {
            return this.paddingBottom;
        }
    }

    private static class NavigationMenuTextItem implements NavigationMenuItem {
        private final MenuItemImpl menuItem;
        boolean needsEmptyIcon;

        NavigationMenuTextItem(MenuItemImpl item) {
            this.menuItem = item;
        }

        public MenuItemImpl getMenuItem() {
            return this.menuItem;
        }
    }

    private static class NormalViewHolder extends ViewHolder {
        public NormalViewHolder(LayoutInflater inflater, ViewGroup parent, OnClickListener listener) {
            super(inflater.inflate(C0078R.layout.design_navigation_item, parent, false));
            this.itemView.setOnClickListener(listener);
        }
    }

    private static class SeparatorViewHolder extends ViewHolder {
        public SeparatorViewHolder(LayoutInflater inflater, ViewGroup parent) {
            super(inflater.inflate(C0078R.layout.design_navigation_item_separator, parent, false));
        }
    }

    private static class SubheaderViewHolder extends ViewHolder {
        public SubheaderViewHolder(LayoutInflater inflater, ViewGroup parent) {
            super(inflater.inflate(C0078R.layout.design_navigation_item_subheader, parent, false));
        }
    }

    private static abstract class ViewHolder extends androidx.recyclerview.widget.RecyclerView.ViewHolder {
        public ViewHolder(View itemView) {
            super(itemView);
        }
    }

    public void initForMenu(Context context, MenuBuilder menu2) {
        this.layoutInflater = LayoutInflater.from(context);
        this.menu = menu2;
        this.paddingSeparator = context.getResources().getDimensionPixelOffset(C0078R.dimen.design_navigation_separator_vertical_padding);
    }

    public MenuView getMenuView(ViewGroup root) {
        if (this.menuView == null) {
            this.menuView = (NavigationMenuView) this.layoutInflater.inflate(C0078R.layout.design_navigation_menu, root, false);
            if (this.adapter == null) {
                this.adapter = new NavigationMenuAdapter();
            }
            this.headerLayout = (LinearLayout) this.layoutInflater.inflate(C0078R.layout.design_navigation_item_header, this.menuView, false);
            this.menuView.setAdapter(this.adapter);
        }
        return this.menuView;
    }

    public void updateMenuView(boolean cleared) {
        NavigationMenuAdapter navigationMenuAdapter = this.adapter;
        if (navigationMenuAdapter != null) {
            navigationMenuAdapter.update();
        }
    }

    public void setCallback(Callback cb) {
        this.callback = cb;
    }

    public boolean onSubMenuSelected(SubMenuBuilder subMenu) {
        return false;
    }

    public void onCloseMenu(MenuBuilder menu2, boolean allMenusAreClosing) {
        Callback callback2 = this.callback;
        if (callback2 != null) {
            callback2.onCloseMenu(menu2, allMenusAreClosing);
        }
    }

    public boolean flagActionItems() {
        return false;
    }

    public boolean expandItemActionView(MenuBuilder menu2, MenuItemImpl item) {
        return false;
    }

    public boolean collapseItemActionView(MenuBuilder menu2, MenuItemImpl item) {
        return false;
    }

    public int getId() {
        return this.f50id;
    }

    public void setId(int id) {
        this.f50id = id;
    }

    public Parcelable onSaveInstanceState() {
        Bundle state = new Bundle();
        if (this.menuView != null) {
            SparseArray<Parcelable> hierarchy = new SparseArray<>();
            this.menuView.saveHierarchyState(hierarchy);
            state.putSparseParcelableArray("android:menu:list", hierarchy);
        }
        NavigationMenuAdapter navigationMenuAdapter = this.adapter;
        if (navigationMenuAdapter != null) {
            state.putBundle(STATE_ADAPTER, navigationMenuAdapter.createInstanceState());
        }
        if (this.headerLayout != null) {
            SparseArray<Parcelable> header = new SparseArray<>();
            this.headerLayout.saveHierarchyState(header);
            state.putSparseParcelableArray(STATE_HEADER, header);
        }
        return state;
    }

    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof Bundle) {
            Bundle state = (Bundle) parcelable;
            SparseArray<Parcelable> hierarchy = state.getSparseParcelableArray("android:menu:list");
            if (hierarchy != null) {
                this.menuView.restoreHierarchyState(hierarchy);
            }
            Bundle adapterState = state.getBundle(STATE_ADAPTER);
            if (adapterState != null) {
                this.adapter.restoreInstanceState(adapterState);
            }
            SparseArray<Parcelable> header = state.getSparseParcelableArray(STATE_HEADER);
            if (header != null) {
                this.headerLayout.restoreHierarchyState(header);
            }
        }
    }

    public void setCheckedItem(MenuItemImpl item) {
        this.adapter.setCheckedItem(item);
    }

    public MenuItemImpl getCheckedItem() {
        return this.adapter.getCheckedItem();
    }

    public View inflateHeaderView(int res) {
        View view = this.layoutInflater.inflate(res, this.headerLayout, false);
        addHeaderView(view);
        return view;
    }

    public void addHeaderView(View view) {
        this.headerLayout.addView(view);
        NavigationMenuView navigationMenuView = this.menuView;
        navigationMenuView.setPadding(0, 0, 0, navigationMenuView.getPaddingBottom());
    }

    public void removeHeaderView(View view) {
        this.headerLayout.removeView(view);
        if (this.headerLayout.getChildCount() == 0) {
            NavigationMenuView navigationMenuView = this.menuView;
            navigationMenuView.setPadding(0, this.paddingTopDefault, 0, navigationMenuView.getPaddingBottom());
        }
    }

    public int getHeaderCount() {
        return this.headerLayout.getChildCount();
    }

    public View getHeaderView(int index) {
        return this.headerLayout.getChildAt(index);
    }

    public ColorStateList getItemTintList() {
        return this.iconTintList;
    }

    public void setItemIconTintList(ColorStateList tint) {
        this.iconTintList = tint;
        updateMenuView(false);
    }

    public ColorStateList getItemTextColor() {
        return this.textColor;
    }

    public void setItemTextColor(ColorStateList textColor2) {
        this.textColor = textColor2;
        updateMenuView(false);
    }

    public void setItemTextAppearance(int resId) {
        this.textAppearance = resId;
        this.textAppearanceSet = true;
        updateMenuView(false);
    }

    public Drawable getItemBackground() {
        return this.itemBackground;
    }

    public void setItemBackground(Drawable itemBackground2) {
        this.itemBackground = itemBackground2;
        updateMenuView(false);
    }

    public int getItemHorizontalPadding() {
        return this.itemHorizontalPadding;
    }

    public void setItemHorizontalPadding(int itemHorizontalPadding2) {
        this.itemHorizontalPadding = itemHorizontalPadding2;
        updateMenuView(false);
    }

    public int getItemIconPadding() {
        return this.itemIconPadding;
    }

    public void setItemIconPadding(int itemIconPadding2) {
        this.itemIconPadding = itemIconPadding2;
        updateMenuView(false);
    }

    public void setUpdateSuspended(boolean updateSuspended) {
        NavigationMenuAdapter navigationMenuAdapter = this.adapter;
        if (navigationMenuAdapter != null) {
            navigationMenuAdapter.setUpdateSuspended(updateSuspended);
        }
    }

    public void dispatchApplyWindowInsets(WindowInsetsCompat insets) {
        int top = insets.getSystemWindowInsetTop();
        if (this.paddingTopDefault != top) {
            this.paddingTopDefault = top;
            if (this.headerLayout.getChildCount() == 0) {
                NavigationMenuView navigationMenuView = this.menuView;
                navigationMenuView.setPadding(0, this.paddingTopDefault, 0, navigationMenuView.getPaddingBottom());
            }
        }
        ViewCompat.dispatchApplyWindowInsets(this.headerLayout, insets);
    }
}
