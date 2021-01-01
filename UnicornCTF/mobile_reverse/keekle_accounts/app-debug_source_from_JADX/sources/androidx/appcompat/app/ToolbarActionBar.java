package androidx.appcompat.app;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.drawable.Drawable;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window.Callback;
import android.widget.SpinnerAdapter;
import androidx.appcompat.app.ActionBar.LayoutParams;
import androidx.appcompat.app.ActionBar.OnMenuVisibilityListener;
import androidx.appcompat.app.ActionBar.OnNavigationListener;
import androidx.appcompat.app.ActionBar.Tab;
import androidx.appcompat.view.WindowCallbackWrapper;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuPresenter;
import androidx.appcompat.widget.DecorToolbar;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.Toolbar.OnMenuItemClickListener;
import androidx.appcompat.widget.ToolbarWidgetWrapper;
import androidx.core.view.ViewCompat;
import java.util.ArrayList;

class ToolbarActionBar extends ActionBar {
    DecorToolbar mDecorToolbar;
    private boolean mLastMenuVisibility;
    private boolean mMenuCallbackSet;
    private final OnMenuItemClickListener mMenuClicker = new OnMenuItemClickListener() {
        public boolean onMenuItemClick(MenuItem item) {
            return ToolbarActionBar.this.mWindowCallback.onMenuItemSelected(0, item);
        }
    };
    private final Runnable mMenuInvalidator = new Runnable() {
        public void run() {
            ToolbarActionBar.this.populateOptionsMenu();
        }
    };
    private ArrayList<OnMenuVisibilityListener> mMenuVisibilityListeners = new ArrayList<>();
    boolean mToolbarMenuPrepared;
    Callback mWindowCallback;

    private final class ActionMenuPresenterCallback implements MenuPresenter.Callback {
        private boolean mClosingActionMenu;

        ActionMenuPresenterCallback() {
        }

        public boolean onOpenSubMenu(MenuBuilder subMenu) {
            if (ToolbarActionBar.this.mWindowCallback == null) {
                return false;
            }
            ToolbarActionBar.this.mWindowCallback.onMenuOpened(108, subMenu);
            return true;
        }

        public void onCloseMenu(MenuBuilder menu, boolean allMenusAreClosing) {
            if (!this.mClosingActionMenu) {
                this.mClosingActionMenu = true;
                ToolbarActionBar.this.mDecorToolbar.dismissPopupMenus();
                if (ToolbarActionBar.this.mWindowCallback != null) {
                    ToolbarActionBar.this.mWindowCallback.onPanelClosed(108, menu);
                }
                this.mClosingActionMenu = false;
            }
        }
    }

    private final class MenuBuilderCallback implements MenuBuilder.Callback {
        MenuBuilderCallback() {
        }

        public boolean onMenuItemSelected(MenuBuilder menu, MenuItem item) {
            return false;
        }

        public void onMenuModeChange(MenuBuilder menu) {
            if (ToolbarActionBar.this.mWindowCallback == null) {
                return;
            }
            if (ToolbarActionBar.this.mDecorToolbar.isOverflowMenuShowing()) {
                ToolbarActionBar.this.mWindowCallback.onPanelClosed(108, menu);
            } else if (ToolbarActionBar.this.mWindowCallback.onPreparePanel(0, null, menu)) {
                ToolbarActionBar.this.mWindowCallback.onMenuOpened(108, menu);
            }
        }
    }

    private class ToolbarCallbackWrapper extends WindowCallbackWrapper {
        public ToolbarCallbackWrapper(Callback wrapped) {
            super(wrapped);
        }

        public boolean onPreparePanel(int featureId, View view, Menu menu) {
            boolean result = super.onPreparePanel(featureId, view, menu);
            if (result && !ToolbarActionBar.this.mToolbarMenuPrepared) {
                ToolbarActionBar.this.mDecorToolbar.setMenuPrepared();
                ToolbarActionBar.this.mToolbarMenuPrepared = true;
            }
            return result;
        }

        public View onCreatePanelView(int featureId) {
            if (featureId == 0) {
                return new View(ToolbarActionBar.this.mDecorToolbar.getContext());
            }
            return super.onCreatePanelView(featureId);
        }
    }

    ToolbarActionBar(Toolbar toolbar, CharSequence title, Callback windowCallback) {
        this.mDecorToolbar = new ToolbarWidgetWrapper(toolbar, false);
        ToolbarCallbackWrapper toolbarCallbackWrapper = new ToolbarCallbackWrapper(windowCallback);
        this.mWindowCallback = toolbarCallbackWrapper;
        this.mDecorToolbar.setWindowCallback(toolbarCallbackWrapper);
        toolbar.setOnMenuItemClickListener(this.mMenuClicker);
        this.mDecorToolbar.setWindowTitle(title);
    }

    public Callback getWrappedWindowCallback() {
        return this.mWindowCallback;
    }

    public void setCustomView(View view) {
        setCustomView(view, new LayoutParams(-2, -2));
    }

    public void setCustomView(View view, LayoutParams layoutParams) {
        if (view != null) {
            view.setLayoutParams(layoutParams);
        }
        this.mDecorToolbar.setCustomView(view);
    }

    public void setCustomView(int resId) {
        setCustomView(LayoutInflater.from(this.mDecorToolbar.getContext()).inflate(resId, this.mDecorToolbar.getViewGroup(), false));
    }

    public void setIcon(int resId) {
        this.mDecorToolbar.setIcon(resId);
    }

    public void setIcon(Drawable icon) {
        this.mDecorToolbar.setIcon(icon);
    }

    public void setLogo(int resId) {
        this.mDecorToolbar.setLogo(resId);
    }

    public void setLogo(Drawable logo) {
        this.mDecorToolbar.setLogo(logo);
    }

    public void setStackedBackgroundDrawable(Drawable d) {
    }

    public void setSplitBackgroundDrawable(Drawable d) {
    }

    public void setHomeButtonEnabled(boolean enabled) {
    }

    public void setElevation(float elevation) {
        ViewCompat.setElevation(this.mDecorToolbar.getViewGroup(), elevation);
    }

    public float getElevation() {
        return ViewCompat.getElevation(this.mDecorToolbar.getViewGroup());
    }

    public Context getThemedContext() {
        return this.mDecorToolbar.getContext();
    }

    public boolean isTitleTruncated() {
        return super.isTitleTruncated();
    }

    public void setHomeAsUpIndicator(Drawable indicator) {
        this.mDecorToolbar.setNavigationIcon(indicator);
    }

    public void setHomeAsUpIndicator(int resId) {
        this.mDecorToolbar.setNavigationIcon(resId);
    }

    public void setHomeActionContentDescription(CharSequence description) {
        this.mDecorToolbar.setNavigationContentDescription(description);
    }

    public void setDefaultDisplayHomeAsUpEnabled(boolean enabled) {
    }

    public void setHomeActionContentDescription(int resId) {
        this.mDecorToolbar.setNavigationContentDescription(resId);
    }

    public void setShowHideAnimationEnabled(boolean enabled) {
    }

    public void onConfigurationChanged(Configuration config) {
        super.onConfigurationChanged(config);
    }

    public void setListNavigationCallbacks(SpinnerAdapter adapter, OnNavigationListener callback) {
        this.mDecorToolbar.setDropdownParams(adapter, new NavItemSelectedListener(callback));
    }

    public void setSelectedNavigationItem(int position) {
        if (this.mDecorToolbar.getNavigationMode() == 1) {
            this.mDecorToolbar.setDropdownSelectedPosition(position);
            return;
        }
        throw new IllegalStateException("setSelectedNavigationIndex not valid for current navigation mode");
    }

    public int getSelectedNavigationIndex() {
        return -1;
    }

    public int getNavigationItemCount() {
        return 0;
    }

    public void setTitle(CharSequence title) {
        this.mDecorToolbar.setTitle(title);
    }

    public void setTitle(int resId) {
        DecorToolbar decorToolbar = this.mDecorToolbar;
        decorToolbar.setTitle(resId != 0 ? decorToolbar.getContext().getText(resId) : null);
    }

    public void setWindowTitle(CharSequence title) {
        this.mDecorToolbar.setWindowTitle(title);
    }

    public boolean requestFocus() {
        ViewGroup viewGroup = this.mDecorToolbar.getViewGroup();
        if (viewGroup == null || viewGroup.hasFocus()) {
            return false;
        }
        viewGroup.requestFocus();
        return true;
    }

    public void setSubtitle(CharSequence subtitle) {
        this.mDecorToolbar.setSubtitle(subtitle);
    }

    public void setSubtitle(int resId) {
        DecorToolbar decorToolbar = this.mDecorToolbar;
        decorToolbar.setSubtitle(resId != 0 ? decorToolbar.getContext().getText(resId) : null);
    }

    public void setDisplayOptions(int options) {
        setDisplayOptions(options, -1);
    }

    public void setDisplayOptions(int options, int mask) {
        this.mDecorToolbar.setDisplayOptions((options & mask) | ((~mask) & this.mDecorToolbar.getDisplayOptions()));
    }

    public void setDisplayUseLogoEnabled(boolean useLogo) {
        setDisplayOptions(useLogo, 1);
    }

    public void setDisplayShowHomeEnabled(boolean showHome) {
        setDisplayOptions(showHome ? 2 : 0, 2);
    }

    public void setDisplayHomeAsUpEnabled(boolean showHomeAsUp) {
        setDisplayOptions(showHomeAsUp ? 4 : 0, 4);
    }

    public void setDisplayShowTitleEnabled(boolean showTitle) {
        setDisplayOptions(showTitle ? 8 : 0, 8);
    }

    public void setDisplayShowCustomEnabled(boolean showCustom) {
        setDisplayOptions(showCustom ? 16 : 0, 16);
    }

    public void setBackgroundDrawable(Drawable d) {
        this.mDecorToolbar.setBackgroundDrawable(d);
    }

    public View getCustomView() {
        return this.mDecorToolbar.getCustomView();
    }

    public CharSequence getTitle() {
        return this.mDecorToolbar.getTitle();
    }

    public CharSequence getSubtitle() {
        return this.mDecorToolbar.getSubtitle();
    }

    public int getNavigationMode() {
        return 0;
    }

    public void setNavigationMode(int mode) {
        if (mode != 2) {
            this.mDecorToolbar.setNavigationMode(mode);
            return;
        }
        throw new IllegalArgumentException("Tabs not supported in this configuration");
    }

    public int getDisplayOptions() {
        return this.mDecorToolbar.getDisplayOptions();
    }

    public Tab newTab() {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void addTab(Tab tab) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void addTab(Tab tab, boolean setSelected) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void addTab(Tab tab, int position) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void addTab(Tab tab, int position, boolean setSelected) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void removeTab(Tab tab) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void removeTabAt(int position) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void removeAllTabs() {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public void selectTab(Tab tab) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public Tab getSelectedTab() {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public Tab getTabAt(int index) {
        throw new UnsupportedOperationException("Tabs are not supported in toolbar action bars");
    }

    public int getTabCount() {
        return 0;
    }

    public int getHeight() {
        return this.mDecorToolbar.getHeight();
    }

    public void show() {
        this.mDecorToolbar.setVisibility(0);
    }

    public void hide() {
        this.mDecorToolbar.setVisibility(8);
    }

    public boolean isShowing() {
        return this.mDecorToolbar.getVisibility() == 0;
    }

    public boolean openOptionsMenu() {
        return this.mDecorToolbar.showOverflowMenu();
    }

    public boolean closeOptionsMenu() {
        return this.mDecorToolbar.hideOverflowMenu();
    }

    public boolean invalidateOptionsMenu() {
        this.mDecorToolbar.getViewGroup().removeCallbacks(this.mMenuInvalidator);
        ViewCompat.postOnAnimation(this.mDecorToolbar.getViewGroup(), this.mMenuInvalidator);
        return true;
    }

    public boolean collapseActionView() {
        if (!this.mDecorToolbar.hasExpandedActionView()) {
            return false;
        }
        this.mDecorToolbar.collapseActionView();
        return true;
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: 0000 */
    public void populateOptionsMenu() {
        Menu menu = getMenu();
        MenuBuilder mb = menu instanceof MenuBuilder ? (MenuBuilder) menu : null;
        if (mb != null) {
            mb.stopDispatchingItemsChanged();
        }
        try {
            menu.clear();
            if (!this.mWindowCallback.onCreatePanelMenu(0, menu) || !this.mWindowCallback.onPreparePanel(0, null, menu)) {
                menu.clear();
            }
            if (mb != null) {
                mb.startDispatchingItemsChanged();
            }
        } catch (Throwable th) {
            if (mb != null) {
                mb.startDispatchingItemsChanged();
            }
            throw th;
        }
    }

    public boolean onMenuKeyEvent(KeyEvent event) {
        if (event.getAction() == 1) {
            openOptionsMenu();
        }
        return true;
    }

    public boolean onKeyShortcut(int keyCode, KeyEvent ev) {
        Menu menu = getMenu();
        if (menu == null) {
            return false;
        }
        boolean z = true;
        if (KeyCharacterMap.load(ev != null ? ev.getDeviceId() : -1).getKeyboardType() == 1) {
            z = false;
        }
        menu.setQwertyMode(z);
        return menu.performShortcut(keyCode, ev, 0);
    }

    /* access modifiers changed from: 0000 */
    public void onDestroy() {
        this.mDecorToolbar.getViewGroup().removeCallbacks(this.mMenuInvalidator);
    }

    public void addOnMenuVisibilityListener(OnMenuVisibilityListener listener) {
        this.mMenuVisibilityListeners.add(listener);
    }

    public void removeOnMenuVisibilityListener(OnMenuVisibilityListener listener) {
        this.mMenuVisibilityListeners.remove(listener);
    }

    public void dispatchMenuVisibilityChanged(boolean isVisible) {
        if (isVisible != this.mLastMenuVisibility) {
            this.mLastMenuVisibility = isVisible;
            int count = this.mMenuVisibilityListeners.size();
            for (int i = 0; i < count; i++) {
                ((OnMenuVisibilityListener) this.mMenuVisibilityListeners.get(i)).onMenuVisibilityChanged(isVisible);
            }
        }
    }

    private Menu getMenu() {
        if (!this.mMenuCallbackSet) {
            this.mDecorToolbar.setMenuCallbacks(new ActionMenuPresenterCallback(), new MenuBuilderCallback());
            this.mMenuCallbackSet = true;
        }
        return this.mDecorToolbar.getMenu();
    }
}
