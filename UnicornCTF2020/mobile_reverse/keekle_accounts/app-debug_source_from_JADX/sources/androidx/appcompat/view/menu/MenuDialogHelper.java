package androidx.appcompat.view.menu;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.DialogInterface.OnKeyListener;
import android.os.IBinder;
import android.view.KeyEvent;
import android.view.KeyEvent.DispatcherState;
import android.view.View;
import android.view.Window;
import android.view.WindowManager.LayoutParams;
import androidx.appcompat.C0003R;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AlertDialog.Builder;
import androidx.appcompat.view.menu.MenuPresenter.Callback;
import androidx.core.view.PointerIconCompat;

class MenuDialogHelper implements OnKeyListener, OnClickListener, OnDismissListener, Callback {
    private AlertDialog mDialog;
    private MenuBuilder mMenu;
    ListMenuPresenter mPresenter;
    private Callback mPresenterCallback;

    public MenuDialogHelper(MenuBuilder menu) {
        this.mMenu = menu;
    }

    public void show(IBinder windowToken) {
        MenuBuilder menu = this.mMenu;
        Builder builder = new Builder(menu.getContext());
        ListMenuPresenter listMenuPresenter = new ListMenuPresenter(builder.getContext(), C0003R.layout.abc_list_menu_item_layout);
        this.mPresenter = listMenuPresenter;
        listMenuPresenter.setCallback(this);
        this.mMenu.addMenuPresenter(this.mPresenter);
        builder.setAdapter(this.mPresenter.getAdapter(), this);
        View headerView = menu.getHeaderView();
        if (headerView != null) {
            builder.setCustomTitle(headerView);
        } else {
            builder.setIcon(menu.getHeaderIcon()).setTitle(menu.getHeaderTitle());
        }
        builder.setOnKeyListener(this);
        AlertDialog create = builder.create();
        this.mDialog = create;
        create.setOnDismissListener(this);
        LayoutParams lp = this.mDialog.getWindow().getAttributes();
        lp.type = PointerIconCompat.TYPE_HELP;
        if (windowToken != null) {
            lp.token = windowToken;
        }
        lp.flags |= 131072;
        this.mDialog.show();
    }

    public boolean onKey(DialogInterface dialog, int keyCode, KeyEvent event) {
        if (keyCode == 82 || keyCode == 4) {
            if (event.getAction() == 0 && event.getRepeatCount() == 0) {
                Window win = this.mDialog.getWindow();
                if (win != null) {
                    View decor = win.getDecorView();
                    if (decor != null) {
                        DispatcherState ds = decor.getKeyDispatcherState();
                        if (ds != null) {
                            ds.startTracking(event, this);
                            return true;
                        }
                    }
                }
            } else if (event.getAction() == 1 && !event.isCanceled()) {
                Window win2 = this.mDialog.getWindow();
                if (win2 != null) {
                    View decor2 = win2.getDecorView();
                    if (decor2 != null) {
                        DispatcherState ds2 = decor2.getKeyDispatcherState();
                        if (ds2 != null && ds2.isTracking(event)) {
                            this.mMenu.close(true);
                            dialog.dismiss();
                            return true;
                        }
                    }
                }
            }
        }
        return this.mMenu.performShortcut(keyCode, event, 0);
    }

    public void setPresenterCallback(Callback cb) {
        this.mPresenterCallback = cb;
    }

    public void dismiss() {
        AlertDialog alertDialog = this.mDialog;
        if (alertDialog != null) {
            alertDialog.dismiss();
        }
    }

    public void onDismiss(DialogInterface dialog) {
        this.mPresenter.onCloseMenu(this.mMenu, true);
    }

    public void onCloseMenu(MenuBuilder menu, boolean allMenusAreClosing) {
        if (allMenusAreClosing || menu == this.mMenu) {
            dismiss();
        }
        Callback callback = this.mPresenterCallback;
        if (callback != null) {
            callback.onCloseMenu(menu, allMenusAreClosing);
        }
    }

    public boolean onOpenSubMenu(MenuBuilder subMenu) {
        Callback callback = this.mPresenterCallback;
        if (callback != null) {
            return callback.onOpenSubMenu(subMenu);
        }
        return false;
    }

    public void onClick(DialogInterface dialog, int which) {
        this.mMenu.performItemAction((MenuItemImpl) this.mPresenter.getAdapter().getItem(which), 0);
    }
}
