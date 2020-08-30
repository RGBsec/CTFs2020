package androidx.appcompat.app;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface.OnCancelListener;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import androidx.appcompat.C0003R;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.view.ActionMode.Callback;
import androidx.core.view.KeyEventDispatcher;
import androidx.core.view.KeyEventDispatcher.Component;

public class AppCompatDialog extends Dialog implements AppCompatCallback {
    private AppCompatDelegate mDelegate;
    private final Component mKeyDispatcher;

    public AppCompatDialog(Context context) {
        this(context, 0);
    }

    public AppCompatDialog(Context context, int theme) {
        super(context, getThemeResId(context, theme));
        this.mKeyDispatcher = new Component() {
            public boolean superDispatchKeyEvent(KeyEvent event) {
                return AppCompatDialog.this.superDispatchKeyEvent(event);
            }
        };
        AppCompatDelegate delegate = getDelegate();
        delegate.setTheme(getThemeResId(context, theme));
        delegate.onCreate(null);
    }

    protected AppCompatDialog(Context context, boolean cancelable, OnCancelListener cancelListener) {
        super(context, cancelable, cancelListener);
        this.mKeyDispatcher = new Component() {
            public boolean superDispatchKeyEvent(KeyEvent event) {
                return AppCompatDialog.this.superDispatchKeyEvent(event);
            }
        };
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        getDelegate().installViewFactory();
        super.onCreate(savedInstanceState);
        getDelegate().onCreate(savedInstanceState);
    }

    public ActionBar getSupportActionBar() {
        return getDelegate().getSupportActionBar();
    }

    public void setContentView(int layoutResID) {
        getDelegate().setContentView(layoutResID);
    }

    public void setContentView(View view) {
        getDelegate().setContentView(view);
    }

    public void setContentView(View view, LayoutParams params) {
        getDelegate().setContentView(view, params);
    }

    public <T extends View> T findViewById(int id) {
        return getDelegate().findViewById(id);
    }

    public void setTitle(CharSequence title) {
        super.setTitle(title);
        getDelegate().setTitle(title);
    }

    public void setTitle(int titleId) {
        super.setTitle(titleId);
        getDelegate().setTitle(getContext().getString(titleId));
    }

    public void addContentView(View view, LayoutParams params) {
        getDelegate().addContentView(view, params);
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
        getDelegate().onStop();
    }

    public boolean supportRequestWindowFeature(int featureId) {
        return getDelegate().requestWindowFeature(featureId);
    }

    public void invalidateOptionsMenu() {
        getDelegate().invalidateOptionsMenu();
    }

    public AppCompatDelegate getDelegate() {
        if (this.mDelegate == null) {
            this.mDelegate = AppCompatDelegate.create((Dialog) this, (AppCompatCallback) this);
        }
        return this.mDelegate;
    }

    private static int getThemeResId(Context context, int themeId) {
        if (themeId != 0) {
            return themeId;
        }
        TypedValue outValue = new TypedValue();
        context.getTheme().resolveAttribute(C0003R.attr.dialogTheme, outValue, true);
        return outValue.resourceId;
    }

    public void onSupportActionModeStarted(ActionMode mode) {
    }

    public void onSupportActionModeFinished(ActionMode mode) {
    }

    public ActionMode onWindowStartingSupportActionMode(Callback callback) {
        return null;
    }

    /* access modifiers changed from: 0000 */
    public boolean superDispatchKeyEvent(KeyEvent event) {
        return super.dispatchKeyEvent(event);
    }

    public boolean dispatchKeyEvent(KeyEvent event) {
        return KeyEventDispatcher.dispatchKeyEvent(this.mKeyDispatcher, getWindow().getDecorView(), this, event);
    }
}
