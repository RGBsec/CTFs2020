package androidx.appcompat.app;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;
import androidx.appcompat.app.ActionBarDrawerToggle.Delegate;
import androidx.appcompat.app.ActionBarDrawerToggle.DelegateProvider;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.view.ActionMode.Callback;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.VectorEnabledTintResources;
import androidx.core.app.ActivityCompat;
import androidx.core.app.NavUtils;
import androidx.core.app.TaskStackBuilder;
import androidx.core.app.TaskStackBuilder.SupportParentable;
import androidx.fragment.app.FragmentActivity;

public class AppCompatActivity extends FragmentActivity implements AppCompatCallback, SupportParentable, DelegateProvider {
    private AppCompatDelegate mDelegate;
    private Resources mResources;

    public AppCompatActivity() {
    }

    public AppCompatActivity(int contentLayoutId) {
        super(contentLayoutId);
    }

    /* access modifiers changed from: protected */
    public void attachBaseContext(Context newBase) {
        super.attachBaseContext(newBase);
        getDelegate().attachBaseContext(newBase);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        AppCompatDelegate delegate = getDelegate();
        delegate.installViewFactory();
        delegate.onCreate(savedInstanceState);
        super.onCreate(savedInstanceState);
    }

    public void setTheme(int resId) {
        super.setTheme(resId);
        getDelegate().setTheme(resId);
    }

    /* access modifiers changed from: protected */
    public void onPostCreate(Bundle savedInstanceState) {
        super.onPostCreate(savedInstanceState);
        getDelegate().onPostCreate(savedInstanceState);
    }

    public ActionBar getSupportActionBar() {
        return getDelegate().getSupportActionBar();
    }

    public void setSupportActionBar(Toolbar toolbar) {
        getDelegate().setSupportActionBar(toolbar);
    }

    public MenuInflater getMenuInflater() {
        return getDelegate().getMenuInflater();
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

    public void addContentView(View view, LayoutParams params) {
        getDelegate().addContentView(view, params);
    }

    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (this.mResources != null) {
            this.mResources.updateConfiguration(newConfig, super.getResources().getDisplayMetrics());
        }
        getDelegate().onConfigurationChanged(newConfig);
    }

    /* access modifiers changed from: protected */
    public void onPostResume() {
        super.onPostResume();
        getDelegate().onPostResume();
    }

    /* access modifiers changed from: protected */
    public void onStart() {
        super.onStart();
        getDelegate().onStart();
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
        getDelegate().onStop();
    }

    public <T extends View> T findViewById(int id) {
        return getDelegate().findViewById(id);
    }

    public final boolean onMenuItemSelected(int featureId, MenuItem item) {
        if (super.onMenuItemSelected(featureId, item)) {
            return true;
        }
        ActionBar ab = getSupportActionBar();
        if (item.getItemId() != 16908332 || ab == null || (ab.getDisplayOptions() & 4) == 0) {
            return false;
        }
        return onSupportNavigateUp();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        getDelegate().onDestroy();
    }

    /* access modifiers changed from: protected */
    public void onTitleChanged(CharSequence title, int color) {
        super.onTitleChanged(title, color);
        getDelegate().setTitle(title);
    }

    public boolean supportRequestWindowFeature(int featureId) {
        return getDelegate().requestWindowFeature(featureId);
    }

    public void supportInvalidateOptionsMenu() {
        getDelegate().invalidateOptionsMenu();
    }

    public void invalidateOptionsMenu() {
        getDelegate().invalidateOptionsMenu();
    }

    public void onSupportActionModeStarted(ActionMode mode) {
    }

    public void onSupportActionModeFinished(ActionMode mode) {
    }

    public ActionMode onWindowStartingSupportActionMode(Callback callback) {
        return null;
    }

    public ActionMode startSupportActionMode(Callback callback) {
        return getDelegate().startSupportActionMode(callback);
    }

    @Deprecated
    public void setSupportProgressBarVisibility(boolean visible) {
    }

    @Deprecated
    public void setSupportProgressBarIndeterminateVisibility(boolean visible) {
    }

    @Deprecated
    public void setSupportProgressBarIndeterminate(boolean indeterminate) {
    }

    @Deprecated
    public void setSupportProgress(int progress) {
    }

    public void onCreateSupportNavigateUpTaskStack(TaskStackBuilder builder) {
        builder.addParentStack((Activity) this);
    }

    public void onPrepareSupportNavigateUpTaskStack(TaskStackBuilder builder) {
    }

    public boolean onSupportNavigateUp() {
        Intent upIntent = getSupportParentActivityIntent();
        if (upIntent == null) {
            return false;
        }
        if (supportShouldUpRecreateTask(upIntent)) {
            TaskStackBuilder b = TaskStackBuilder.create(this);
            onCreateSupportNavigateUpTaskStack(b);
            onPrepareSupportNavigateUpTaskStack(b);
            b.startActivities();
            try {
                ActivityCompat.finishAffinity(this);
            } catch (IllegalStateException e) {
                finish();
            }
        } else {
            supportNavigateUpTo(upIntent);
        }
        return true;
    }

    public Intent getSupportParentActivityIntent() {
        return NavUtils.getParentActivityIntent(this);
    }

    public boolean supportShouldUpRecreateTask(Intent targetIntent) {
        return NavUtils.shouldUpRecreateTask(this, targetIntent);
    }

    public void supportNavigateUpTo(Intent upIntent) {
        NavUtils.navigateUpTo(this, upIntent);
    }

    public void onContentChanged() {
        onSupportContentChanged();
    }

    @Deprecated
    public void onSupportContentChanged() {
    }

    public Delegate getDrawerToggleDelegate() {
        return getDelegate().getDrawerToggleDelegate();
    }

    public boolean onMenuOpened(int featureId, Menu menu) {
        return super.onMenuOpened(featureId, menu);
    }

    public void onPanelClosed(int featureId, Menu menu) {
        super.onPanelClosed(featureId, menu);
    }

    /* access modifiers changed from: protected */
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        getDelegate().onSaveInstanceState(outState);
    }

    public AppCompatDelegate getDelegate() {
        if (this.mDelegate == null) {
            this.mDelegate = AppCompatDelegate.create((Activity) this, (AppCompatCallback) this);
        }
        return this.mDelegate;
    }

    public boolean dispatchKeyEvent(KeyEvent event) {
        int keyCode = event.getKeyCode();
        ActionBar actionBar = getSupportActionBar();
        if (keyCode != 82 || actionBar == null || !actionBar.onMenuKeyEvent(event)) {
            return super.dispatchKeyEvent(event);
        }
        return true;
    }

    public Resources getResources() {
        if (this.mResources == null && VectorEnabledTintResources.shouldBeUsed()) {
            this.mResources = new VectorEnabledTintResources(this, super.getResources());
        }
        Resources resources = this.mResources;
        return resources == null ? super.getResources() : resources;
    }

    private boolean performMenuItemShortcut(int keycode, KeyEvent event) {
        if (VERSION.SDK_INT < 26 && !event.isCtrlPressed() && !KeyEvent.metaStateHasNoModifiers(event.getMetaState()) && event.getRepeatCount() == 0 && !KeyEvent.isModifierKey(event.getKeyCode())) {
            Window currentWindow = getWindow();
            if (!(currentWindow == null || currentWindow.getDecorView() == null || !currentWindow.getDecorView().dispatchKeyShortcutEvent(event))) {
                return true;
            }
        }
        return false;
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (performMenuItemShortcut(keyCode, event)) {
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    public void openOptionsMenu() {
        ActionBar actionBar = getSupportActionBar();
        if (!getWindow().hasFeature(0)) {
            return;
        }
        if (actionBar == null || !actionBar.openOptionsMenu()) {
            super.openOptionsMenu();
        }
    }

    public void closeOptionsMenu() {
        ActionBar actionBar = getSupportActionBar();
        if (!getWindow().hasFeature(0)) {
            return;
        }
        if (actionBar == null || !actionBar.closeOptionsMenu()) {
            super.closeOptionsMenu();
        }
    }

    /* access modifiers changed from: protected */
    public void onNightModeChanged(int mode) {
    }
}
