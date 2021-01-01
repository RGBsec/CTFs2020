package androidx.appcompat.app;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Bundle;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MenuInflater;
import android.view.View;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;
import androidx.appcompat.app.ActionBarDrawerToggle.Delegate;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.view.ActionMode.Callback;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.VectorEnabledTintResources;
import androidx.collection.ArraySet;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.ref.WeakReference;
import java.util.Iterator;

public abstract class AppCompatDelegate {
    public static final int FEATURE_ACTION_MODE_OVERLAY = 10;
    public static final int FEATURE_SUPPORT_ACTION_BAR = 108;
    public static final int FEATURE_SUPPORT_ACTION_BAR_OVERLAY = 109;
    @Deprecated
    public static final int MODE_NIGHT_AUTO = 0;
    public static final int MODE_NIGHT_AUTO_BATTERY = 3;
    @Deprecated
    public static final int MODE_NIGHT_AUTO_TIME = 0;
    public static final int MODE_NIGHT_FOLLOW_SYSTEM = -1;
    public static final int MODE_NIGHT_NO = 1;
    public static final int MODE_NIGHT_UNSPECIFIED = -100;
    public static final int MODE_NIGHT_YES = 2;
    static final String TAG = "AppCompatDelegate";
    private static final ArraySet<WeakReference<AppCompatDelegate>> sActiveDelegates = new ArraySet<>();
    private static final Object sActiveDelegatesLock = new Object();
    private static int sDefaultNightMode = -100;

    @Retention(RetentionPolicy.SOURCE)
    public @interface NightMode {
    }

    public abstract void addContentView(View view, LayoutParams layoutParams);

    public abstract boolean applyDayNight();

    public abstract View createView(View view, String str, Context context, AttributeSet attributeSet);

    public abstract <T extends View> T findViewById(int i);

    public abstract Delegate getDrawerToggleDelegate();

    public abstract MenuInflater getMenuInflater();

    public abstract ActionBar getSupportActionBar();

    public abstract boolean hasWindowFeature(int i);

    public abstract void installViewFactory();

    public abstract void invalidateOptionsMenu();

    public abstract boolean isHandleNativeActionModesEnabled();

    public abstract void onConfigurationChanged(Configuration configuration);

    public abstract void onCreate(Bundle bundle);

    public abstract void onDestroy();

    public abstract void onPostCreate(Bundle bundle);

    public abstract void onPostResume();

    public abstract void onSaveInstanceState(Bundle bundle);

    public abstract void onStart();

    public abstract void onStop();

    public abstract boolean requestWindowFeature(int i);

    public abstract void setContentView(int i);

    public abstract void setContentView(View view);

    public abstract void setContentView(View view, LayoutParams layoutParams);

    public abstract void setHandleNativeActionModesEnabled(boolean z);

    public abstract void setLocalNightMode(int i);

    public abstract void setSupportActionBar(Toolbar toolbar);

    public abstract void setTitle(CharSequence charSequence);

    public abstract ActionMode startSupportActionMode(Callback callback);

    public static AppCompatDelegate create(Activity activity, AppCompatCallback callback) {
        return new AppCompatDelegateImpl(activity, callback);
    }

    public static AppCompatDelegate create(Dialog dialog, AppCompatCallback callback) {
        return new AppCompatDelegateImpl(dialog, callback);
    }

    public static AppCompatDelegate create(Context context, Window window, AppCompatCallback callback) {
        return new AppCompatDelegateImpl(context, window, callback);
    }

    public static AppCompatDelegate create(Context context, Activity activity, AppCompatCallback callback) {
        return new AppCompatDelegateImpl(context, activity, callback);
    }

    AppCompatDelegate() {
    }

    public void setTheme(int themeResId) {
    }

    public void attachBaseContext(Context context) {
    }

    public int getLocalNightMode() {
        return -100;
    }

    public static void setDefaultNightMode(int mode) {
        if (mode != -1 && mode != 0 && mode != 1 && mode != 2 && mode != 3) {
            Log.d(TAG, "setDefaultNightMode() called with an unknown mode");
        } else if (sDefaultNightMode != mode) {
            sDefaultNightMode = mode;
            applyDayNightToActiveDelegates();
        }
    }

    public static int getDefaultNightMode() {
        return sDefaultNightMode;
    }

    public static void setCompatVectorFromResourcesEnabled(boolean enabled) {
        VectorEnabledTintResources.setCompatVectorFromResourcesEnabled(enabled);
    }

    public static boolean isCompatVectorFromResourcesEnabled() {
        return VectorEnabledTintResources.isCompatVectorFromResourcesEnabled();
    }

    static void markStarted(AppCompatDelegate delegate) {
        synchronized (sActiveDelegatesLock) {
            removeDelegateFromActives(delegate);
            sActiveDelegates.add(new WeakReference(delegate));
        }
    }

    static void markStopped(AppCompatDelegate delegate) {
        synchronized (sActiveDelegatesLock) {
            removeDelegateFromActives(delegate);
        }
    }

    private static void removeDelegateFromActives(AppCompatDelegate toRemove) {
        synchronized (sActiveDelegatesLock) {
            Iterator<WeakReference<AppCompatDelegate>> i = sActiveDelegates.iterator();
            while (i.hasNext()) {
                AppCompatDelegate delegate = (AppCompatDelegate) ((WeakReference) i.next()).get();
                if (delegate == toRemove || delegate == null) {
                    i.remove();
                }
            }
        }
    }

    private static void applyDayNightToActiveDelegates() {
        synchronized (sActiveDelegatesLock) {
            Iterator it = sActiveDelegates.iterator();
            while (it.hasNext()) {
                AppCompatDelegate delegate = (AppCompatDelegate) ((WeakReference) it.next()).get();
                if (delegate != null) {
                    delegate.applyDayNight();
                }
            }
        }
    }
}
