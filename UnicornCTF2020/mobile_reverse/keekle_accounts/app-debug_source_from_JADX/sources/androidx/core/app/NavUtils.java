package androidx.core.app;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build.VERSION;
import android.util.Log;

public final class NavUtils {
    public static final String PARENT_ACTIVITY = "android.support.PARENT_ACTIVITY";
    private static final String TAG = "NavUtils";

    public static boolean shouldUpRecreateTask(Activity sourceActivity, Intent targetIntent) {
        if (VERSION.SDK_INT >= 16) {
            return sourceActivity.shouldUpRecreateTask(targetIntent);
        }
        String action = sourceActivity.getIntent().getAction();
        return action != null && !action.equals("android.intent.action.MAIN");
    }

    public static void navigateUpFromSameTask(Activity sourceActivity) {
        Intent upIntent = getParentActivityIntent(sourceActivity);
        if (upIntent != null) {
            navigateUpTo(sourceActivity, upIntent);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Activity ");
        sb.append(sourceActivity.getClass().getSimpleName());
        sb.append(" does not have a parent activity name specified. (Did you forget to add the android.support.PARENT_ACTIVITY <meta-data>  element in your manifest?)");
        throw new IllegalArgumentException(sb.toString());
    }

    public static void navigateUpTo(Activity sourceActivity, Intent upIntent) {
        if (VERSION.SDK_INT >= 16) {
            sourceActivity.navigateUpTo(upIntent);
            return;
        }
        upIntent.addFlags(67108864);
        sourceActivity.startActivity(upIntent);
        sourceActivity.finish();
    }

    public static Intent getParentActivityIntent(Activity sourceActivity) {
        Intent intent;
        if (VERSION.SDK_INT >= 16) {
            Intent result = sourceActivity.getParentActivityIntent();
            if (result != null) {
                return result;
            }
        }
        String parentName = getParentActivityName(sourceActivity);
        if (parentName == null) {
            return null;
        }
        ComponentName target = new ComponentName(sourceActivity, parentName);
        try {
            if (getParentActivityName(sourceActivity, target) == null) {
                intent = Intent.makeMainActivity(target);
            } else {
                intent = new Intent().setComponent(target);
            }
            return intent;
        } catch (NameNotFoundException e) {
            StringBuilder sb = new StringBuilder();
            sb.append("getParentActivityIntent: bad parentActivityName '");
            sb.append(parentName);
            sb.append("' in manifest");
            Log.e(TAG, sb.toString());
            return null;
        }
    }

    public static Intent getParentActivityIntent(Context context, Class<?> sourceActivityClass) throws NameNotFoundException {
        Intent parentIntent;
        String parentActivity = getParentActivityName(context, new ComponentName(context, sourceActivityClass));
        if (parentActivity == null) {
            return null;
        }
        ComponentName target = new ComponentName(context, parentActivity);
        if (getParentActivityName(context, target) == null) {
            parentIntent = Intent.makeMainActivity(target);
        } else {
            parentIntent = new Intent().setComponent(target);
        }
        return parentIntent;
    }

    public static Intent getParentActivityIntent(Context context, ComponentName componentName) throws NameNotFoundException {
        Intent parentIntent;
        String parentActivity = getParentActivityName(context, componentName);
        if (parentActivity == null) {
            return null;
        }
        ComponentName target = new ComponentName(componentName.getPackageName(), parentActivity);
        if (getParentActivityName(context, target) == null) {
            parentIntent = Intent.makeMainActivity(target);
        } else {
            parentIntent = new Intent().setComponent(target);
        }
        return parentIntent;
    }

    public static String getParentActivityName(Activity sourceActivity) {
        try {
            return getParentActivityName(sourceActivity, sourceActivity.getComponentName());
        } catch (NameNotFoundException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static String getParentActivityName(Context context, ComponentName componentName) throws NameNotFoundException {
        int flags;
        PackageManager pm = context.getPackageManager();
        if (VERSION.SDK_INT >= 24) {
            flags = 128 | 512;
        } else {
            flags = 128 | 512;
        }
        ActivityInfo info = pm.getActivityInfo(componentName, flags);
        if (VERSION.SDK_INT >= 16) {
            String result = info.parentActivityName;
            if (result != null) {
                return result;
            }
        }
        if (info.metaData == null) {
            return null;
        }
        String parentActivity = info.metaData.getString(PARENT_ACTIVITY);
        if (parentActivity == null) {
            return null;
        }
        if (parentActivity.charAt(0) == '.') {
            StringBuilder sb = new StringBuilder();
            sb.append(context.getPackageName());
            sb.append(parentActivity);
            parentActivity = sb.toString();
        }
        return parentActivity;
    }

    private NavUtils() {
    }
}
