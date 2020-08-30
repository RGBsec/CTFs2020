package com.google.android.gms.common.internal;

import android.content.Context;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.res.Resources;
import android.text.TextUtils;
import android.util.Log;
import androidx.collection.SimpleArrayMap;
import com.google.android.gms.base.C0262R;
import com.google.android.gms.common.C0265R;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.common.util.DeviceProperties;
import com.google.android.gms.common.wrappers.Wrappers;

public final class ConnectionErrorMessages {
    private static final SimpleArrayMap<String, String> zaog = new SimpleArrayMap<>();

    public static String getErrorTitle(Context context, int i) {
        Resources resources = context.getResources();
        String str = "GoogleApiAvailability";
        switch (i) {
            case 1:
                return resources.getString(C0262R.string.common_google_play_services_install_title);
            case 2:
                return resources.getString(C0262R.string.common_google_play_services_update_title);
            case 3:
                return resources.getString(C0262R.string.common_google_play_services_enable_title);
            case 4:
            case 6:
            case 18:
                return null;
            case 5:
                Log.e(str, "An invalid account was specified when connecting. Please provide a valid account.");
                return zaa(context, "common_google_play_services_invalid_account_title");
            case 7:
                Log.e(str, "Network error occurred. Please retry request later.");
                return zaa(context, "common_google_play_services_network_error_title");
            case 8:
                Log.e(str, "Internal error occurred. Please see logs for detailed information");
                return null;
            case 9:
                Log.e(str, "Google Play services is invalid. Cannot recover.");
                return null;
            case 10:
                Log.e(str, "Developer error occurred. Please see logs for detailed information");
                return null;
            case 11:
                Log.e(str, "The application is not licensed to the user.");
                return null;
            case 16:
                Log.e(str, "One of the API components you attempted to connect to is not available.");
                return null;
            case 17:
                Log.e(str, "The specified account could not be signed in.");
                return zaa(context, "common_google_play_services_sign_in_failed_title");
            case 20:
                Log.e(str, "The current user profile is restricted and could not use authenticated features.");
                return zaa(context, "common_google_play_services_restricted_profile_title");
            default:
                StringBuilder sb = new StringBuilder(33);
                sb.append("Unexpected error code ");
                sb.append(i);
                Log.e(str, sb.toString());
                return null;
        }
    }

    public static String getErrorNotificationTitle(Context context, int i) {
        String str;
        if (i == 6) {
            str = zaa(context, "common_google_play_services_resolution_required_title");
        } else {
            str = getErrorTitle(context, i);
        }
        return str == null ? context.getResources().getString(C0262R.string.common_google_play_services_notification_ticker) : str;
    }

    public static String getErrorMessage(Context context, int i) {
        Resources resources = context.getResources();
        String appName = getAppName(context);
        if (i == 1) {
            return resources.getString(C0262R.string.common_google_play_services_install_text, new Object[]{appName});
        } else if (i != 2) {
            if (i == 3) {
                return resources.getString(C0262R.string.common_google_play_services_enable_text, new Object[]{appName});
            } else if (i == 5) {
                return zaa(context, "common_google_play_services_invalid_account_text", appName);
            } else {
                if (i == 7) {
                    return zaa(context, "common_google_play_services_network_error_text", appName);
                }
                if (i == 9) {
                    return resources.getString(C0262R.string.common_google_play_services_unsupported_text, new Object[]{appName});
                } else if (i == 20) {
                    return zaa(context, "common_google_play_services_restricted_profile_text", appName);
                } else {
                    switch (i) {
                        case 16:
                            return zaa(context, "common_google_play_services_api_unavailable_text", appName);
                        case 17:
                            return zaa(context, "common_google_play_services_sign_in_failed_text", appName);
                        case 18:
                            return resources.getString(C0262R.string.common_google_play_services_updating_text, new Object[]{appName});
                        default:
                            return resources.getString(C0265R.string.common_google_play_services_unknown_issue, new Object[]{appName});
                    }
                }
            }
        } else if (DeviceProperties.isWearableWithoutPlayStore(context)) {
            return resources.getString(C0262R.string.common_google_play_services_wear_update_text);
        } else {
            return resources.getString(C0262R.string.common_google_play_services_update_text, new Object[]{appName});
        }
    }

    public static String getErrorNotificationMessage(Context context, int i) {
        if (i != 6) {
            return getErrorMessage(context, i);
        }
        return zaa(context, "common_google_play_services_resolution_required_text", getAppName(context));
    }

    public static String getErrorDialogButtonMessage(Context context, int i) {
        Resources resources = context.getResources();
        if (i == 1) {
            return resources.getString(C0262R.string.common_google_play_services_install_button);
        }
        if (i == 2) {
            return resources.getString(C0262R.string.common_google_play_services_update_button);
        }
        if (i != 3) {
            return resources.getString(17039370);
        }
        return resources.getString(C0262R.string.common_google_play_services_enable_button);
    }

    public static String getAppName(Context context) {
        String packageName = context.getPackageName();
        try {
            return Wrappers.packageManager(context).getApplicationLabel(packageName).toString();
        } catch (NameNotFoundException | NullPointerException unused) {
            String str = context.getApplicationInfo().name;
            return TextUtils.isEmpty(str) ? packageName : str;
        }
    }

    private static String zaa(Context context, String str, String str2) {
        Resources resources = context.getResources();
        String zaa = zaa(context, str);
        if (zaa == null) {
            zaa = resources.getString(C0265R.string.common_google_play_services_unknown_issue);
        }
        return String.format(resources.getConfiguration().locale, zaa, new Object[]{str2});
    }

    private static String zaa(Context context, String str) {
        synchronized (zaog) {
            String str2 = (String) zaog.get(str);
            if (str2 != null) {
                return str2;
            }
            Resources remoteResource = GooglePlayServicesUtil.getRemoteResource(context);
            if (remoteResource == null) {
                return null;
            }
            int identifier = remoteResource.getIdentifier(str, "string", "com.google.android.gms");
            if (identifier == 0) {
                String str3 = "GoogleApiAvailability";
                String str4 = "Missing resource: ";
                String valueOf = String.valueOf(str);
                Log.w(str3, valueOf.length() != 0 ? str4.concat(valueOf) : new String(str4));
                return null;
            }
            String string = remoteResource.getString(identifier);
            if (TextUtils.isEmpty(string)) {
                String str5 = "GoogleApiAvailability";
                String str6 = "Got empty resource: ";
                String valueOf2 = String.valueOf(str);
                Log.w(str5, valueOf2.length() != 0 ? str6.concat(valueOf2) : new String(str6));
                return null;
            }
            zaog.put(str, string);
            return string;
        }
    }

    public static String getDefaultNotificationChannelName(Context context) {
        return context.getResources().getString(C0262R.string.common_google_play_services_notification_channel_name);
    }

    private ConnectionErrorMessages() {
    }
}
