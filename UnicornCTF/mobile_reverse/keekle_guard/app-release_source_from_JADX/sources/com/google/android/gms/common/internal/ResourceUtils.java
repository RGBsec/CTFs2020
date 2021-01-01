package com.google.android.gms.common.internal;

import android.net.Uri;
import android.net.Uri.Builder;

public final class ResourceUtils {
    private static final Uri zzet = new Builder().scheme("android.resource").authority("com.google.android.gms").appendPath("drawable").build();

    private ResourceUtils() {
    }
}
