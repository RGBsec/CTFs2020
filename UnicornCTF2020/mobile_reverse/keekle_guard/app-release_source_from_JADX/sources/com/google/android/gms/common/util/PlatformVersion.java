package com.google.android.gms.common.util;

import android.os.Build.VERSION;
import androidx.core.p003os.BuildCompat;

public final class PlatformVersion {
    private PlatformVersion() {
    }

    public static boolean isAtLeastHoneycomb() {
        return true;
    }

    public static boolean isAtLeastHoneycombMR1() {
        return true;
    }

    public static boolean isAtLeastIceCreamSandwich() {
        return true;
    }

    public static boolean isAtLeastIceCreamSandwichMR1() {
        return true;
    }

    public static boolean isAtLeastJellyBean() {
        return true;
    }

    public static boolean isAtLeastJellyBeanMR1() {
        return VERSION.SDK_INT >= 17;
    }

    public static boolean isAtLeastJellyBeanMR2() {
        return VERSION.SDK_INT >= 18;
    }

    public static boolean isAtLeastKitKat() {
        return VERSION.SDK_INT >= 19;
    }

    public static boolean isAtLeastKitKatWatch() {
        return VERSION.SDK_INT >= 20;
    }

    public static boolean isAtLeastLollipop() {
        return VERSION.SDK_INT >= 21;
    }

    public static boolean isAtLeastLollipopMR1() {
        return VERSION.SDK_INT >= 22;
    }

    public static boolean isAtLeastM() {
        return VERSION.SDK_INT >= 23;
    }

    public static boolean isAtLeastN() {
        return VERSION.SDK_INT >= 24;
    }

    public static boolean isAtLeastO() {
        return VERSION.SDK_INT >= 26;
    }

    public static boolean isAtLeastP() {
        return VERSION.SDK_INT >= 28;
    }

    public static boolean isAtLeastQ() {
        if (BuildCompat.isAtLeastQ() || ((VERSION.CODENAME.equals("REL") && VERSION.SDK_INT >= 29) || (VERSION.CODENAME.length() == 1 && VERSION.CODENAME.charAt(0) >= 'Q' && VERSION.CODENAME.charAt(0) <= 'Z'))) {
            return true;
        }
        return false;
    }
}
