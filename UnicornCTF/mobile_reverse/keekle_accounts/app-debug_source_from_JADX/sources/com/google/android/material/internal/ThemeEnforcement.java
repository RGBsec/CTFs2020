package com.google.android.material.internal;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import androidx.appcompat.widget.TintTypedArray;
import com.google.android.material.C0078R;

public final class ThemeEnforcement {
    private static final int[] APPCOMPAT_CHECK_ATTRS = {C0078R.attr.colorPrimary};
    private static final String APPCOMPAT_THEME_NAME = "Theme.AppCompat";
    private static final int[] MATERIAL_CHECK_ATTRS = {C0078R.attr.colorSecondary};
    private static final String MATERIAL_THEME_NAME = "Theme.MaterialComponents";

    private ThemeEnforcement() {
    }

    public static TypedArray obtainStyledAttributes(Context context, AttributeSet set, int[] attrs, int defStyleAttr, int defStyleRes, int... textAppearanceResIndices) {
        checkCompatibleTheme(context, set, defStyleAttr, defStyleRes);
        checkTextAppearance(context, set, attrs, defStyleAttr, defStyleRes, textAppearanceResIndices);
        return context.obtainStyledAttributes(set, attrs, defStyleAttr, defStyleRes);
    }

    public static TintTypedArray obtainTintedStyledAttributes(Context context, AttributeSet set, int[] attrs, int defStyleAttr, int defStyleRes, int... textAppearanceResIndices) {
        checkCompatibleTheme(context, set, defStyleAttr, defStyleRes);
        checkTextAppearance(context, set, attrs, defStyleAttr, defStyleRes, textAppearanceResIndices);
        return TintTypedArray.obtainStyledAttributes(context, set, attrs, defStyleAttr, defStyleRes);
    }

    private static void checkCompatibleTheme(Context context, AttributeSet set, int defStyleAttr, int defStyleRes) {
        TypedArray a = context.obtainStyledAttributes(set, C0078R.styleable.ThemeEnforcement, defStyleAttr, defStyleRes);
        boolean enforceMaterialTheme = a.getBoolean(C0078R.styleable.ThemeEnforcement_enforceMaterialTheme, false);
        a.recycle();
        if (enforceMaterialTheme) {
            checkMaterialTheme(context);
        }
        checkAppCompatTheme(context);
    }

    private static void checkTextAppearance(Context context, AttributeSet set, int[] attrs, int defStyleAttr, int defStyleRes, int... textAppearanceResIndices) {
        TypedArray themeEnforcementAttrs = context.obtainStyledAttributes(set, C0078R.styleable.ThemeEnforcement, defStyleAttr, defStyleRes);
        boolean validTextAppearance = false;
        if (!themeEnforcementAttrs.getBoolean(C0078R.styleable.ThemeEnforcement_enforceTextAppearance, false)) {
            themeEnforcementAttrs.recycle();
            return;
        }
        if (textAppearanceResIndices != null && textAppearanceResIndices.length != 0) {
            validTextAppearance = isCustomTextAppearanceValid(context, set, attrs, defStyleAttr, defStyleRes, textAppearanceResIndices);
        } else if (themeEnforcementAttrs.getResourceId(C0078R.styleable.ThemeEnforcement_android_textAppearance, -1) != -1) {
            validTextAppearance = true;
        }
        themeEnforcementAttrs.recycle();
        if (!validTextAppearance) {
            throw new IllegalArgumentException("This component requires that you specify a valid TextAppearance attribute. Update your app theme to inherit from Theme.MaterialComponents (or a descendant).");
        }
    }

    private static boolean isCustomTextAppearanceValid(Context context, AttributeSet set, int[] attrs, int defStyleAttr, int defStyleRes, int... textAppearanceResIndices) {
        TypedArray componentAttrs = context.obtainStyledAttributes(set, attrs, defStyleAttr, defStyleRes);
        for (int customTextAppearanceIndex : textAppearanceResIndices) {
            if (componentAttrs.getResourceId(customTextAppearanceIndex, -1) == -1) {
                componentAttrs.recycle();
                return false;
            }
        }
        componentAttrs.recycle();
        return true;
    }

    public static void checkAppCompatTheme(Context context) {
        checkTheme(context, APPCOMPAT_CHECK_ATTRS, APPCOMPAT_THEME_NAME);
    }

    public static void checkMaterialTheme(Context context) {
        checkTheme(context, MATERIAL_CHECK_ATTRS, MATERIAL_THEME_NAME);
    }

    public static boolean isAppCompatTheme(Context context) {
        return isTheme(context, APPCOMPAT_CHECK_ATTRS);
    }

    public static boolean isMaterialTheme(Context context) {
        return isTheme(context, MATERIAL_CHECK_ATTRS);
    }

    private static boolean isTheme(Context context, int[] themeAttributes) {
        TypedArray a = context.obtainStyledAttributes(themeAttributes);
        boolean success = a.hasValue(0);
        a.recycle();
        return success;
    }

    private static void checkTheme(Context context, int[] themeAttributes, String themeName) {
        if (!isTheme(context, themeAttributes)) {
            StringBuilder sb = new StringBuilder();
            sb.append("The style on this component requires your app theme to be ");
            sb.append(themeName);
            sb.append(" (or a descendant).");
            throw new IllegalArgumentException(sb.toString());
        }
    }
}
