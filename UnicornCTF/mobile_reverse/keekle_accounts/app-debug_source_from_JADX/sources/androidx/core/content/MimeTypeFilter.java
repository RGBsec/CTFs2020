package androidx.core.content;

import java.util.ArrayList;

public final class MimeTypeFilter {
    private MimeTypeFilter() {
    }

    private static boolean mimeTypeAgainstFilter(String[] mimeTypeParts, String[] filterParts) {
        if (filterParts.length != 2) {
            throw new IllegalArgumentException("Ill-formatted MIME type filter. Must be type/subtype.");
        } else if (filterParts[0].isEmpty() || filterParts[1].isEmpty()) {
            throw new IllegalArgumentException("Ill-formatted MIME type filter. Type or subtype empty.");
        } else if (mimeTypeParts.length != 2) {
            return false;
        } else {
            String str = "*";
            if (str.equals(filterParts[0]) || filterParts[0].equals(mimeTypeParts[0])) {
                return str.equals(filterParts[1]) || filterParts[1].equals(mimeTypeParts[1]);
            }
            return false;
        }
    }

    public static boolean matches(String mimeType, String filter) {
        if (mimeType == null) {
            return false;
        }
        String str = "/";
        return mimeTypeAgainstFilter(mimeType.split(str), filter.split(str));
    }

    public static String matches(String mimeType, String[] filters) {
        if (mimeType == null) {
            return null;
        }
        String str = "/";
        String[] mimeTypeParts = mimeType.split(str);
        for (String filter : filters) {
            if (mimeTypeAgainstFilter(mimeTypeParts, filter.split(str))) {
                return filter;
            }
        }
        return null;
    }

    public static String matches(String[] mimeTypes, String filter) {
        if (mimeTypes == null) {
            return null;
        }
        String str = "/";
        String[] filterParts = filter.split(str);
        for (String mimeType : mimeTypes) {
            if (mimeTypeAgainstFilter(mimeType.split(str), filterParts)) {
                return mimeType;
            }
        }
        return null;
    }

    public static String[] matchesMany(String[] mimeTypes, String filter) {
        if (mimeTypes == null) {
            return new String[0];
        }
        ArrayList<String> list = new ArrayList<>();
        String str = "/";
        String[] filterParts = filter.split(str);
        for (String mimeType : mimeTypes) {
            if (mimeTypeAgainstFilter(mimeType.split(str), filterParts)) {
                list.add(mimeType);
            }
        }
        return (String[]) list.toArray(new String[list.size()]);
    }
}
