package androidx.core.content;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ProviderInfo;
import android.content.res.XmlResourceParser;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.Build.VERSION;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.webkit.MimeTypeMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map.Entry;
import org.xmlpull.v1.XmlPullParserException;

public class FileProvider extends ContentProvider {
    private static final String ATTR_NAME = "name";
    private static final String ATTR_PATH = "path";
    private static final String[] COLUMNS = {"_display_name", "_size"};
    private static final File DEVICE_ROOT = new File("/");
    private static final String META_DATA_FILE_PROVIDER_PATHS = "android.support.FILE_PROVIDER_PATHS";
    private static final String TAG_CACHE_PATH = "cache-path";
    private static final String TAG_EXTERNAL = "external-path";
    private static final String TAG_EXTERNAL_CACHE = "external-cache-path";
    private static final String TAG_EXTERNAL_FILES = "external-files-path";
    private static final String TAG_EXTERNAL_MEDIA = "external-media-path";
    private static final String TAG_FILES_PATH = "files-path";
    private static final String TAG_ROOT_PATH = "root-path";
    private static HashMap<String, PathStrategy> sCache = new HashMap<>();
    private PathStrategy mStrategy;

    interface PathStrategy {
        File getFileForUri(Uri uri);

        Uri getUriForFile(File file);
    }

    static class SimplePathStrategy implements PathStrategy {
        private final String mAuthority;
        private final HashMap<String, File> mRoots = new HashMap<>();

        SimplePathStrategy(String authority) {
            this.mAuthority = authority;
        }

        /* access modifiers changed from: 0000 */
        public void addRoot(String name, File root) {
            if (!TextUtils.isEmpty(name)) {
                try {
                    this.mRoots.put(name, root.getCanonicalFile());
                } catch (IOException e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Failed to resolve canonical path for ");
                    sb.append(root);
                    throw new IllegalArgumentException(sb.toString(), e);
                }
            } else {
                throw new IllegalArgumentException("Name must not be empty");
            }
        }

        public Uri getUriForFile(File file) {
            String path;
            try {
                String path2 = file.getCanonicalPath();
                Entry<String, File> mostSpecific = null;
                for (Entry<String, File> root : this.mRoots.entrySet()) {
                    String rootPath = ((File) root.getValue()).getPath();
                    if (path2.startsWith(rootPath) && (mostSpecific == null || rootPath.length() > ((File) mostSpecific.getValue()).getPath().length())) {
                        mostSpecific = root;
                    }
                }
                if (mostSpecific != null) {
                    String rootPath2 = ((File) mostSpecific.getValue()).getPath();
                    String str = "/";
                    if (rootPath2.endsWith(str)) {
                        path = path2.substring(rootPath2.length());
                    } else {
                        path = path2.substring(rootPath2.length() + 1);
                    }
                    StringBuilder sb = new StringBuilder();
                    sb.append(Uri.encode((String) mostSpecific.getKey()));
                    sb.append('/');
                    sb.append(Uri.encode(path, str));
                    return new Builder().scheme("content").authority(this.mAuthority).encodedPath(sb.toString()).build();
                }
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Failed to find configured root that contains ");
                sb2.append(path2);
                throw new IllegalArgumentException(sb2.toString());
            } catch (IOException e) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append("Failed to resolve canonical path for ");
                sb3.append(file);
                throw new IllegalArgumentException(sb3.toString());
            }
        }

        public File getFileForUri(Uri uri) {
            String path = uri.getEncodedPath();
            int splitIndex = path.indexOf(47, 1);
            String tag = Uri.decode(path.substring(1, splitIndex));
            String path2 = Uri.decode(path.substring(splitIndex + 1));
            File root = (File) this.mRoots.get(tag);
            if (root != null) {
                File file = new File(root, path2);
                try {
                    File file2 = file.getCanonicalFile();
                    if (file2.getPath().startsWith(root.getPath())) {
                        return file2;
                    }
                    throw new SecurityException("Resolved path jumped beyond configured root");
                } catch (IOException e) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Failed to resolve canonical path for ");
                    sb.append(file);
                    throw new IllegalArgumentException(sb.toString());
                }
            } else {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Unable to find configured root for ");
                sb2.append(uri);
                throw new IllegalArgumentException(sb2.toString());
            }
        }
    }

    public boolean onCreate() {
        return true;
    }

    public void attachInfo(Context context, ProviderInfo info) {
        super.attachInfo(context, info);
        if (info.exported) {
            throw new SecurityException("Provider must not be exported");
        } else if (info.grantUriPermissions) {
            this.mStrategy = getPathStrategy(context, info.authority);
        } else {
            throw new SecurityException("Provider must grant uri permissions");
        }
    }

    public static Uri getUriForFile(Context context, String authority, File file) {
        return getPathStrategy(context, authority).getUriForFile(file);
    }

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file = this.mStrategy.getFileForUri(uri);
        if (projection == null) {
            projection = COLUMNS;
        }
        String[] cols = new String[projection.length];
        Object[] values = new Object[projection.length];
        int i = 0;
        for (String col : projection) {
            String str = "_display_name";
            if (str.equals(col)) {
                cols[i] = str;
                int i2 = i + 1;
                values[i] = file.getName();
                i = i2;
            } else {
                String str2 = "_size";
                if (str2.equals(col)) {
                    cols[i] = str2;
                    int i3 = i + 1;
                    values[i] = Long.valueOf(file.length());
                    i = i3;
                }
            }
        }
        String[] cols2 = copyOf(cols, i);
        Object[] values2 = copyOf(values, i);
        MatrixCursor cursor = new MatrixCursor(cols2, 1);
        cursor.addRow(values2);
        return cursor;
    }

    public String getType(Uri uri) {
        File file = this.mStrategy.getFileForUri(uri);
        int lastDot = file.getName().lastIndexOf(46);
        if (lastDot >= 0) {
            String mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(file.getName().substring(lastDot + 1));
            if (mime != null) {
                return mime;
            }
        }
        return "application/octet-stream";
    }

    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("No external inserts");
    }

    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("No external updates");
    }

    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return this.mStrategy.getFileForUri(uri).delete() ? 1 : 0;
    }

    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        return ParcelFileDescriptor.open(this.mStrategy.getFileForUri(uri), modeToMode(mode));
    }

    private static PathStrategy getPathStrategy(Context context, String authority) {
        PathStrategy strat;
        synchronized (sCache) {
            strat = (PathStrategy) sCache.get(authority);
            if (strat == null) {
                try {
                    strat = parsePathStrategy(context, authority);
                    sCache.put(authority, strat);
                } catch (IOException e) {
                    throw new IllegalArgumentException("Failed to parse android.support.FILE_PROVIDER_PATHS meta-data", e);
                } catch (XmlPullParserException e2) {
                    throw new IllegalArgumentException("Failed to parse android.support.FILE_PROVIDER_PATHS meta-data", e2);
                }
            }
        }
        return strat;
    }

    private static PathStrategy parsePathStrategy(Context context, String authority) throws IOException, XmlPullParserException {
        SimplePathStrategy strat = new SimplePathStrategy(authority);
        ProviderInfo info = context.getPackageManager().resolveContentProvider(authority, 128);
        if (info != null) {
            XmlResourceParser in = info.loadXmlMetaData(context.getPackageManager(), META_DATA_FILE_PROVIDER_PATHS);
            if (in != null) {
                while (true) {
                    int next = in.next();
                    int type = next;
                    if (next == 1) {
                        return strat;
                    }
                    if (type == 2) {
                        String tag = in.getName();
                        String name = in.getAttributeValue(null, ATTR_NAME);
                        String path = in.getAttributeValue(null, ATTR_PATH);
                        File target = null;
                        if (TAG_ROOT_PATH.equals(tag)) {
                            target = DEVICE_ROOT;
                        } else if (TAG_FILES_PATH.equals(tag)) {
                            target = context.getFilesDir();
                        } else if (TAG_CACHE_PATH.equals(tag)) {
                            target = context.getCacheDir();
                        } else if (TAG_EXTERNAL.equals(tag)) {
                            target = Environment.getExternalStorageDirectory();
                        } else if (TAG_EXTERNAL_FILES.equals(tag)) {
                            File[] externalFilesDirs = ContextCompat.getExternalFilesDirs(context, null);
                            if (externalFilesDirs.length > 0) {
                                target = externalFilesDirs[0];
                            }
                        } else if (TAG_EXTERNAL_CACHE.equals(tag)) {
                            File[] externalCacheDirs = ContextCompat.getExternalCacheDirs(context);
                            if (externalCacheDirs.length > 0) {
                                target = externalCacheDirs[0];
                            }
                        } else if (VERSION.SDK_INT >= 21 && TAG_EXTERNAL_MEDIA.equals(tag)) {
                            File[] externalMediaDirs = context.getExternalMediaDirs();
                            if (externalMediaDirs.length > 0) {
                                target = externalMediaDirs[0];
                            }
                        }
                        if (target != null) {
                            strat.addRoot(name, buildPath(target, path));
                        }
                    }
                }
            } else {
                throw new IllegalArgumentException("Missing android.support.FILE_PROVIDER_PATHS meta-data");
            }
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("Couldn't find meta-data for provider with authority ");
            sb.append(authority);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    private static int modeToMode(String mode) {
        if ("r".equals(mode)) {
            return 268435456;
        }
        if ("w".equals(mode) || "wt".equals(mode)) {
            return 738197504;
        }
        if ("wa".equals(mode)) {
            return 704643072;
        }
        if ("rw".equals(mode)) {
            return 939524096;
        }
        if ("rwt".equals(mode)) {
            return 1006632960;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Invalid mode: ");
        sb.append(mode);
        throw new IllegalArgumentException(sb.toString());
    }

    private static File buildPath(File base, String... segments) {
        File cur = base;
        for (String segment : segments) {
            if (segment != null) {
                cur = new File(cur, segment);
            }
        }
        return cur;
    }

    private static String[] copyOf(String[] original, int newLength) {
        String[] result = new String[newLength];
        System.arraycopy(original, 0, result, 0, newLength);
        return result;
    }

    private static Object[] copyOf(Object[] original, int newLength) {
        Object[] result = new Object[newLength];
        System.arraycopy(original, 0, result, 0, newLength);
        return result;
    }
}
