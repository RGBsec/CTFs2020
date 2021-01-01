package androidx.appcompat.widget;

import android.app.SearchManager;
import android.app.SearchableInfo;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.ConstantState;
import android.net.Uri;
import android.net.Uri.Builder;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.TextAppearanceSpan;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.C0003R;
import androidx.core.content.ContextCompat;
import androidx.cursoradapter.widget.ResourceCursorAdapter;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.WeakHashMap;

class SuggestionsAdapter extends ResourceCursorAdapter implements OnClickListener {
    private static final boolean DBG = false;
    static final int INVALID_INDEX = -1;
    private static final String LOG_TAG = "SuggestionsAdapter";
    private static final int QUERY_LIMIT = 50;
    static final int REFINE_ALL = 2;
    static final int REFINE_BY_ENTRY = 1;
    static final int REFINE_NONE = 0;
    private boolean mClosed = false;
    private final int mCommitIconResId;
    private int mFlagsCol = -1;
    private int mIconName1Col = -1;
    private int mIconName2Col = -1;
    private final WeakHashMap<String, ConstantState> mOutsideDrawablesCache;
    private final Context mProviderContext;
    private int mQueryRefinement = 1;
    private final SearchManager mSearchManager = ((SearchManager) this.mContext.getSystemService("search"));
    private final SearchView mSearchView;
    private final SearchableInfo mSearchable;
    private int mText1Col = -1;
    private int mText2Col = -1;
    private int mText2UrlCol = -1;
    private ColorStateList mUrlColor;

    private static final class ChildViewCache {
        public final ImageView mIcon1;
        public final ImageView mIcon2;
        public final ImageView mIconRefine;
        public final TextView mText1;
        public final TextView mText2;

        public ChildViewCache(View v) {
            this.mText1 = (TextView) v.findViewById(16908308);
            this.mText2 = (TextView) v.findViewById(16908309);
            this.mIcon1 = (ImageView) v.findViewById(16908295);
            this.mIcon2 = (ImageView) v.findViewById(16908296);
            this.mIconRefine = (ImageView) v.findViewById(C0003R.C0005id.edit_query);
        }
    }

    public SuggestionsAdapter(Context context, SearchView searchView, SearchableInfo searchable, WeakHashMap<String, ConstantState> outsideDrawablesCache) {
        super(context, searchView.getSuggestionRowLayout(), (Cursor) null, true);
        this.mSearchView = searchView;
        this.mSearchable = searchable;
        this.mCommitIconResId = searchView.getSuggestionCommitIconResId();
        this.mProviderContext = context;
        this.mOutsideDrawablesCache = outsideDrawablesCache;
    }

    public void setQueryRefinement(int refineWhat) {
        this.mQueryRefinement = refineWhat;
    }

    public int getQueryRefinement() {
        return this.mQueryRefinement;
    }

    public boolean hasStableIds() {
        return false;
    }

    public Cursor runQueryOnBackgroundThread(CharSequence constraint) {
        String query = constraint == null ? "" : constraint.toString();
        if (this.mSearchView.getVisibility() != 0 || this.mSearchView.getWindowVisibility() != 0) {
            return null;
        }
        try {
            Cursor cursor = getSearchManagerSuggestions(this.mSearchable, query, 50);
            if (cursor != null) {
                cursor.getCount();
                return cursor;
            }
        } catch (RuntimeException e) {
            Log.w(LOG_TAG, "Search suggestions query threw an exception.", e);
        }
        return null;
    }

    public void close() {
        changeCursor(null);
        this.mClosed = true;
    }

    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
        updateSpinnerState(getCursor());
    }

    public void notifyDataSetInvalidated() {
        super.notifyDataSetInvalidated();
        updateSpinnerState(getCursor());
    }

    private void updateSpinnerState(Cursor cursor) {
        Bundle extras = cursor != null ? cursor.getExtras() : null;
        if (extras != null && !extras.getBoolean("in_progress")) {
        }
    }

    public void changeCursor(Cursor c) {
        boolean z = this.mClosed;
        String str = LOG_TAG;
        if (z) {
            Log.w(str, "Tried to change cursor after adapter was closed.");
            if (c != null) {
                c.close();
            }
            return;
        }
        try {
            super.changeCursor(c);
            if (c != null) {
                this.mText1Col = c.getColumnIndex("suggest_text_1");
                this.mText2Col = c.getColumnIndex("suggest_text_2");
                this.mText2UrlCol = c.getColumnIndex("suggest_text_2_url");
                this.mIconName1Col = c.getColumnIndex("suggest_icon_1");
                this.mIconName2Col = c.getColumnIndex("suggest_icon_2");
                this.mFlagsCol = c.getColumnIndex("suggest_flags");
            }
        } catch (Exception e) {
            Log.e(str, "error changing cursor and caching columns", e);
        }
    }

    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        View v = super.newView(context, cursor, parent);
        v.setTag(new ChildViewCache(v));
        ((ImageView) v.findViewById(C0003R.C0005id.edit_query)).setImageResource(this.mCommitIconResId);
        return v;
    }

    public void bindView(View view, Context context, Cursor cursor) {
        CharSequence text2;
        ChildViewCache views = (ChildViewCache) view.getTag();
        int flags = 0;
        int i = this.mFlagsCol;
        if (i != -1) {
            flags = cursor.getInt(i);
        }
        if (views.mText1 != null) {
            setViewText(views.mText1, getStringOrNull(cursor, this.mText1Col));
        }
        if (views.mText2 != null) {
            CharSequence text22 = getStringOrNull(cursor, this.mText2UrlCol);
            if (text22 != null) {
                text2 = formatUrl(text22);
            } else {
                text2 = getStringOrNull(cursor, this.mText2Col);
            }
            if (TextUtils.isEmpty(text2)) {
                if (views.mText1 != null) {
                    views.mText1.setSingleLine(false);
                    views.mText1.setMaxLines(2);
                }
            } else if (views.mText1 != null) {
                views.mText1.setSingleLine(true);
                views.mText1.setMaxLines(1);
            }
            setViewText(views.mText2, text2);
        }
        if (views.mIcon1 != null) {
            setViewDrawable(views.mIcon1, getIcon1(cursor), 4);
        }
        if (views.mIcon2 != null) {
            setViewDrawable(views.mIcon2, getIcon2(cursor), 8);
        }
        int i2 = this.mQueryRefinement;
        if (i2 == 2 || (i2 == 1 && (flags & 1) != 0)) {
            views.mIconRefine.setVisibility(0);
            views.mIconRefine.setTag(views.mText1.getText());
            views.mIconRefine.setOnClickListener(this);
            return;
        }
        views.mIconRefine.setVisibility(8);
    }

    public void onClick(View v) {
        Object tag = v.getTag();
        if (tag instanceof CharSequence) {
            this.mSearchView.onQueryRefine((CharSequence) tag);
        }
    }

    private CharSequence formatUrl(CharSequence url) {
        if (this.mUrlColor == null) {
            TypedValue colorValue = new TypedValue();
            this.mContext.getTheme().resolveAttribute(C0003R.attr.textColorSearchUrl, colorValue, true);
            this.mUrlColor = this.mContext.getResources().getColorStateList(colorValue.resourceId);
        }
        SpannableString text = new SpannableString(url);
        TextAppearanceSpan textAppearanceSpan = new TextAppearanceSpan(null, 0, 0, this.mUrlColor, null);
        text.setSpan(textAppearanceSpan, 0, url.length(), 33);
        return text;
    }

    private void setViewText(TextView v, CharSequence text) {
        v.setText(text);
        if (TextUtils.isEmpty(text)) {
            v.setVisibility(8);
        } else {
            v.setVisibility(0);
        }
    }

    private Drawable getIcon1(Cursor cursor) {
        int i = this.mIconName1Col;
        if (i == -1) {
            return null;
        }
        Drawable drawable = getDrawableFromResourceValue(cursor.getString(i));
        if (drawable != null) {
            return drawable;
        }
        return getDefaultIcon1(cursor);
    }

    private Drawable getIcon2(Cursor cursor) {
        int i = this.mIconName2Col;
        if (i == -1) {
            return null;
        }
        return getDrawableFromResourceValue(cursor.getString(i));
    }

    private void setViewDrawable(ImageView v, Drawable drawable, int nullVisibility) {
        v.setImageDrawable(drawable);
        if (drawable == null) {
            v.setVisibility(nullVisibility);
            return;
        }
        v.setVisibility(0);
        drawable.setVisible(false, false);
        drawable.setVisible(true, false);
    }

    public CharSequence convertToString(Cursor cursor) {
        if (cursor == null) {
            return null;
        }
        String query = getColumnString(cursor, "suggest_intent_query");
        if (query != null) {
            return query;
        }
        if (this.mSearchable.shouldRewriteQueryFromData()) {
            String data = getColumnString(cursor, "suggest_intent_data");
            if (data != null) {
                return data;
            }
        }
        if (this.mSearchable.shouldRewriteQueryFromText()) {
            String text1 = getColumnString(cursor, "suggest_text_1");
            if (text1 != null) {
                return text1;
            }
        }
        return null;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        try {
            return super.getView(position, convertView, parent);
        } catch (RuntimeException e) {
            Log.w(LOG_TAG, "Search suggestions cursor threw exception.", e);
            View v = newView(this.mContext, this.mCursor, parent);
            if (v != null) {
                ((ChildViewCache) v.getTag()).mText1.setText(e.toString());
            }
            return v;
        }
    }

    public View getDropDownView(int position, View convertView, ViewGroup parent) {
        try {
            return super.getDropDownView(position, convertView, parent);
        } catch (RuntimeException e) {
            Log.w(LOG_TAG, "Search suggestions cursor threw exception.", e);
            View v = newDropDownView(this.mContext, this.mCursor, parent);
            if (v != null) {
                ((ChildViewCache) v.getTag()).mText1.setText(e.toString());
            }
            return v;
        }
    }

    private Drawable getDrawableFromResourceValue(String drawableId) {
        if (drawableId == null || drawableId.isEmpty() || "0".equals(drawableId)) {
            return null;
        }
        try {
            int resourceId = Integer.parseInt(drawableId);
            StringBuilder sb = new StringBuilder();
            sb.append("android.resource://");
            sb.append(this.mProviderContext.getPackageName());
            sb.append("/");
            sb.append(resourceId);
            String drawableUri = sb.toString();
            Drawable drawable = checkIconCache(drawableUri);
            if (drawable != null) {
                return drawable;
            }
            Drawable drawable2 = ContextCompat.getDrawable(this.mProviderContext, resourceId);
            storeInIconCache(drawableUri, drawable2);
            return drawable2;
        } catch (NumberFormatException e) {
            Drawable drawable3 = checkIconCache(drawableId);
            if (drawable3 != null) {
                return drawable3;
            }
            Drawable drawable4 = getDrawable(Uri.parse(drawableId));
            storeInIconCache(drawableId, drawable4);
            return drawable4;
        } catch (NotFoundException e2) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Icon resource not found: ");
            sb2.append(drawableId);
            Log.w(LOG_TAG, sb2.toString());
            return null;
        }
    }

    private Drawable getDrawable(Uri uri) {
        InputStream stream;
        String str = "Error closing icon stream for ";
        String str2 = LOG_TAG;
        try {
            if ("android.resource".equals(uri.getScheme())) {
                return getDrawableFromResourceUri(uri);
            }
            stream = this.mProviderContext.getContentResolver().openInputStream(uri);
            if (stream != null) {
                Drawable createFromStream = Drawable.createFromStream(stream, null);
                try {
                    stream.close();
                } catch (IOException ex) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(str);
                    sb.append(uri);
                    Log.e(str2, sb.toString(), ex);
                }
                return createFromStream;
            }
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Failed to open ");
            sb2.append(uri);
            throw new FileNotFoundException(sb2.toString());
        } catch (NotFoundException e) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append("Resource does not exist: ");
            sb3.append(uri);
            throw new FileNotFoundException(sb3.toString());
        } catch (FileNotFoundException fnfe) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append("Icon not found: ");
            sb4.append(uri);
            sb4.append(", ");
            sb4.append(fnfe.getMessage());
            Log.w(str2, sb4.toString());
            return null;
        } catch (Throwable th) {
            try {
                stream.close();
            } catch (IOException ex2) {
                StringBuilder sb5 = new StringBuilder();
                sb5.append(str);
                sb5.append(uri);
                Log.e(str2, sb5.toString(), ex2);
            }
            throw th;
        }
    }

    private Drawable checkIconCache(String resourceUri) {
        ConstantState cached = (ConstantState) this.mOutsideDrawablesCache.get(resourceUri);
        if (cached == null) {
            return null;
        }
        return cached.newDrawable();
    }

    private void storeInIconCache(String resourceUri, Drawable drawable) {
        if (drawable != null) {
            this.mOutsideDrawablesCache.put(resourceUri, drawable.getConstantState());
        }
    }

    private Drawable getDefaultIcon1(Cursor cursor) {
        Drawable drawable = getActivityIconWithCache(this.mSearchable.getSearchActivity());
        if (drawable != null) {
            return drawable;
        }
        return this.mContext.getPackageManager().getDefaultActivityIcon();
    }

    /* JADX WARNING: type inference failed for: r2v0 */
    /* JADX WARNING: type inference failed for: r2v1, types: [java.lang.Object] */
    /* JADX WARNING: type inference failed for: r2v2, types: [android.graphics.drawable.Drawable$ConstantState] */
    /* JADX WARNING: type inference failed for: r2v3, types: [android.graphics.drawable.Drawable] */
    /* JADX WARNING: type inference failed for: r2v6, types: [android.graphics.drawable.Drawable] */
    /* JADX WARNING: type inference failed for: r2v7 */
    /* JADX WARNING: type inference failed for: r2v8 */
    /* JADX WARNING: Multi-variable type inference failed. Error: jadx.core.utils.exceptions.JadxRuntimeException: No candidate types for var: r2v0
      assigns: [?[int, float, boolean, short, byte, char, OBJECT, ARRAY], android.graphics.drawable.Drawable, android.graphics.drawable.Drawable$ConstantState]
      uses: [java.lang.Object, android.graphics.drawable.Drawable]
      mth insns count: 21
    	at jadx.core.dex.visitors.typeinference.TypeSearch.fillTypeCandidates(TypeSearch.java:237)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.typeinference.TypeSearch.run(TypeSearch.java:53)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.runMultiVariableSearch(TypeInferenceVisitor.java:99)
    	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:92)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:27)
    	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:14)
    	at java.base/java.util.ArrayList.forEach(ArrayList.java:1540)
    	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:14)
    	at jadx.core.ProcessClass.process(ProcessClass.java:30)
    	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:311)
    	at jadx.api.JavaClass.decompile(JavaClass.java:62)
    	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:217)
     */
    /* JADX WARNING: Unknown variable types count: 3 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private android.graphics.drawable.Drawable getActivityIconWithCache(android.content.ComponentName r5) {
        /*
            r4 = this;
            java.lang.String r0 = r5.flattenToShortString()
            java.util.WeakHashMap<java.lang.String, android.graphics.drawable.Drawable$ConstantState> r1 = r4.mOutsideDrawablesCache
            boolean r1 = r1.containsKey(r0)
            r2 = 0
            if (r1 == 0) goto L_0x0023
            java.util.WeakHashMap<java.lang.String, android.graphics.drawable.Drawable$ConstantState> r1 = r4.mOutsideDrawablesCache
            java.lang.Object r1 = r1.get(r0)
            android.graphics.drawable.Drawable$ConstantState r1 = (android.graphics.drawable.Drawable.ConstantState) r1
            if (r1 != 0) goto L_0x0018
            goto L_0x0022
        L_0x0018:
            android.content.Context r2 = r4.mProviderContext
            android.content.res.Resources r2 = r2.getResources()
            android.graphics.drawable.Drawable r2 = r1.newDrawable(r2)
        L_0x0022:
            return r2
        L_0x0023:
            android.graphics.drawable.Drawable r1 = r4.getActivityIcon(r5)
            if (r1 != 0) goto L_0x002a
            goto L_0x002e
        L_0x002a:
            android.graphics.drawable.Drawable$ConstantState r2 = r1.getConstantState()
        L_0x002e:
            java.util.WeakHashMap<java.lang.String, android.graphics.drawable.Drawable$ConstantState> r3 = r4.mOutsideDrawablesCache
            r3.put(r0, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.SuggestionsAdapter.getActivityIconWithCache(android.content.ComponentName):android.graphics.drawable.Drawable");
    }

    private Drawable getActivityIcon(ComponentName component) {
        String str = LOG_TAG;
        PackageManager pm = this.mContext.getPackageManager();
        try {
            ActivityInfo activityInfo = pm.getActivityInfo(component, 128);
            int iconId = activityInfo.getIconResource();
            if (iconId == 0) {
                return null;
            }
            Drawable drawable = pm.getDrawable(component.getPackageName(), iconId, activityInfo.applicationInfo);
            if (drawable != null) {
                return drawable;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Invalid icon resource ");
            sb.append(iconId);
            sb.append(" for ");
            sb.append(component.flattenToShortString());
            Log.w(str, sb.toString());
            return null;
        } catch (NameNotFoundException ex) {
            Log.w(str, ex.toString());
            return null;
        }
    }

    public static String getColumnString(Cursor cursor, String columnName) {
        return getStringOrNull(cursor, cursor.getColumnIndex(columnName));
    }

    private static String getStringOrNull(Cursor cursor, int col) {
        if (col == -1) {
            return null;
        }
        try {
            return cursor.getString(col);
        } catch (Exception e) {
            Log.e(LOG_TAG, "unexpected error retrieving valid column from cursor, did the remote process die?", e);
            return null;
        }
    }

    /* access modifiers changed from: 0000 */
    public Drawable getDrawableFromResourceUri(Uri uri) throws FileNotFoundException {
        int id;
        String authority = uri.getAuthority();
        if (!TextUtils.isEmpty(authority)) {
            try {
                Resources r = this.mContext.getPackageManager().getResourcesForApplication(authority);
                List<String> path = uri.getPathSegments();
                if (path != null) {
                    int len = path.size();
                    if (len == 1) {
                        try {
                            id = Integer.parseInt((String) path.get(0));
                        } catch (NumberFormatException e) {
                            StringBuilder sb = new StringBuilder();
                            sb.append("Single path segment is not a resource ID: ");
                            sb.append(uri);
                            throw new FileNotFoundException(sb.toString());
                        }
                    } else if (len == 2) {
                        id = r.getIdentifier((String) path.get(1), (String) path.get(0), authority);
                    } else {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("More than two path segments: ");
                        sb2.append(uri);
                        throw new FileNotFoundException(sb2.toString());
                    }
                    if (id != 0) {
                        return r.getDrawable(id);
                    }
                    StringBuilder sb3 = new StringBuilder();
                    sb3.append("No resource found for: ");
                    sb3.append(uri);
                    throw new FileNotFoundException(sb3.toString());
                }
                StringBuilder sb4 = new StringBuilder();
                sb4.append("No path: ");
                sb4.append(uri);
                throw new FileNotFoundException(sb4.toString());
            } catch (NameNotFoundException e2) {
                StringBuilder sb5 = new StringBuilder();
                sb5.append("No package found for authority: ");
                sb5.append(uri);
                throw new FileNotFoundException(sb5.toString());
            }
        } else {
            StringBuilder sb6 = new StringBuilder();
            sb6.append("No authority: ");
            sb6.append(uri);
            throw new FileNotFoundException(sb6.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public Cursor getSearchManagerSuggestions(SearchableInfo searchable, String query, int limit) {
        String[] selArgs;
        if (searchable == null) {
            return null;
        }
        String authority = searchable.getSuggestAuthority();
        if (authority == null) {
            return null;
        }
        String str = "";
        Builder uriBuilder = new Builder().scheme("content").authority(authority).query(str).fragment(str);
        String contentPath = searchable.getSuggestPath();
        if (contentPath != null) {
            uriBuilder.appendEncodedPath(contentPath);
        }
        uriBuilder.appendPath("search_suggest_query");
        String selection = searchable.getSuggestSelection();
        if (selection != null) {
            selArgs = new String[]{query};
        } else {
            uriBuilder.appendPath(query);
            selArgs = null;
        }
        if (limit > 0) {
            uriBuilder.appendQueryParameter("limit", String.valueOf(limit));
        }
        return this.mContext.getContentResolver().query(uriBuilder.build(), null, selection, selArgs, null);
    }
}
