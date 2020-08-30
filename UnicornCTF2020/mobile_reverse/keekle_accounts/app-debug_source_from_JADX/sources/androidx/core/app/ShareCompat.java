package androidx.core.app;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Parcelable;
import android.text.Html;
import android.text.Spanned;
import android.util.Log;
import android.view.ActionProvider;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ShareActionProvider;
import androidx.core.content.IntentCompat;
import java.util.ArrayList;

public final class ShareCompat {
    public static final String EXTRA_CALLING_ACTIVITY = "androidx.core.app.EXTRA_CALLING_ACTIVITY";
    public static final String EXTRA_CALLING_ACTIVITY_INTEROP = "android.support.v4.app.EXTRA_CALLING_ACTIVITY";
    public static final String EXTRA_CALLING_PACKAGE = "androidx.core.app.EXTRA_CALLING_PACKAGE";
    public static final String EXTRA_CALLING_PACKAGE_INTEROP = "android.support.v4.app.EXTRA_CALLING_PACKAGE";
    private static final String HISTORY_FILENAME_PREFIX = ".sharecompat_";

    public static class IntentBuilder {
        private Activity mActivity;
        private ArrayList<String> mBccAddresses;
        private ArrayList<String> mCcAddresses;
        private CharSequence mChooserTitle;
        private Intent mIntent;
        private ArrayList<Uri> mStreams;
        private ArrayList<String> mToAddresses;

        public static IntentBuilder from(Activity launchingActivity) {
            return new IntentBuilder(launchingActivity);
        }

        private IntentBuilder(Activity launchingActivity) {
            this.mActivity = launchingActivity;
            Intent action = new Intent().setAction("android.intent.action.SEND");
            this.mIntent = action;
            action.putExtra(ShareCompat.EXTRA_CALLING_PACKAGE, launchingActivity.getPackageName());
            this.mIntent.putExtra(ShareCompat.EXTRA_CALLING_PACKAGE_INTEROP, launchingActivity.getPackageName());
            this.mIntent.putExtra(ShareCompat.EXTRA_CALLING_ACTIVITY, launchingActivity.getComponentName());
            this.mIntent.putExtra(ShareCompat.EXTRA_CALLING_ACTIVITY_INTEROP, launchingActivity.getComponentName());
            this.mIntent.addFlags(524288);
        }

        public Intent getIntent() {
            ArrayList<String> arrayList = this.mToAddresses;
            if (arrayList != null) {
                combineArrayExtra("android.intent.extra.EMAIL", arrayList);
                this.mToAddresses = null;
            }
            ArrayList<String> arrayList2 = this.mCcAddresses;
            if (arrayList2 != null) {
                combineArrayExtra("android.intent.extra.CC", arrayList2);
                this.mCcAddresses = null;
            }
            ArrayList<String> arrayList3 = this.mBccAddresses;
            if (arrayList3 != null) {
                combineArrayExtra("android.intent.extra.BCC", arrayList3);
                this.mBccAddresses = null;
            }
            ArrayList<Uri> arrayList4 = this.mStreams;
            boolean z = true;
            if (arrayList4 == null || arrayList4.size() <= 1) {
                z = false;
            }
            boolean needsSendMultiple = z;
            String str = "android.intent.action.SEND_MULTIPLE";
            boolean isSendMultiple = this.mIntent.getAction().equals(str);
            String str2 = "android.intent.extra.STREAM";
            if (!needsSendMultiple && isSendMultiple) {
                this.mIntent.setAction("android.intent.action.SEND");
                ArrayList<Uri> arrayList5 = this.mStreams;
                if (arrayList5 == null || arrayList5.isEmpty()) {
                    this.mIntent.removeExtra(str2);
                } else {
                    this.mIntent.putExtra(str2, (Parcelable) this.mStreams.get(0));
                }
                this.mStreams = null;
            }
            if (needsSendMultiple && !isSendMultiple) {
                this.mIntent.setAction(str);
                ArrayList<Uri> arrayList6 = this.mStreams;
                if (arrayList6 == null || arrayList6.isEmpty()) {
                    this.mIntent.removeExtra(str2);
                } else {
                    this.mIntent.putParcelableArrayListExtra(str2, this.mStreams);
                }
            }
            return this.mIntent;
        }

        /* access modifiers changed from: 0000 */
        public Activity getActivity() {
            return this.mActivity;
        }

        private void combineArrayExtra(String extra, ArrayList<String> add) {
            String[] currentAddresses = this.mIntent.getStringArrayExtra(extra);
            int currentLength = currentAddresses != null ? currentAddresses.length : 0;
            String[] finalAddresses = new String[(add.size() + currentLength)];
            add.toArray(finalAddresses);
            if (currentAddresses != null) {
                System.arraycopy(currentAddresses, 0, finalAddresses, add.size(), currentLength);
            }
            this.mIntent.putExtra(extra, finalAddresses);
        }

        private void combineArrayExtra(String extra, String[] add) {
            Intent intent = getIntent();
            String[] old = intent.getStringArrayExtra(extra);
            int oldLength = old != null ? old.length : 0;
            String[] result = new String[(add.length + oldLength)];
            if (old != null) {
                System.arraycopy(old, 0, result, 0, oldLength);
            }
            System.arraycopy(add, 0, result, oldLength, add.length);
            intent.putExtra(extra, result);
        }

        public Intent createChooserIntent() {
            return Intent.createChooser(getIntent(), this.mChooserTitle);
        }

        public void startChooser() {
            this.mActivity.startActivity(createChooserIntent());
        }

        public IntentBuilder setChooserTitle(CharSequence title) {
            this.mChooserTitle = title;
            return this;
        }

        public IntentBuilder setChooserTitle(int resId) {
            return setChooserTitle(this.mActivity.getText(resId));
        }

        public IntentBuilder setType(String mimeType) {
            this.mIntent.setType(mimeType);
            return this;
        }

        public IntentBuilder setText(CharSequence text) {
            this.mIntent.putExtra("android.intent.extra.TEXT", text);
            return this;
        }

        public IntentBuilder setHtmlText(String htmlText) {
            this.mIntent.putExtra(IntentCompat.EXTRA_HTML_TEXT, htmlText);
            if (!this.mIntent.hasExtra("android.intent.extra.TEXT")) {
                setText(Html.fromHtml(htmlText));
            }
            return this;
        }

        public IntentBuilder setStream(Uri streamUri) {
            String str = "android.intent.action.SEND";
            if (!this.mIntent.getAction().equals(str)) {
                this.mIntent.setAction(str);
            }
            this.mStreams = null;
            this.mIntent.putExtra("android.intent.extra.STREAM", streamUri);
            return this;
        }

        public IntentBuilder addStream(Uri streamUri) {
            String str = "android.intent.extra.STREAM";
            Uri currentStream = (Uri) this.mIntent.getParcelableExtra(str);
            if (this.mStreams == null && currentStream == null) {
                return setStream(streamUri);
            }
            if (this.mStreams == null) {
                this.mStreams = new ArrayList<>();
            }
            if (currentStream != null) {
                this.mIntent.removeExtra(str);
                this.mStreams.add(currentStream);
            }
            this.mStreams.add(streamUri);
            return this;
        }

        public IntentBuilder setEmailTo(String[] addresses) {
            if (this.mToAddresses != null) {
                this.mToAddresses = null;
            }
            this.mIntent.putExtra("android.intent.extra.EMAIL", addresses);
            return this;
        }

        public IntentBuilder addEmailTo(String address) {
            if (this.mToAddresses == null) {
                this.mToAddresses = new ArrayList<>();
            }
            this.mToAddresses.add(address);
            return this;
        }

        public IntentBuilder addEmailTo(String[] addresses) {
            combineArrayExtra("android.intent.extra.EMAIL", addresses);
            return this;
        }

        public IntentBuilder setEmailCc(String[] addresses) {
            this.mIntent.putExtra("android.intent.extra.CC", addresses);
            return this;
        }

        public IntentBuilder addEmailCc(String address) {
            if (this.mCcAddresses == null) {
                this.mCcAddresses = new ArrayList<>();
            }
            this.mCcAddresses.add(address);
            return this;
        }

        public IntentBuilder addEmailCc(String[] addresses) {
            combineArrayExtra("android.intent.extra.CC", addresses);
            return this;
        }

        public IntentBuilder setEmailBcc(String[] addresses) {
            this.mIntent.putExtra("android.intent.extra.BCC", addresses);
            return this;
        }

        public IntentBuilder addEmailBcc(String address) {
            if (this.mBccAddresses == null) {
                this.mBccAddresses = new ArrayList<>();
            }
            this.mBccAddresses.add(address);
            return this;
        }

        public IntentBuilder addEmailBcc(String[] addresses) {
            combineArrayExtra("android.intent.extra.BCC", addresses);
            return this;
        }

        public IntentBuilder setSubject(String subject) {
            this.mIntent.putExtra("android.intent.extra.SUBJECT", subject);
            return this;
        }
    }

    public static class IntentReader {
        private static final String TAG = "IntentReader";
        private Activity mActivity;
        private ComponentName mCallingActivity;
        private String mCallingPackage;
        private Intent mIntent;
        private ArrayList<Uri> mStreams;

        public static IntentReader from(Activity activity) {
            return new IntentReader(activity);
        }

        private IntentReader(Activity activity) {
            this.mActivity = activity;
            this.mIntent = activity.getIntent();
            this.mCallingPackage = ShareCompat.getCallingPackage(activity);
            this.mCallingActivity = ShareCompat.getCallingActivity(activity);
        }

        public boolean isShareIntent() {
            String action = this.mIntent.getAction();
            return "android.intent.action.SEND".equals(action) || "android.intent.action.SEND_MULTIPLE".equals(action);
        }

        public boolean isSingleShare() {
            return "android.intent.action.SEND".equals(this.mIntent.getAction());
        }

        public boolean isMultipleShare() {
            return "android.intent.action.SEND_MULTIPLE".equals(this.mIntent.getAction());
        }

        public String getType() {
            return this.mIntent.getType();
        }

        public CharSequence getText() {
            return this.mIntent.getCharSequenceExtra("android.intent.extra.TEXT");
        }

        public String getHtmlText() {
            String result = this.mIntent.getStringExtra(IntentCompat.EXTRA_HTML_TEXT);
            if (result != null) {
                return result;
            }
            CharSequence text = getText();
            if (text instanceof Spanned) {
                return Html.toHtml((Spanned) text);
            }
            if (text == null) {
                return result;
            }
            if (VERSION.SDK_INT >= 16) {
                return Html.escapeHtml(text);
            }
            StringBuilder out = new StringBuilder();
            withinStyle(out, text, 0, text.length());
            return out.toString();
        }

        private static void withinStyle(StringBuilder out, CharSequence text, int start, int end) {
            int i = start;
            while (i < end) {
                char c = text.charAt(i);
                if (c == '<') {
                    out.append("&lt;");
                } else if (c == '>') {
                    out.append("&gt;");
                } else if (c == '&') {
                    out.append("&amp;");
                } else if (c > '~' || c < ' ') {
                    StringBuilder sb = new StringBuilder();
                    sb.append("&#");
                    sb.append(c);
                    sb.append(";");
                    out.append(sb.toString());
                } else if (c == ' ') {
                    while (i + 1 < end && text.charAt(i + 1) == ' ') {
                        out.append("&nbsp;");
                        i++;
                    }
                    out.append(' ');
                } else {
                    out.append(c);
                }
                i++;
            }
        }

        public Uri getStream() {
            return (Uri) this.mIntent.getParcelableExtra("android.intent.extra.STREAM");
        }

        public Uri getStream(int index) {
            String str = "android.intent.extra.STREAM";
            if (this.mStreams == null && isMultipleShare()) {
                this.mStreams = this.mIntent.getParcelableArrayListExtra(str);
            }
            ArrayList<Uri> arrayList = this.mStreams;
            if (arrayList != null) {
                return (Uri) arrayList.get(index);
            }
            if (index == 0) {
                return (Uri) this.mIntent.getParcelableExtra(str);
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Stream items available: ");
            sb.append(getStreamCount());
            sb.append(" index requested: ");
            sb.append(index);
            throw new IndexOutOfBoundsException(sb.toString());
        }

        public int getStreamCount() {
            String str = "android.intent.extra.STREAM";
            if (this.mStreams == null && isMultipleShare()) {
                this.mStreams = this.mIntent.getParcelableArrayListExtra(str);
            }
            ArrayList<Uri> arrayList = this.mStreams;
            if (arrayList != null) {
                return arrayList.size();
            }
            return this.mIntent.hasExtra(str) ? 1 : 0;
        }

        public String[] getEmailTo() {
            return this.mIntent.getStringArrayExtra("android.intent.extra.EMAIL");
        }

        public String[] getEmailCc() {
            return this.mIntent.getStringArrayExtra("android.intent.extra.CC");
        }

        public String[] getEmailBcc() {
            return this.mIntent.getStringArrayExtra("android.intent.extra.BCC");
        }

        public String getSubject() {
            return this.mIntent.getStringExtra("android.intent.extra.SUBJECT");
        }

        public String getCallingPackage() {
            return this.mCallingPackage;
        }

        public ComponentName getCallingActivity() {
            return this.mCallingActivity;
        }

        public Drawable getCallingActivityIcon() {
            if (this.mCallingActivity == null) {
                return null;
            }
            try {
                return this.mActivity.getPackageManager().getActivityIcon(this.mCallingActivity);
            } catch (NameNotFoundException e) {
                Log.e(TAG, "Could not retrieve icon for calling activity", e);
                return null;
            }
        }

        public Drawable getCallingApplicationIcon() {
            if (this.mCallingPackage == null) {
                return null;
            }
            try {
                return this.mActivity.getPackageManager().getApplicationIcon(this.mCallingPackage);
            } catch (NameNotFoundException e) {
                Log.e(TAG, "Could not retrieve icon for calling application", e);
                return null;
            }
        }

        public CharSequence getCallingApplicationLabel() {
            if (this.mCallingPackage == null) {
                return null;
            }
            PackageManager pm = this.mActivity.getPackageManager();
            try {
                return pm.getApplicationLabel(pm.getApplicationInfo(this.mCallingPackage, 0));
            } catch (NameNotFoundException e) {
                Log.e(TAG, "Could not retrieve label for calling application", e);
                return null;
            }
        }
    }

    private ShareCompat() {
    }

    public static String getCallingPackage(Activity calledActivity) {
        String result = calledActivity.getCallingPackage();
        if (result != null) {
            return result;
        }
        String result2 = calledActivity.getIntent().getStringExtra(EXTRA_CALLING_PACKAGE);
        if (result2 == null) {
            return calledActivity.getIntent().getStringExtra(EXTRA_CALLING_PACKAGE_INTEROP);
        }
        return result2;
    }

    public static ComponentName getCallingActivity(Activity calledActivity) {
        ComponentName result = calledActivity.getCallingActivity();
        if (result != null) {
            return result;
        }
        ComponentName result2 = (ComponentName) calledActivity.getIntent().getParcelableExtra(EXTRA_CALLING_ACTIVITY);
        if (result2 == null) {
            return (ComponentName) calledActivity.getIntent().getParcelableExtra(EXTRA_CALLING_ACTIVITY_INTEROP);
        }
        return result2;
    }

    public static void configureMenuItem(MenuItem item, IntentBuilder shareIntent) {
        ShareActionProvider provider;
        ActionProvider itemProvider = item.getActionProvider();
        if (!(itemProvider instanceof ShareActionProvider)) {
            provider = new ShareActionProvider(shareIntent.getActivity());
        } else {
            provider = (ShareActionProvider) itemProvider;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(HISTORY_FILENAME_PREFIX);
        sb.append(shareIntent.getActivity().getClass().getName());
        provider.setShareHistoryFileName(sb.toString());
        provider.setShareIntent(shareIntent.getIntent());
        item.setActionProvider(provider);
        if (VERSION.SDK_INT < 16 && !item.hasSubMenu()) {
            item.setIntent(shareIntent.createChooserIntent());
        }
    }

    public static void configureMenuItem(Menu menu, int menuItemId, IntentBuilder shareIntent) {
        MenuItem item = menu.findItem(menuItemId);
        if (item != null) {
            configureMenuItem(item, shareIntent);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Could not find menu item with id ");
        sb.append(menuItemId);
        sb.append(" in the supplied menu");
        throw new IllegalArgumentException(sb.toString());
    }
}
