package androidx.appcompat.widget;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.database.DataSetObservable;
import android.os.AsyncTask;
import android.text.TextUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ActivityChooserModel extends DataSetObservable {
    static final String ATTRIBUTE_ACTIVITY = "activity";
    static final String ATTRIBUTE_TIME = "time";
    static final String ATTRIBUTE_WEIGHT = "weight";
    static final boolean DEBUG = false;
    private static final int DEFAULT_ACTIVITY_INFLATION = 5;
    private static final float DEFAULT_HISTORICAL_RECORD_WEIGHT = 1.0f;
    public static final String DEFAULT_HISTORY_FILE_NAME = "activity_choser_model_history.xml";
    public static final int DEFAULT_HISTORY_MAX_LENGTH = 50;
    private static final String HISTORY_FILE_EXTENSION = ".xml";
    private static final int INVALID_INDEX = -1;
    static final String LOG_TAG = ActivityChooserModel.class.getSimpleName();
    static final String TAG_HISTORICAL_RECORD = "historical-record";
    static final String TAG_HISTORICAL_RECORDS = "historical-records";
    private static final Map<String, ActivityChooserModel> sDataModelRegistry = new HashMap();
    private static final Object sRegistryLock = new Object();
    private final List<ActivityResolveInfo> mActivities = new ArrayList();
    private OnChooseActivityListener mActivityChoserModelPolicy;
    private ActivitySorter mActivitySorter = new DefaultSorter();
    boolean mCanReadHistoricalData = true;
    final Context mContext;
    private final List<HistoricalRecord> mHistoricalRecords = new ArrayList();
    private boolean mHistoricalRecordsChanged = true;
    final String mHistoryFileName;
    private int mHistoryMaxSize = 50;
    private final Object mInstanceLock = new Object();
    private Intent mIntent;
    private boolean mReadShareHistoryCalled = false;
    private boolean mReloadActivities = false;

    public interface ActivityChooserModelClient {
        void setActivityChooserModel(ActivityChooserModel activityChooserModel);
    }

    public static final class ActivityResolveInfo implements Comparable<ActivityResolveInfo> {
        public final ResolveInfo resolveInfo;
        public float weight;

        public ActivityResolveInfo(ResolveInfo resolveInfo2) {
            this.resolveInfo = resolveInfo2;
        }

        public int hashCode() {
            return Float.floatToIntBits(this.weight) + 31;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            if (Float.floatToIntBits(this.weight) != Float.floatToIntBits(((ActivityResolveInfo) obj).weight)) {
                return false;
            }
            return true;
        }

        public int compareTo(ActivityResolveInfo another) {
            return Float.floatToIntBits(another.weight) - Float.floatToIntBits(this.weight);
        }

        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("[");
            builder.append("resolveInfo:");
            builder.append(this.resolveInfo.toString());
            builder.append("; weight:");
            builder.append(new BigDecimal((double) this.weight));
            builder.append("]");
            return builder.toString();
        }
    }

    public interface ActivitySorter {
        void sort(Intent intent, List<ActivityResolveInfo> list, List<HistoricalRecord> list2);
    }

    private static final class DefaultSorter implements ActivitySorter {
        private static final float WEIGHT_DECAY_COEFFICIENT = 0.95f;
        private final Map<ComponentName, ActivityResolveInfo> mPackageNameToActivityMap = new HashMap();

        DefaultSorter() {
        }

        public void sort(Intent intent, List<ActivityResolveInfo> activities, List<HistoricalRecord> historicalRecords) {
            Map<ComponentName, ActivityResolveInfo> componentNameToActivityMap = this.mPackageNameToActivityMap;
            componentNameToActivityMap.clear();
            int activityCount = activities.size();
            for (int i = 0; i < activityCount; i++) {
                ActivityResolveInfo activity = (ActivityResolveInfo) activities.get(i);
                activity.weight = 0.0f;
                componentNameToActivityMap.put(new ComponentName(activity.resolveInfo.activityInfo.packageName, activity.resolveInfo.activityInfo.name), activity);
            }
            int lastShareIndex = historicalRecords.size() - 1;
            float nextRecordWeight = ActivityChooserModel.DEFAULT_HISTORICAL_RECORD_WEIGHT;
            for (int i2 = lastShareIndex; i2 >= 0; i2--) {
                HistoricalRecord historicalRecord = (HistoricalRecord) historicalRecords.get(i2);
                ActivityResolveInfo activity2 = (ActivityResolveInfo) componentNameToActivityMap.get(historicalRecord.activity);
                if (activity2 != null) {
                    activity2.weight += historicalRecord.weight * nextRecordWeight;
                    nextRecordWeight *= WEIGHT_DECAY_COEFFICIENT;
                }
            }
            Collections.sort(activities);
        }
    }

    public static final class HistoricalRecord {
        public final ComponentName activity;
        public final long time;
        public final float weight;

        public HistoricalRecord(String activityName, long time2, float weight2) {
            this(ComponentName.unflattenFromString(activityName), time2, weight2);
        }

        public HistoricalRecord(ComponentName activityName, long time2, float weight2) {
            this.activity = activityName;
            this.time = time2;
            this.weight = weight2;
        }

        public int hashCode() {
            int i = 1 * 31;
            ComponentName componentName = this.activity;
            int result = (i + (componentName == null ? 0 : componentName.hashCode())) * 31;
            long j = this.time;
            return ((result + ((int) (j ^ (j >>> 32)))) * 31) + Float.floatToIntBits(this.weight);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            HistoricalRecord other = (HistoricalRecord) obj;
            ComponentName componentName = this.activity;
            if (componentName == null) {
                if (other.activity != null) {
                    return false;
                }
            } else if (!componentName.equals(other.activity)) {
                return false;
            }
            if (this.time == other.time && Float.floatToIntBits(this.weight) == Float.floatToIntBits(other.weight)) {
                return true;
            }
            return false;
        }

        public String toString() {
            StringBuilder builder = new StringBuilder();
            builder.append("[");
            builder.append("; activity:");
            builder.append(this.activity);
            builder.append("; time:");
            builder.append(this.time);
            builder.append("; weight:");
            builder.append(new BigDecimal((double) this.weight));
            builder.append("]");
            return builder.toString();
        }
    }

    public interface OnChooseActivityListener {
        boolean onChooseActivity(ActivityChooserModel activityChooserModel, Intent intent);
    }

    private final class PersistHistoryAsyncTask extends AsyncTask<Object, Void, Void> {
        PersistHistoryAsyncTask() {
        }

        /* JADX WARNING: Removed duplicated region for block: B:27:0x00af A[SYNTHETIC, Splitter:B:27:0x00af] */
        /* JADX WARNING: Removed duplicated region for block: B:35:0x00d5 A[SYNTHETIC, Splitter:B:35:0x00d5] */
        /* JADX WARNING: Removed duplicated region for block: B:43:0x00fb A[SYNTHETIC, Splitter:B:43:0x00fb] */
        /* JADX WARNING: Removed duplicated region for block: B:51:0x010a A[SYNTHETIC, Splitter:B:51:0x010a] */
        /* JADX WARNING: Unknown top exception splitter block from list: {B:23:0x0090=Splitter:B:23:0x0090, B:31:0x00b6=Splitter:B:31:0x00b6, B:39:0x00dc=Splitter:B:39:0x00dc} */
        /* Code decompiled incorrectly, please refer to instructions dump. */
        public java.lang.Void doInBackground(java.lang.Object... r18) {
            /*
                r17 = this;
                r1 = r17
                java.lang.String r0 = "historical-record"
                java.lang.String r2 = "historical-records"
                java.lang.String r3 = "Error writing historical record file: "
                r4 = 0
                r5 = r18[r4]
                java.util.List r5 = (java.util.List) r5
                r6 = 1
                r7 = r18[r6]
                java.lang.String r7 = (java.lang.String) r7
                r8 = 0
                r9 = 0
                androidx.appcompat.widget.ActivityChooserModel r10 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch:{ FileNotFoundException -> 0x0110 }
                android.content.Context r10 = r10.mContext     // Catch:{ FileNotFoundException -> 0x0110 }
                java.io.FileOutputStream r10 = r10.openFileOutput(r7, r4)     // Catch:{ FileNotFoundException -> 0x0110 }
                r8 = r10
                org.xmlpull.v1.XmlSerializer r10 = android.util.Xml.newSerializer()
                r10.setOutput(r8, r9)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                java.lang.String r11 = "UTF-8"
                java.lang.Boolean r12 = java.lang.Boolean.valueOf(r6)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                r10.startDocument(r11, r12)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                r10.startTag(r9, r2)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                int r11 = r5.size()     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                r12 = 0
            L_0x0036:
                if (r12 >= r11) goto L_0x006e
                java.lang.Object r13 = r5.remove(r4)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                androidx.appcompat.widget.ActivityChooserModel$HistoricalRecord r13 = (androidx.appcompat.widget.ActivityChooserModel.HistoricalRecord) r13     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                r10.startTag(r9, r0)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                java.lang.String r14 = "activity"
                android.content.ComponentName r15 = r13.activity     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                java.lang.String r15 = r15.flattenToString()     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                r10.attribute(r9, r14, r15)     // Catch:{ IllegalArgumentException -> 0x00d9, IllegalStateException -> 0x00b3, IOException -> 0x008d, all -> 0x0087 }
                java.lang.String r14 = "time"
                r16 = r5
                long r4 = r13.time     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                java.lang.String r4 = java.lang.String.valueOf(r4)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                r10.attribute(r9, r14, r4)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                java.lang.String r4 = "weight"
                float r5 = r13.weight     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                java.lang.String r5 = java.lang.String.valueOf(r5)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                r10.attribute(r9, r4, r5)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                r10.endTag(r9, r0)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                int r12 = r12 + 1
                r5 = r16
                r4 = 0
                goto L_0x0036
            L_0x006e:
                r16 = r5
                r10.endTag(r9, r2)     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                r10.endDocument()     // Catch:{ IllegalArgumentException -> 0x0085, IllegalStateException -> 0x0083, IOException -> 0x0081 }
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r6
                if (r8 == 0) goto L_0x0101
                r8.close()     // Catch:{ IOException -> 0x00ff }
                goto L_0x00fe
            L_0x0081:
                r0 = move-exception
                goto L_0x0090
            L_0x0083:
                r0 = move-exception
                goto L_0x00b6
            L_0x0085:
                r0 = move-exception
                goto L_0x00dc
            L_0x0087:
                r0 = move-exception
                r16 = r5
                r2 = r0
                goto L_0x0104
            L_0x008d:
                r0 = move-exception
                r16 = r5
            L_0x0090:
                java.lang.String r2 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch:{ all -> 0x0102 }
                java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch:{ all -> 0x0102 }
                r4.<init>()     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r3 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r3.mHistoryFileName     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r4.toString()     // Catch:{ all -> 0x0102 }
                android.util.Log.e(r2, r3, r0)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r6
                if (r8 == 0) goto L_0x0101
                r8.close()     // Catch:{ IOException -> 0x00ff }
                goto L_0x00fe
            L_0x00b3:
                r0 = move-exception
                r16 = r5
            L_0x00b6:
                java.lang.String r2 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch:{ all -> 0x0102 }
                java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch:{ all -> 0x0102 }
                r4.<init>()     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r3 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r3.mHistoryFileName     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r4.toString()     // Catch:{ all -> 0x0102 }
                android.util.Log.e(r2, r3, r0)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r6
                if (r8 == 0) goto L_0x0101
                r8.close()     // Catch:{ IOException -> 0x00ff }
                goto L_0x00fe
            L_0x00d9:
                r0 = move-exception
                r16 = r5
            L_0x00dc:
                java.lang.String r2 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG     // Catch:{ all -> 0x0102 }
                java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch:{ all -> 0x0102 }
                r4.<init>()     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r3 = androidx.appcompat.widget.ActivityChooserModel.this     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r3.mHistoryFileName     // Catch:{ all -> 0x0102 }
                r4.append(r3)     // Catch:{ all -> 0x0102 }
                java.lang.String r3 = r4.toString()     // Catch:{ all -> 0x0102 }
                android.util.Log.e(r2, r3, r0)     // Catch:{ all -> 0x0102 }
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r6
                if (r8 == 0) goto L_0x0101
                r8.close()     // Catch:{ IOException -> 0x00ff }
            L_0x00fe:
                goto L_0x0101
            L_0x00ff:
                r0 = move-exception
                goto L_0x00fe
            L_0x0101:
                return r9
            L_0x0102:
                r0 = move-exception
                r2 = r0
            L_0x0104:
                androidx.appcompat.widget.ActivityChooserModel r0 = androidx.appcompat.widget.ActivityChooserModel.this
                r0.mCanReadHistoricalData = r6
                if (r8 == 0) goto L_0x010f
                r8.close()     // Catch:{ IOException -> 0x010e }
                goto L_0x010f
            L_0x010e:
                r0 = move-exception
            L_0x010f:
                throw r2
            L_0x0110:
                r0 = move-exception
                r16 = r5
                java.lang.String r2 = androidx.appcompat.widget.ActivityChooserModel.LOG_TAG
                java.lang.StringBuilder r4 = new java.lang.StringBuilder
                r4.<init>()
                r4.append(r3)
                r4.append(r7)
                java.lang.String r3 = r4.toString()
                android.util.Log.e(r2, r3, r0)
                return r9
            */
            throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActivityChooserModel.PersistHistoryAsyncTask.doInBackground(java.lang.Object[]):java.lang.Void");
        }
    }

    public static ActivityChooserModel get(Context context, String historyFileName) {
        ActivityChooserModel dataModel;
        synchronized (sRegistryLock) {
            dataModel = (ActivityChooserModel) sDataModelRegistry.get(historyFileName);
            if (dataModel == null) {
                dataModel = new ActivityChooserModel(context, historyFileName);
                sDataModelRegistry.put(historyFileName, dataModel);
            }
        }
        return dataModel;
    }

    private ActivityChooserModel(Context context, String historyFileName) {
        this.mContext = context.getApplicationContext();
        if (!TextUtils.isEmpty(historyFileName)) {
            String str = HISTORY_FILE_EXTENSION;
            if (!historyFileName.endsWith(str)) {
                StringBuilder sb = new StringBuilder();
                sb.append(historyFileName);
                sb.append(str);
                this.mHistoryFileName = sb.toString();
                return;
            }
        }
        this.mHistoryFileName = historyFileName;
    }

    public void setIntent(Intent intent) {
        synchronized (this.mInstanceLock) {
            if (this.mIntent != intent) {
                this.mIntent = intent;
                this.mReloadActivities = true;
                ensureConsistentState();
            }
        }
    }

    public Intent getIntent() {
        Intent intent;
        synchronized (this.mInstanceLock) {
            intent = this.mIntent;
        }
        return intent;
    }

    public int getActivityCount() {
        int size;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            size = this.mActivities.size();
        }
        return size;
    }

    public ResolveInfo getActivity(int index) {
        ResolveInfo resolveInfo;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            resolveInfo = ((ActivityResolveInfo) this.mActivities.get(index)).resolveInfo;
        }
        return resolveInfo;
    }

    public int getActivityIndex(ResolveInfo activity) {
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            List<ActivityResolveInfo> activities = this.mActivities;
            int activityCount = activities.size();
            for (int i = 0; i < activityCount; i++) {
                if (((ActivityResolveInfo) activities.get(i)).resolveInfo == activity) {
                    return i;
                }
            }
            return -1;
        }
    }

    public Intent chooseActivity(int index) {
        synchronized (this.mInstanceLock) {
            if (this.mIntent == null) {
                return null;
            }
            ensureConsistentState();
            ActivityResolveInfo chosenActivity = (ActivityResolveInfo) this.mActivities.get(index);
            ComponentName chosenName = new ComponentName(chosenActivity.resolveInfo.activityInfo.packageName, chosenActivity.resolveInfo.activityInfo.name);
            Intent choiceIntent = new Intent(this.mIntent);
            choiceIntent.setComponent(chosenName);
            if (this.mActivityChoserModelPolicy != null) {
                if (this.mActivityChoserModelPolicy.onChooseActivity(this, new Intent(choiceIntent))) {
                    return null;
                }
            }
            addHistoricalRecord(new HistoricalRecord(chosenName, System.currentTimeMillis(), (float) DEFAULT_HISTORICAL_RECORD_WEIGHT));
            return choiceIntent;
        }
    }

    public void setOnChooseActivityListener(OnChooseActivityListener listener) {
        synchronized (this.mInstanceLock) {
            this.mActivityChoserModelPolicy = listener;
        }
    }

    public ResolveInfo getDefaultActivity() {
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            if (this.mActivities.isEmpty()) {
                return null;
            }
            ResolveInfo resolveInfo = ((ActivityResolveInfo) this.mActivities.get(0)).resolveInfo;
            return resolveInfo;
        }
    }

    public void setDefaultActivity(int index) {
        float weight;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            ActivityResolveInfo newDefaultActivity = (ActivityResolveInfo) this.mActivities.get(index);
            ActivityResolveInfo oldDefaultActivity = (ActivityResolveInfo) this.mActivities.get(0);
            if (oldDefaultActivity != null) {
                weight = (oldDefaultActivity.weight - newDefaultActivity.weight) + 5.0f;
            } else {
                weight = DEFAULT_HISTORICAL_RECORD_WEIGHT;
            }
            addHistoricalRecord(new HistoricalRecord(new ComponentName(newDefaultActivity.resolveInfo.activityInfo.packageName, newDefaultActivity.resolveInfo.activityInfo.name), System.currentTimeMillis(), weight));
        }
    }

    private void persistHistoricalDataIfNeeded() {
        if (!this.mReadShareHistoryCalled) {
            throw new IllegalStateException("No preceding call to #readHistoricalData");
        } else if (this.mHistoricalRecordsChanged) {
            this.mHistoricalRecordsChanged = false;
            if (!TextUtils.isEmpty(this.mHistoryFileName)) {
                new PersistHistoryAsyncTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Object[]{new ArrayList(this.mHistoricalRecords), this.mHistoryFileName});
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0015, code lost:
        return;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void setActivitySorter(androidx.appcompat.widget.ActivityChooserModel.ActivitySorter r3) {
        /*
            r2 = this;
            java.lang.Object r0 = r2.mInstanceLock
            monitor-enter(r0)
            androidx.appcompat.widget.ActivityChooserModel$ActivitySorter r1 = r2.mActivitySorter     // Catch:{ all -> 0x0016 }
            if (r1 != r3) goto L_0x0009
            monitor-exit(r0)     // Catch:{ all -> 0x0016 }
            return
        L_0x0009:
            r2.mActivitySorter = r3     // Catch:{ all -> 0x0016 }
            boolean r1 = r2.sortActivitiesIfNeeded()     // Catch:{ all -> 0x0016 }
            if (r1 == 0) goto L_0x0014
            r2.notifyChanged()     // Catch:{ all -> 0x0016 }
        L_0x0014:
            monitor-exit(r0)     // Catch:{ all -> 0x0016 }
            return
        L_0x0016:
            r1 = move-exception
            monitor-exit(r0)     // Catch:{ all -> 0x0016 }
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActivityChooserModel.setActivitySorter(androidx.appcompat.widget.ActivityChooserModel$ActivitySorter):void");
    }

    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0018, code lost:
        return;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void setHistoryMaxSize(int r3) {
        /*
            r2 = this;
            java.lang.Object r0 = r2.mInstanceLock
            monitor-enter(r0)
            int r1 = r2.mHistoryMaxSize     // Catch:{ all -> 0x0019 }
            if (r1 != r3) goto L_0x0009
            monitor-exit(r0)     // Catch:{ all -> 0x0019 }
            return
        L_0x0009:
            r2.mHistoryMaxSize = r3     // Catch:{ all -> 0x0019 }
            r2.pruneExcessiveHistoricalRecordsIfNeeded()     // Catch:{ all -> 0x0019 }
            boolean r1 = r2.sortActivitiesIfNeeded()     // Catch:{ all -> 0x0019 }
            if (r1 == 0) goto L_0x0017
            r2.notifyChanged()     // Catch:{ all -> 0x0019 }
        L_0x0017:
            monitor-exit(r0)     // Catch:{ all -> 0x0019 }
            return
        L_0x0019:
            r1 = move-exception
            monitor-exit(r0)     // Catch:{ all -> 0x0019 }
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActivityChooserModel.setHistoryMaxSize(int):void");
    }

    public int getHistoryMaxSize() {
        int i;
        synchronized (this.mInstanceLock) {
            i = this.mHistoryMaxSize;
        }
        return i;
    }

    public int getHistorySize() {
        int size;
        synchronized (this.mInstanceLock) {
            ensureConsistentState();
            size = this.mHistoricalRecords.size();
        }
        return size;
    }

    private void ensureConsistentState() {
        boolean stateChanged = loadActivitiesIfNeeded() | readHistoricalDataIfNeeded();
        pruneExcessiveHistoricalRecordsIfNeeded();
        if (stateChanged) {
            sortActivitiesIfNeeded();
            notifyChanged();
        }
    }

    private boolean sortActivitiesIfNeeded() {
        if (this.mActivitySorter == null || this.mIntent == null || this.mActivities.isEmpty() || this.mHistoricalRecords.isEmpty()) {
            return false;
        }
        this.mActivitySorter.sort(this.mIntent, this.mActivities, Collections.unmodifiableList(this.mHistoricalRecords));
        return true;
    }

    private boolean loadActivitiesIfNeeded() {
        if (!this.mReloadActivities || this.mIntent == null) {
            return false;
        }
        this.mReloadActivities = false;
        this.mActivities.clear();
        List<ResolveInfo> resolveInfos = this.mContext.getPackageManager().queryIntentActivities(this.mIntent, 0);
        int resolveInfoCount = resolveInfos.size();
        for (int i = 0; i < resolveInfoCount; i++) {
            this.mActivities.add(new ActivityResolveInfo((ResolveInfo) resolveInfos.get(i)));
        }
        return true;
    }

    private boolean readHistoricalDataIfNeeded() {
        if (!this.mCanReadHistoricalData || !this.mHistoricalRecordsChanged || TextUtils.isEmpty(this.mHistoryFileName)) {
            return false;
        }
        this.mCanReadHistoricalData = false;
        this.mReadShareHistoryCalled = true;
        readHistoricalDataImpl();
        return true;
    }

    private boolean addHistoricalRecord(HistoricalRecord historicalRecord) {
        boolean added = this.mHistoricalRecords.add(historicalRecord);
        if (added) {
            this.mHistoricalRecordsChanged = true;
            pruneExcessiveHistoricalRecordsIfNeeded();
            persistHistoricalDataIfNeeded();
            sortActivitiesIfNeeded();
            notifyChanged();
        }
        return added;
    }

    private void pruneExcessiveHistoricalRecordsIfNeeded() {
        int pruneCount = this.mHistoricalRecords.size() - this.mHistoryMaxSize;
        if (pruneCount > 0) {
            this.mHistoricalRecordsChanged = true;
            for (int i = 0; i < pruneCount; i++) {
                HistoricalRecord historicalRecord = (HistoricalRecord) this.mHistoricalRecords.remove(0);
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:17:0x003c, code lost:
        if (r1 == null) goto L_0x00cb;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:?, code lost:
        r1.close();
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void readHistoricalDataImpl() {
        /*
            r12 = this;
            java.lang.String r0 = "Error reading historical recrod file: "
            r1 = 0
            android.content.Context r2 = r12.mContext     // Catch:{ FileNotFoundException -> 0x00d4 }
            java.lang.String r3 = r12.mHistoryFileName     // Catch:{ FileNotFoundException -> 0x00d4 }
            java.io.FileInputStream r2 = r2.openFileInput(r3)     // Catch:{ FileNotFoundException -> 0x00d4 }
            r1 = r2
            org.xmlpull.v1.XmlPullParser r2 = android.util.Xml.newPullParser()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r3 = "UTF-8"
            r2.setInput(r1, r3)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r3 = 0
        L_0x0017:
            r4 = 1
            if (r3 == r4) goto L_0x0023
            r5 = 2
            if (r3 == r5) goto L_0x0023
            int r4 = r2.next()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r3 = r4
            goto L_0x0017
        L_0x0023:
            java.lang.String r5 = "historical-records"
            java.lang.String r6 = r2.getName()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            boolean r5 = r5.equals(r6)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            if (r5 == 0) goto L_0x0083
            java.util.List<androidx.appcompat.widget.ActivityChooserModel$HistoricalRecord> r5 = r12.mHistoricalRecords     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r5.clear()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
        L_0x0034:
            int r6 = r2.next()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r3 = r6
            if (r3 != r4) goto L_0x0043
            if (r1 == 0) goto L_0x00cb
            r1.close()     // Catch:{ IOException -> 0x00c9 }
            goto L_0x00c8
        L_0x0043:
            r6 = 3
            if (r3 == r6) goto L_0x0034
            r6 = 4
            if (r3 != r6) goto L_0x004a
            goto L_0x0034
        L_0x004a:
            java.lang.String r6 = r2.getName()     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r7 = "historical-record"
            boolean r7 = r7.equals(r6)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            if (r7 == 0) goto L_0x007b
            java.lang.String r7 = "activity"
            r8 = 0
            java.lang.String r7 = r2.getAttributeValue(r8, r7)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r9 = "time"
            java.lang.String r9 = r2.getAttributeValue(r8, r9)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            long r9 = java.lang.Long.parseLong(r9)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r11 = "weight"
            java.lang.String r8 = r2.getAttributeValue(r8, r11)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            float r8 = java.lang.Float.parseFloat(r8)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            androidx.appcompat.widget.ActivityChooserModel$HistoricalRecord r11 = new androidx.appcompat.widget.ActivityChooserModel$HistoricalRecord     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r11.<init>(r7, r9, r8)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            r5.add(r11)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            goto L_0x0034
        L_0x007b:
            org.xmlpull.v1.XmlPullParserException r4 = new org.xmlpull.v1.XmlPullParserException     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r7 = "Share records file not well-formed."
            r4.<init>(r7)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            throw r4     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
        L_0x0083:
            org.xmlpull.v1.XmlPullParserException r4 = new org.xmlpull.v1.XmlPullParserException     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            java.lang.String r5 = "Share records file does not start with historical-records tag."
            r4.<init>(r5)     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
            throw r4     // Catch:{ XmlPullParserException -> 0x00ab, IOException -> 0x008d }
        L_0x008b:
            r0 = move-exception
            goto L_0x00cc
        L_0x008d:
            r2 = move-exception
            java.lang.String r3 = LOG_TAG     // Catch:{ all -> 0x008b }
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch:{ all -> 0x008b }
            r4.<init>()     // Catch:{ all -> 0x008b }
            r4.append(r0)     // Catch:{ all -> 0x008b }
            java.lang.String r0 = r12.mHistoryFileName     // Catch:{ all -> 0x008b }
            r4.append(r0)     // Catch:{ all -> 0x008b }
            java.lang.String r0 = r4.toString()     // Catch:{ all -> 0x008b }
            android.util.Log.e(r3, r0, r2)     // Catch:{ all -> 0x008b }
            if (r1 == 0) goto L_0x00cb
            r1.close()     // Catch:{ IOException -> 0x00c9 }
            goto L_0x00c8
        L_0x00ab:
            r2 = move-exception
            java.lang.String r3 = LOG_TAG     // Catch:{ all -> 0x008b }
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch:{ all -> 0x008b }
            r4.<init>()     // Catch:{ all -> 0x008b }
            r4.append(r0)     // Catch:{ all -> 0x008b }
            java.lang.String r0 = r12.mHistoryFileName     // Catch:{ all -> 0x008b }
            r4.append(r0)     // Catch:{ all -> 0x008b }
            java.lang.String r0 = r4.toString()     // Catch:{ all -> 0x008b }
            android.util.Log.e(r3, r0, r2)     // Catch:{ all -> 0x008b }
            if (r1 == 0) goto L_0x00cb
            r1.close()     // Catch:{ IOException -> 0x00c9 }
        L_0x00c8:
            goto L_0x00cb
        L_0x00c9:
            r0 = move-exception
            goto L_0x00c8
        L_0x00cb:
            return
        L_0x00cc:
            if (r1 == 0) goto L_0x00d3
            r1.close()     // Catch:{ IOException -> 0x00d2 }
            goto L_0x00d3
        L_0x00d2:
            r2 = move-exception
        L_0x00d3:
            throw r0
        L_0x00d4:
            r0 = move-exception
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActivityChooserModel.readHistoricalDataImpl():void");
    }
}
