package androidx.fragment.app;

import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.IntentSender.SendIntentException;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import androidx.activity.ComponentActivity;
import androidx.activity.OnBackPressedDispatcher;
import androidx.activity.OnBackPressedDispatcherOwner;
import androidx.collection.SparseArrayCompat;
import androidx.core.app.ActivityCompat;
import androidx.core.app.ActivityCompat.OnRequestPermissionsResultCallback;
import androidx.core.app.ActivityCompat.PermissionCompatDelegate;
import androidx.core.app.ActivityCompat.RequestPermissionsRequestCodeValidator;
import androidx.core.app.SharedElementCallback;
import androidx.core.internal.view.SupportMenu;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.Lifecycle.State;
import androidx.lifecycle.LifecycleRegistry;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.loader.app.LoaderManager;
import java.io.FileDescriptor;
import java.io.PrintWriter;

public class FragmentActivity extends ComponentActivity implements OnRequestPermissionsResultCallback, RequestPermissionsRequestCodeValidator {
    static final String ALLOCATED_REQUEST_INDICIES_TAG = "android:support:request_indicies";
    static final String FRAGMENTS_TAG = "android:support:fragments";
    static final int MAX_NUM_PENDING_FRAGMENT_ACTIVITY_RESULTS = 65534;
    static final String NEXT_CANDIDATE_REQUEST_INDEX_TAG = "android:support:next_request_index";
    static final String REQUEST_FRAGMENT_WHO_TAG = "android:support:request_fragment_who";
    private static final String TAG = "FragmentActivity";
    boolean mCreated;
    final LifecycleRegistry mFragmentLifecycleRegistry = new LifecycleRegistry(this);
    final FragmentController mFragments = FragmentController.createController(new HostCallbacks());
    int mNextCandidateRequestIndex;
    SparseArrayCompat<String> mPendingFragmentActivityResults;
    boolean mRequestedPermissionsFromFragment;
    boolean mResumed;
    boolean mStartedActivityFromFragment;
    boolean mStartedIntentSenderFromFragment;
    boolean mStopped = true;

    class HostCallbacks extends FragmentHostCallback<FragmentActivity> implements ViewModelStoreOwner, OnBackPressedDispatcherOwner {
        public HostCallbacks() {
            super(FragmentActivity.this);
        }

        public Lifecycle getLifecycle() {
            return FragmentActivity.this.mFragmentLifecycleRegistry;
        }

        public ViewModelStore getViewModelStore() {
            return FragmentActivity.this.getViewModelStore();
        }

        public OnBackPressedDispatcher getOnBackPressedDispatcher() {
            return FragmentActivity.this.getOnBackPressedDispatcher();
        }

        public void onDump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
            FragmentActivity.this.dump(prefix, fd, writer, args);
        }

        public boolean onShouldSaveFragmentState(Fragment fragment) {
            return !FragmentActivity.this.isFinishing();
        }

        public LayoutInflater onGetLayoutInflater() {
            return FragmentActivity.this.getLayoutInflater().cloneInContext(FragmentActivity.this);
        }

        public FragmentActivity onGetHost() {
            return FragmentActivity.this;
        }

        public void onSupportInvalidateOptionsMenu() {
            FragmentActivity.this.supportInvalidateOptionsMenu();
        }

        public void onStartActivityFromFragment(Fragment fragment, Intent intent, int requestCode) {
            FragmentActivity.this.startActivityFromFragment(fragment, intent, requestCode);
        }

        public void onStartActivityFromFragment(Fragment fragment, Intent intent, int requestCode, Bundle options) {
            FragmentActivity.this.startActivityFromFragment(fragment, intent, requestCode, options);
        }

        public void onStartIntentSenderFromFragment(Fragment fragment, IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags, Bundle options) throws SendIntentException {
            FragmentActivity.this.startIntentSenderFromFragment(fragment, intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags, options);
        }

        public void onRequestPermissionsFromFragment(Fragment fragment, String[] permissions, int requestCode) {
            FragmentActivity.this.requestPermissionsFromFragment(fragment, permissions, requestCode);
        }

        public boolean onShouldShowRequestPermissionRationale(String permission) {
            return ActivityCompat.shouldShowRequestPermissionRationale(FragmentActivity.this, permission);
        }

        public boolean onHasWindowAnimations() {
            return FragmentActivity.this.getWindow() != null;
        }

        public int onGetWindowAnimations() {
            Window w = FragmentActivity.this.getWindow();
            if (w == null) {
                return 0;
            }
            return w.getAttributes().windowAnimations;
        }

        public void onAttachFragment(Fragment fragment) {
            FragmentActivity.this.onAttachFragment(fragment);
        }

        public View onFindViewById(int id) {
            return FragmentActivity.this.findViewById(id);
        }

        public boolean onHasView() {
            Window w = FragmentActivity.this.getWindow();
            return (w == null || w.peekDecorView() == null) ? false : true;
        }
    }

    public FragmentActivity() {
    }

    public FragmentActivity(int contentLayoutId) {
        super(contentLayoutId);
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        this.mFragments.noteStateNotSaved();
        int requestIndex = requestCode >> 16;
        if (requestIndex != 0) {
            int requestIndex2 = requestIndex - 1;
            String who = (String) this.mPendingFragmentActivityResults.get(requestIndex2);
            this.mPendingFragmentActivityResults.remove(requestIndex2);
            String str = TAG;
            if (who == null) {
                Log.w(str, "Activity result delivered for unknown Fragment.");
                return;
            }
            Fragment targetFragment = this.mFragments.findFragmentByWho(who);
            if (targetFragment == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("Activity result no fragment exists for who: ");
                sb.append(who);
                Log.w(str, sb.toString());
            } else {
                targetFragment.onActivityResult(65535 & requestCode, resultCode, data);
            }
            return;
        }
        PermissionCompatDelegate delegate = ActivityCompat.getPermissionCompatDelegate();
        if (delegate == null || !delegate.onActivityResult(this, requestCode, resultCode, data)) {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    public void supportFinishAfterTransition() {
        ActivityCompat.finishAfterTransition(this);
    }

    public void setEnterSharedElementCallback(SharedElementCallback callback) {
        ActivityCompat.setEnterSharedElementCallback(this, callback);
    }

    public void setExitSharedElementCallback(SharedElementCallback listener) {
        ActivityCompat.setExitSharedElementCallback(this, listener);
    }

    public void supportPostponeEnterTransition() {
        ActivityCompat.postponeEnterTransition(this);
    }

    public void supportStartPostponedEnterTransition() {
        ActivityCompat.startPostponedEnterTransition(this);
    }

    public void onMultiWindowModeChanged(boolean isInMultiWindowMode) {
        this.mFragments.dispatchMultiWindowModeChanged(isInMultiWindowMode);
    }

    public void onPictureInPictureModeChanged(boolean isInPictureInPictureMode) {
        this.mFragments.dispatchPictureInPictureModeChanged(isInPictureInPictureMode);
    }

    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        this.mFragments.noteStateNotSaved();
        this.mFragments.dispatchConfigurationChanged(newConfig);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        this.mFragments.attachHost(null);
        if (savedInstanceState != null) {
            this.mFragments.restoreSaveState(savedInstanceState.getParcelable(FRAGMENTS_TAG));
            String str = NEXT_CANDIDATE_REQUEST_INDEX_TAG;
            if (savedInstanceState.containsKey(str)) {
                this.mNextCandidateRequestIndex = savedInstanceState.getInt(str);
                int[] requestCodes = savedInstanceState.getIntArray(ALLOCATED_REQUEST_INDICIES_TAG);
                String[] fragmentWhos = savedInstanceState.getStringArray(REQUEST_FRAGMENT_WHO_TAG);
                if (requestCodes == null || fragmentWhos == null || requestCodes.length != fragmentWhos.length) {
                    Log.w(TAG, "Invalid requestCode mapping in savedInstanceState.");
                } else {
                    this.mPendingFragmentActivityResults = new SparseArrayCompat<>(requestCodes.length);
                    for (int i = 0; i < requestCodes.length; i++) {
                        this.mPendingFragmentActivityResults.put(requestCodes[i], fragmentWhos[i]);
                    }
                }
            }
        }
        if (this.mPendingFragmentActivityResults == null) {
            this.mPendingFragmentActivityResults = new SparseArrayCompat<>();
            this.mNextCandidateRequestIndex = 0;
        }
        super.onCreate(savedInstanceState);
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_CREATE);
        this.mFragments.dispatchCreate();
    }

    public boolean onCreatePanelMenu(int featureId, Menu menu) {
        if (featureId == 0) {
            return super.onCreatePanelMenu(featureId, menu) | this.mFragments.dispatchCreateOptionsMenu(menu, getMenuInflater());
        }
        return super.onCreatePanelMenu(featureId, menu);
    }

    public View onCreateView(View parent, String name, Context context, AttributeSet attrs) {
        View v = dispatchFragmentsOnCreateView(parent, name, context, attrs);
        if (v == null) {
            return super.onCreateView(parent, name, context, attrs);
        }
        return v;
    }

    public View onCreateView(String name, Context context, AttributeSet attrs) {
        View v = dispatchFragmentsOnCreateView(null, name, context, attrs);
        if (v == null) {
            return super.onCreateView(name, context, attrs);
        }
        return v;
    }

    /* access modifiers changed from: 0000 */
    public final View dispatchFragmentsOnCreateView(View parent, String name, Context context, AttributeSet attrs) {
        return this.mFragments.onCreateView(parent, name, context, attrs);
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        this.mFragments.dispatchDestroy();
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_DESTROY);
    }

    public void onLowMemory() {
        super.onLowMemory();
        this.mFragments.dispatchLowMemory();
    }

    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        if (super.onMenuItemSelected(featureId, item)) {
            return true;
        }
        if (featureId == 0) {
            return this.mFragments.dispatchOptionsItemSelected(item);
        }
        if (featureId != 6) {
            return false;
        }
        return this.mFragments.dispatchContextItemSelected(item);
    }

    public void onPanelClosed(int featureId, Menu menu) {
        if (featureId == 0) {
            this.mFragments.dispatchOptionsMenuClosed(menu);
        }
        super.onPanelClosed(featureId, menu);
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
        this.mResumed = false;
        this.mFragments.dispatchPause();
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_PAUSE);
    }

    /* access modifiers changed from: protected */
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        this.mFragments.noteStateNotSaved();
    }

    public void onStateNotSaved() {
        this.mFragments.noteStateNotSaved();
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
        this.mResumed = true;
        this.mFragments.noteStateNotSaved();
        this.mFragments.execPendingActions();
    }

    /* access modifiers changed from: protected */
    public void onPostResume() {
        super.onPostResume();
        onResumeFragments();
    }

    /* access modifiers changed from: protected */
    public void onResumeFragments() {
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_RESUME);
        this.mFragments.dispatchResume();
    }

    public boolean onPreparePanel(int featureId, View view, Menu menu) {
        if (featureId == 0) {
            return onPrepareOptionsPanel(view, menu) | this.mFragments.dispatchPrepareOptionsMenu(menu);
        }
        return super.onPreparePanel(featureId, view, menu);
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public boolean onPrepareOptionsPanel(View view, Menu menu) {
        return super.onPreparePanel(0, view, menu);
    }

    /* access modifiers changed from: protected */
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        markFragmentsCreated();
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_STOP);
        Parcelable p = this.mFragments.saveAllState();
        if (p != null) {
            outState.putParcelable(FRAGMENTS_TAG, p);
        }
        if (this.mPendingFragmentActivityResults.size() > 0) {
            outState.putInt(NEXT_CANDIDATE_REQUEST_INDEX_TAG, this.mNextCandidateRequestIndex);
            int[] requestCodes = new int[this.mPendingFragmentActivityResults.size()];
            String[] fragmentWhos = new String[this.mPendingFragmentActivityResults.size()];
            for (int i = 0; i < this.mPendingFragmentActivityResults.size(); i++) {
                requestCodes[i] = this.mPendingFragmentActivityResults.keyAt(i);
                fragmentWhos[i] = (String) this.mPendingFragmentActivityResults.valueAt(i);
            }
            outState.putIntArray(ALLOCATED_REQUEST_INDICIES_TAG, requestCodes);
            outState.putStringArray(REQUEST_FRAGMENT_WHO_TAG, fragmentWhos);
        }
    }

    /* access modifiers changed from: protected */
    public void onStart() {
        super.onStart();
        this.mStopped = false;
        if (!this.mCreated) {
            this.mCreated = true;
            this.mFragments.dispatchActivityCreated();
        }
        this.mFragments.noteStateNotSaved();
        this.mFragments.execPendingActions();
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_START);
        this.mFragments.dispatchStart();
    }

    /* access modifiers changed from: protected */
    public void onStop() {
        super.onStop();
        this.mStopped = true;
        markFragmentsCreated();
        this.mFragments.dispatchStop();
        this.mFragmentLifecycleRegistry.handleLifecycleEvent(Event.ON_STOP);
    }

    @Deprecated
    public void supportInvalidateOptionsMenu() {
        invalidateOptionsMenu();
    }

    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        super.dump(prefix, fd, writer, args);
        writer.print(prefix);
        writer.print("Local FragmentActivity ");
        writer.print(Integer.toHexString(System.identityHashCode(this)));
        writer.println(" State:");
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);
        sb.append("  ");
        String innerPrefix = sb.toString();
        writer.print(innerPrefix);
        writer.print("mCreated=");
        writer.print(this.mCreated);
        writer.print(" mResumed=");
        writer.print(this.mResumed);
        writer.print(" mStopped=");
        writer.print(this.mStopped);
        if (getApplication() != null) {
            LoaderManager.getInstance(this).dump(innerPrefix, fd, writer, args);
        }
        this.mFragments.getSupportFragmentManager().dump(prefix, fd, writer, args);
    }

    public void onAttachFragment(Fragment fragment) {
    }

    public FragmentManager getSupportFragmentManager() {
        return this.mFragments.getSupportFragmentManager();
    }

    @Deprecated
    public LoaderManager getSupportLoaderManager() {
        return LoaderManager.getInstance(this);
    }

    public void startActivityForResult(Intent intent, int requestCode) {
        if (!this.mStartedActivityFromFragment && requestCode != -1) {
            checkForValidRequestCode(requestCode);
        }
        super.startActivityForResult(intent, requestCode);
    }

    public void startActivityForResult(Intent intent, int requestCode, Bundle options) {
        if (!this.mStartedActivityFromFragment && requestCode != -1) {
            checkForValidRequestCode(requestCode);
        }
        super.startActivityForResult(intent, requestCode, options);
    }

    public void startIntentSenderForResult(IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags) throws SendIntentException {
        if (!this.mStartedIntentSenderFromFragment && requestCode != -1) {
            checkForValidRequestCode(requestCode);
        }
        super.startIntentSenderForResult(intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags);
    }

    public void startIntentSenderForResult(IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags, Bundle options) throws SendIntentException {
        if (!this.mStartedIntentSenderFromFragment && requestCode != -1) {
            checkForValidRequestCode(requestCode);
        }
        super.startIntentSenderForResult(intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags, options);
    }

    static void checkForValidRequestCode(int requestCode) {
        if ((-65536 & requestCode) != 0) {
            throw new IllegalArgumentException("Can only use lower 16 bits for requestCode");
        }
    }

    public final void validateRequestPermissionsRequestCode(int requestCode) {
        if (!this.mRequestedPermissionsFromFragment && requestCode != -1) {
            checkForValidRequestCode(requestCode);
        }
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        this.mFragments.noteStateNotSaved();
        int index = (requestCode >> 16) & SupportMenu.USER_MASK;
        if (index != 0) {
            int index2 = index - 1;
            String who = (String) this.mPendingFragmentActivityResults.get(index2);
            this.mPendingFragmentActivityResults.remove(index2);
            String str = TAG;
            if (who == null) {
                Log.w(str, "Activity result delivered for unknown Fragment.");
                return;
            }
            Fragment frag = this.mFragments.findFragmentByWho(who);
            if (frag == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("Activity result no fragment exists for who: ");
                sb.append(who);
                Log.w(str, sb.toString());
            } else {
                frag.onRequestPermissionsResult(65535 & requestCode, permissions, grantResults);
            }
        }
    }

    public void startActivityFromFragment(Fragment fragment, Intent intent, int requestCode) {
        startActivityFromFragment(fragment, intent, requestCode, null);
    }

    public void startActivityFromFragment(Fragment fragment, Intent intent, int requestCode, Bundle options) {
        this.mStartedActivityFromFragment = true;
        if (requestCode == -1) {
            try {
                ActivityCompat.startActivityForResult(this, intent, -1, options);
            } finally {
                this.mStartedActivityFromFragment = false;
            }
        } else {
            checkForValidRequestCode(requestCode);
            ActivityCompat.startActivityForResult(this, intent, ((allocateRequestIndex(fragment) + 1) << 16) + (65535 & requestCode), options);
            this.mStartedActivityFromFragment = false;
        }
    }

    public void startIntentSenderFromFragment(Fragment fragment, IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags, Bundle options) throws SendIntentException {
        int i = requestCode;
        this.mStartedIntentSenderFromFragment = true;
        if (i == -1) {
            try {
                ActivityCompat.startIntentSenderForResult(this, intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags, options);
            } finally {
                this.mStartedIntentSenderFromFragment = false;
            }
        } else {
            checkForValidRequestCode(requestCode);
            ActivityCompat.startIntentSenderForResult(this, intent, ((allocateRequestIndex(fragment) + 1) << 16) + (65535 & i), fillInIntent, flagsMask, flagsValues, extraFlags, options);
            this.mStartedIntentSenderFromFragment = false;
        }
    }

    private int allocateRequestIndex(Fragment fragment) {
        if (this.mPendingFragmentActivityResults.size() < MAX_NUM_PENDING_FRAGMENT_ACTIVITY_RESULTS) {
            while (this.mPendingFragmentActivityResults.indexOfKey(this.mNextCandidateRequestIndex) >= 0) {
                this.mNextCandidateRequestIndex = (this.mNextCandidateRequestIndex + 1) % MAX_NUM_PENDING_FRAGMENT_ACTIVITY_RESULTS;
            }
            int requestIndex = this.mNextCandidateRequestIndex;
            this.mPendingFragmentActivityResults.put(requestIndex, fragment.mWho);
            this.mNextCandidateRequestIndex = (this.mNextCandidateRequestIndex + 1) % MAX_NUM_PENDING_FRAGMENT_ACTIVITY_RESULTS;
            return requestIndex;
        }
        throw new IllegalStateException("Too many pending Fragment activity results.");
    }

    /* access modifiers changed from: 0000 */
    public void requestPermissionsFromFragment(Fragment fragment, String[] permissions, int requestCode) {
        if (requestCode == -1) {
            ActivityCompat.requestPermissions(this, permissions, requestCode);
            return;
        }
        checkForValidRequestCode(requestCode);
        try {
            this.mRequestedPermissionsFromFragment = true;
            ActivityCompat.requestPermissions(this, permissions, ((allocateRequestIndex(fragment) + 1) << 16) + (65535 & requestCode));
        } finally {
            this.mRequestedPermissionsFromFragment = false;
        }
    }

    private void markFragmentsCreated() {
        do {
        } while (markState(getSupportFragmentManager(), State.CREATED));
    }

    private static boolean markState(FragmentManager manager, State state) {
        boolean hadNotMarked = false;
        for (Fragment fragment : manager.getFragments()) {
            if (fragment != null) {
                if (fragment.getLifecycle().getCurrentState().isAtLeast(State.STARTED)) {
                    fragment.mLifecycleRegistry.setCurrentState(state);
                    hadNotMarked = true;
                }
                if (fragment.getHost() != null) {
                    hadNotMarked |= markState(fragment.getChildFragmentManager(), state);
                }
            }
        }
        return hadNotMarked;
    }
}
