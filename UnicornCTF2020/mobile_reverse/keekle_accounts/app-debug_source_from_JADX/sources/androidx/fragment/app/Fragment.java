package androidx.fragment.app;

import android.animation.Animator;
import android.app.Activity;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.IntentSender.SendIntentException;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnCreateContextMenuListener;
import android.view.ViewGroup;
import android.view.animation.Animation;
import androidx.core.app.SharedElementCallback;
import androidx.core.util.DebugUtils;
import androidx.core.view.LayoutInflaterCompat;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.Lifecycle.State;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.LifecycleRegistry;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.loader.app.LoaderManager;
import androidx.savedstate.SavedStateRegistry;
import androidx.savedstate.SavedStateRegistryController;
import androidx.savedstate.SavedStateRegistryOwner;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class Fragment implements ComponentCallbacks, OnCreateContextMenuListener, LifecycleOwner, ViewModelStoreOwner, SavedStateRegistryOwner {
    static final int ACTIVITY_CREATED = 2;
    static final int CREATED = 1;
    static final int INITIALIZING = 0;
    static final int RESUMED = 4;
    static final int STARTED = 3;
    static final Object USE_DEFAULT_TRANSITION = new Object();
    boolean mAdded;
    AnimationInfo mAnimationInfo;
    Bundle mArguments;
    int mBackStackNesting;
    private boolean mCalled;
    FragmentManagerImpl mChildFragmentManager;
    ViewGroup mContainer;
    int mContainerId;
    private int mContentLayoutId;
    boolean mDeferStart;
    boolean mDetached;
    int mFragmentId;
    FragmentManagerImpl mFragmentManager;
    boolean mFromLayout;
    boolean mHasMenu;
    boolean mHidden;
    boolean mHiddenChanged;
    FragmentHostCallback mHost;
    boolean mInLayout;
    View mInnerView;
    boolean mIsCreated;
    boolean mIsNewlyAdded;
    private Boolean mIsPrimaryNavigationFragment;
    LayoutInflater mLayoutInflater;
    LifecycleRegistry mLifecycleRegistry;
    State mMaxState;
    boolean mMenuVisible;
    Fragment mParentFragment;
    boolean mPerformedCreateView;
    float mPostponedAlpha;
    Runnable mPostponedDurationRunnable;
    boolean mRemoving;
    boolean mRestored;
    boolean mRetainInstance;
    boolean mRetainInstanceChangedWhileDetached;
    Bundle mSavedFragmentState;
    SavedStateRegistryController mSavedStateRegistryController;
    Boolean mSavedUserVisibleHint;
    SparseArray<Parcelable> mSavedViewState;
    int mState;
    String mTag;
    Fragment mTarget;
    int mTargetRequestCode;
    String mTargetWho;
    boolean mUserVisibleHint;
    View mView;
    FragmentViewLifecycleOwner mViewLifecycleOwner;
    MutableLiveData<LifecycleOwner> mViewLifecycleOwnerLiveData;
    String mWho;

    static class AnimationInfo {
        Boolean mAllowEnterTransitionOverlap;
        Boolean mAllowReturnTransitionOverlap;
        View mAnimatingAway;
        Animator mAnimator;
        Object mEnterTransition = null;
        SharedElementCallback mEnterTransitionCallback = null;
        boolean mEnterTransitionPostponed;
        Object mExitTransition = null;
        SharedElementCallback mExitTransitionCallback = null;
        boolean mIsHideReplaced;
        int mNextAnim;
        int mNextTransition;
        int mNextTransitionStyle;
        Object mReenterTransition = Fragment.USE_DEFAULT_TRANSITION;
        Object mReturnTransition = Fragment.USE_DEFAULT_TRANSITION;
        Object mSharedElementEnterTransition = null;
        Object mSharedElementReturnTransition = Fragment.USE_DEFAULT_TRANSITION;
        OnStartEnterTransitionListener mStartEnterTransitionListener;
        int mStateAfterAnimating;

        AnimationInfo() {
        }
    }

    public static class InstantiationException extends RuntimeException {
        public InstantiationException(String msg, Exception cause) {
            super(msg, cause);
        }
    }

    interface OnStartEnterTransitionListener {
        void onStartEnterTransition();

        void startListening();
    }

    public static class SavedState implements Parcelable {
        public static final Creator<SavedState> CREATOR = new ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        final Bundle mState;

        SavedState(Bundle state) {
            this.mState = state;
        }

        SavedState(Parcel in, ClassLoader loader) {
            Bundle readBundle = in.readBundle();
            this.mState = readBundle;
            if (loader != null && readBundle != null) {
                readBundle.setClassLoader(loader);
            }
        }

        public int describeContents() {
            return 0;
        }

        public void writeToParcel(Parcel dest, int flags) {
            dest.writeBundle(this.mState);
        }
    }

    public Lifecycle getLifecycle() {
        return this.mLifecycleRegistry;
    }

    public LifecycleOwner getViewLifecycleOwner() {
        FragmentViewLifecycleOwner fragmentViewLifecycleOwner = this.mViewLifecycleOwner;
        if (fragmentViewLifecycleOwner != null) {
            return fragmentViewLifecycleOwner;
        }
        throw new IllegalStateException("Can't access the Fragment View's LifecycleOwner when getView() is null i.e., before onCreateView() or after onDestroyView()");
    }

    public LiveData<LifecycleOwner> getViewLifecycleOwnerLiveData() {
        return this.mViewLifecycleOwnerLiveData;
    }

    public ViewModelStore getViewModelStore() {
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl != null) {
            return fragmentManagerImpl.getViewModelStore(this);
        }
        throw new IllegalStateException("Can't access ViewModels from detached fragment");
    }

    public final SavedStateRegistry getSavedStateRegistry() {
        return this.mSavedStateRegistryController.getSavedStateRegistry();
    }

    public Fragment() {
        this.mState = 0;
        this.mWho = UUID.randomUUID().toString();
        this.mTargetWho = null;
        this.mIsPrimaryNavigationFragment = null;
        this.mChildFragmentManager = new FragmentManagerImpl();
        this.mMenuVisible = true;
        this.mUserVisibleHint = true;
        this.mPostponedDurationRunnable = new Runnable() {
            public void run() {
                Fragment.this.startPostponedEnterTransition();
            }
        };
        this.mMaxState = State.RESUMED;
        this.mViewLifecycleOwnerLiveData = new MutableLiveData<>();
        initLifecycle();
    }

    public Fragment(int contentLayoutId) {
        this();
        this.mContentLayoutId = contentLayoutId;
    }

    private void initLifecycle() {
        this.mLifecycleRegistry = new LifecycleRegistry(this);
        this.mSavedStateRegistryController = SavedStateRegistryController.create(this);
        if (VERSION.SDK_INT >= 19) {
            this.mLifecycleRegistry.addObserver(new LifecycleEventObserver() {
                public void onStateChanged(LifecycleOwner source, Event event) {
                    if (event == Event.ON_STOP && Fragment.this.mView != null) {
                        Fragment.this.mView.cancelPendingInputEvents();
                    }
                }
            });
        }
    }

    @Deprecated
    public static Fragment instantiate(Context context, String fname) {
        return instantiate(context, fname, null);
    }

    @Deprecated
    public static Fragment instantiate(Context context, String fname, Bundle args) {
        String str = ": make sure class name exists, is public, and has an empty constructor that is public";
        String str2 = "Unable to instantiate fragment ";
        try {
            Fragment f = (Fragment) FragmentFactory.loadFragmentClass(context.getClassLoader(), fname).getConstructor(new Class[0]).newInstance(new Object[0]);
            if (args != null) {
                args.setClassLoader(f.getClass().getClassLoader());
                f.setArguments(args);
            }
            return f;
        } catch (InstantiationException e) {
            StringBuilder sb = new StringBuilder();
            sb.append(str2);
            sb.append(fname);
            sb.append(str);
            throw new InstantiationException(sb.toString(), e);
        } catch (IllegalAccessException e2) {
            StringBuilder sb2 = new StringBuilder();
            sb2.append(str2);
            sb2.append(fname);
            sb2.append(str);
            throw new InstantiationException(sb2.toString(), e2);
        } catch (NoSuchMethodException e3) {
            StringBuilder sb3 = new StringBuilder();
            sb3.append(str2);
            sb3.append(fname);
            sb3.append(": could not find Fragment constructor");
            throw new InstantiationException(sb3.toString(), e3);
        } catch (InvocationTargetException e4) {
            StringBuilder sb4 = new StringBuilder();
            sb4.append(str2);
            sb4.append(fname);
            sb4.append(": calling Fragment constructor caused an exception");
            throw new InstantiationException(sb4.toString(), e4);
        }
    }

    /* access modifiers changed from: 0000 */
    public final void restoreViewState(Bundle savedInstanceState) {
        SparseArray<Parcelable> sparseArray = this.mSavedViewState;
        if (sparseArray != null) {
            this.mInnerView.restoreHierarchyState(sparseArray);
            this.mSavedViewState = null;
        }
        this.mCalled = false;
        onViewStateRestored(savedInstanceState);
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onViewStateRestored()");
            throw new SuperNotCalledException(sb.toString());
        } else if (this.mView != null) {
            this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_CREATE);
        }
    }

    /* access modifiers changed from: 0000 */
    public final boolean isInBackStack() {
        return this.mBackStackNesting > 0;
    }

    public final boolean equals(Object o) {
        return super.equals(o);
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        DebugUtils.buildShortClassTag(this, sb);
        sb.append(" (");
        sb.append(this.mWho);
        sb.append(")");
        if (this.mFragmentId != 0) {
            sb.append(" id=0x");
            sb.append(Integer.toHexString(this.mFragmentId));
        }
        if (this.mTag != null) {
            sb.append(" ");
            sb.append(this.mTag);
        }
        sb.append('}');
        return sb.toString();
    }

    public final int getId() {
        return this.mFragmentId;
    }

    public final String getTag() {
        return this.mTag;
    }

    public void setArguments(Bundle args) {
        if (this.mFragmentManager == null || !isStateSaved()) {
            this.mArguments = args;
            return;
        }
        throw new IllegalStateException("Fragment already added and state has been saved");
    }

    public final Bundle getArguments() {
        return this.mArguments;
    }

    public final Bundle requireArguments() {
        Bundle arguments = getArguments();
        if (arguments != null) {
            return arguments;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" does not have any arguments.");
        throw new IllegalStateException(sb.toString());
    }

    public final boolean isStateSaved() {
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl == null) {
            return false;
        }
        return fragmentManagerImpl.isStateSaved();
    }

    public void setInitialSavedState(SavedState state) {
        if (this.mFragmentManager == null) {
            this.mSavedFragmentState = (state == null || state.mState == null) ? null : state.mState;
            return;
        }
        throw new IllegalStateException("Fragment already added");
    }

    public void setTargetFragment(Fragment fragment, int requestCode) {
        FragmentManager mine = getFragmentManager();
        FragmentManager theirs = fragment != null ? fragment.getFragmentManager() : null;
        if (mine == null || theirs == null || mine == theirs) {
            Fragment check = fragment;
            while (check != null) {
                if (check != this) {
                    check = check.getTargetFragment();
                } else {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Setting ");
                    sb.append(fragment);
                    sb.append(" as the target of ");
                    sb.append(this);
                    sb.append(" would create a target cycle");
                    throw new IllegalArgumentException(sb.toString());
                }
            }
            if (fragment == null) {
                this.mTargetWho = null;
                this.mTarget = null;
            } else if (this.mFragmentManager == null || fragment.mFragmentManager == null) {
                this.mTargetWho = null;
                this.mTarget = fragment;
            } else {
                this.mTargetWho = fragment.mWho;
                this.mTarget = null;
            }
            this.mTargetRequestCode = requestCode;
            return;
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append("Fragment ");
        sb2.append(fragment);
        sb2.append(" must share the same FragmentManager to be set as a target fragment");
        throw new IllegalArgumentException(sb2.toString());
    }

    public final Fragment getTargetFragment() {
        Fragment fragment = this.mTarget;
        if (fragment != null) {
            return fragment;
        }
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl == null || this.mTargetWho == null) {
            return null;
        }
        return (Fragment) fragmentManagerImpl.mActive.get(this.mTargetWho);
    }

    public final int getTargetRequestCode() {
        return this.mTargetRequestCode;
    }

    public Context getContext() {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback == null) {
            return null;
        }
        return fragmentHostCallback.getContext();
    }

    public final Context requireContext() {
        Context context = getContext();
        if (context != null) {
            return context;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to a context.");
        throw new IllegalStateException(sb.toString());
    }

    public final FragmentActivity getActivity() {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback == null) {
            return null;
        }
        return (FragmentActivity) fragmentHostCallback.getActivity();
    }

    public final FragmentActivity requireActivity() {
        FragmentActivity activity = getActivity();
        if (activity != null) {
            return activity;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to an activity.");
        throw new IllegalStateException(sb.toString());
    }

    public final Object getHost() {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback == null) {
            return null;
        }
        return fragmentHostCallback.onGetHost();
    }

    public final Object requireHost() {
        Object host = getHost();
        if (host != null) {
            return host;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to a host.");
        throw new IllegalStateException(sb.toString());
    }

    public final Resources getResources() {
        return requireContext().getResources();
    }

    public final CharSequence getText(int resId) {
        return getResources().getText(resId);
    }

    public final String getString(int resId) {
        return getResources().getString(resId);
    }

    public final String getString(int resId, Object... formatArgs) {
        return getResources().getString(resId, formatArgs);
    }

    public final FragmentManager getFragmentManager() {
        return this.mFragmentManager;
    }

    public final FragmentManager requireFragmentManager() {
        FragmentManager fragmentManager = getFragmentManager();
        if (fragmentManager != null) {
            return fragmentManager;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not associated with a fragment manager.");
        throw new IllegalStateException(sb.toString());
    }

    public final FragmentManager getChildFragmentManager() {
        if (this.mHost != null) {
            return this.mChildFragmentManager;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" has not been attached yet.");
        throw new IllegalStateException(sb.toString());
    }

    public final Fragment getParentFragment() {
        return this.mParentFragment;
    }

    public final Fragment requireParentFragment() {
        Fragment parentFragment = getParentFragment();
        if (parentFragment != null) {
            return parentFragment;
        }
        String str = "Fragment ";
        if (getContext() == null) {
            StringBuilder sb = new StringBuilder();
            sb.append(str);
            sb.append(this);
            sb.append(" is not attached to any Fragment or host");
            throw new IllegalStateException(sb.toString());
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(str);
        sb2.append(this);
        sb2.append(" is not a child Fragment, it is directly attached to ");
        sb2.append(getContext());
        throw new IllegalStateException(sb2.toString());
    }

    public final boolean isAdded() {
        return this.mHost != null && this.mAdded;
    }

    public final boolean isDetached() {
        return this.mDetached;
    }

    public final boolean isRemoving() {
        return this.mRemoving;
    }

    public final boolean isInLayout() {
        return this.mInLayout;
    }

    public final boolean isResumed() {
        return this.mState >= 4;
    }

    public final boolean isVisible() {
        if (isAdded() && !isHidden()) {
            View view = this.mView;
            if (!(view == null || view.getWindowToken() == null || this.mView.getVisibility() != 0)) {
                return true;
            }
        }
        return false;
    }

    public final boolean isHidden() {
        return this.mHidden;
    }

    public final boolean hasOptionsMenu() {
        return this.mHasMenu;
    }

    public final boolean isMenuVisible() {
        return this.mMenuVisible;
    }

    public void onHiddenChanged(boolean hidden) {
    }

    public void setRetainInstance(boolean retain) {
        this.mRetainInstance = retain;
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl == null) {
            this.mRetainInstanceChangedWhileDetached = true;
        } else if (retain) {
            fragmentManagerImpl.addRetainedFragment(this);
        } else {
            fragmentManagerImpl.removeRetainedFragment(this);
        }
    }

    public final boolean getRetainInstance() {
        return this.mRetainInstance;
    }

    public void setHasOptionsMenu(boolean hasMenu) {
        if (this.mHasMenu != hasMenu) {
            this.mHasMenu = hasMenu;
            if (isAdded() && !isHidden()) {
                this.mHost.onSupportInvalidateOptionsMenu();
            }
        }
    }

    public void setMenuVisibility(boolean menuVisible) {
        if (this.mMenuVisible != menuVisible) {
            this.mMenuVisible = menuVisible;
            if (this.mHasMenu && isAdded() && !isHidden()) {
                this.mHost.onSupportInvalidateOptionsMenu();
            }
        }
    }

    @Deprecated
    public void setUserVisibleHint(boolean isVisibleToUser) {
        if (!this.mUserVisibleHint && isVisibleToUser && this.mState < 3 && this.mFragmentManager != null && isAdded() && this.mIsCreated) {
            this.mFragmentManager.performPendingDeferredStart(this);
        }
        this.mUserVisibleHint = isVisibleToUser;
        this.mDeferStart = this.mState < 3 && !isVisibleToUser;
        if (this.mSavedFragmentState != null) {
            this.mSavedUserVisibleHint = Boolean.valueOf(isVisibleToUser);
        }
    }

    @Deprecated
    public boolean getUserVisibleHint() {
        return this.mUserVisibleHint;
    }

    @Deprecated
    public LoaderManager getLoaderManager() {
        return LoaderManager.getInstance(this);
    }

    public void startActivity(Intent intent) {
        startActivity(intent, null);
    }

    public void startActivity(Intent intent, Bundle options) {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            fragmentHostCallback.onStartActivityFromFragment(this, intent, -1, options);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to Activity");
        throw new IllegalStateException(sb.toString());
    }

    public void startActivityForResult(Intent intent, int requestCode) {
        startActivityForResult(intent, requestCode, null);
    }

    public void startActivityForResult(Intent intent, int requestCode, Bundle options) {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            fragmentHostCallback.onStartActivityFromFragment(this, intent, requestCode, options);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to Activity");
        throw new IllegalStateException(sb.toString());
    }

    public void startIntentSenderForResult(IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags, Bundle options) throws SendIntentException {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            fragmentHostCallback.onStartIntentSenderFromFragment(this, intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags, options);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to Activity");
        throw new IllegalStateException(sb.toString());
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
    }

    public final void requestPermissions(String[] permissions, int requestCode) {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            fragmentHostCallback.onRequestPermissionsFromFragment(this, permissions, requestCode);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" not attached to Activity");
        throw new IllegalStateException(sb.toString());
    }

    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
    }

    public boolean shouldShowRequestPermissionRationale(String permission) {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            return fragmentHostCallback.onShouldShowRequestPermissionRationale(permission);
        }
        return false;
    }

    public LayoutInflater onGetLayoutInflater(Bundle savedInstanceState) {
        return getLayoutInflater(savedInstanceState);
    }

    public final LayoutInflater getLayoutInflater() {
        LayoutInflater layoutInflater = this.mLayoutInflater;
        if (layoutInflater == null) {
            return performGetLayoutInflater(null);
        }
        return layoutInflater;
    }

    /* access modifiers changed from: 0000 */
    public LayoutInflater performGetLayoutInflater(Bundle savedInstanceState) {
        LayoutInflater layoutInflater = onGetLayoutInflater(savedInstanceState);
        this.mLayoutInflater = layoutInflater;
        return layoutInflater;
    }

    @Deprecated
    public LayoutInflater getLayoutInflater(Bundle savedFragmentState) {
        FragmentHostCallback fragmentHostCallback = this.mHost;
        if (fragmentHostCallback != null) {
            LayoutInflater result = fragmentHostCallback.onGetLayoutInflater();
            LayoutInflaterCompat.setFactory2(result, this.mChildFragmentManager.getLayoutInflaterFactory());
            return result;
        }
        throw new IllegalStateException("onGetLayoutInflater() cannot be executed until the Fragment is attached to the FragmentManager.");
    }

    public void onInflate(Context context, AttributeSet attrs, Bundle savedInstanceState) {
        this.mCalled = true;
        FragmentHostCallback fragmentHostCallback = this.mHost;
        Activity hostActivity = fragmentHostCallback == null ? null : fragmentHostCallback.getActivity();
        if (hostActivity != null) {
            this.mCalled = false;
            onInflate(hostActivity, attrs, savedInstanceState);
        }
    }

    @Deprecated
    public void onInflate(Activity activity, AttributeSet attrs, Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onAttachFragment(Fragment childFragment) {
    }

    public void onAttach(Context context) {
        this.mCalled = true;
        FragmentHostCallback fragmentHostCallback = this.mHost;
        Activity hostActivity = fragmentHostCallback == null ? null : fragmentHostCallback.getActivity();
        if (hostActivity != null) {
            this.mCalled = false;
            onAttach(hostActivity);
        }
    }

    @Deprecated
    public void onAttach(Activity activity) {
        this.mCalled = true;
    }

    public Animation onCreateAnimation(int transit, boolean enter, int nextAnim) {
        return null;
    }

    public Animator onCreateAnimator(int transit, boolean enter, int nextAnim) {
        return null;
    }

    public void onCreate(Bundle savedInstanceState) {
        this.mCalled = true;
        restoreChildFragmentState(savedInstanceState);
        if (!this.mChildFragmentManager.isStateAtLeast(1)) {
            this.mChildFragmentManager.dispatchCreate();
        }
    }

    /* access modifiers changed from: 0000 */
    public void restoreChildFragmentState(Bundle savedInstanceState) {
        if (savedInstanceState != null) {
            Parcelable p = savedInstanceState.getParcelable("android:support:fragments");
            if (p != null) {
                this.mChildFragmentManager.restoreSaveState(p);
                this.mChildFragmentManager.dispatchCreate();
            }
        }
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        int i = this.mContentLayoutId;
        if (i != 0) {
            return inflater.inflate(i, container, false);
        }
        return null;
    }

    public void onViewCreated(View view, Bundle savedInstanceState) {
    }

    public View getView() {
        return this.mView;
    }

    public final View requireView() {
        View view = getView();
        if (view != null) {
            return view;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not return a View from onCreateView() or this was called before onCreateView().");
        throw new IllegalStateException(sb.toString());
    }

    public void onActivityCreated(Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onViewStateRestored(Bundle savedInstanceState) {
        this.mCalled = true;
    }

    public void onStart() {
        this.mCalled = true;
    }

    public void onResume() {
        this.mCalled = true;
    }

    public void onSaveInstanceState(Bundle outState) {
    }

    public void onMultiWindowModeChanged(boolean isInMultiWindowMode) {
    }

    public void onPictureInPictureModeChanged(boolean isInPictureInPictureMode) {
    }

    public void onConfigurationChanged(Configuration newConfig) {
        this.mCalled = true;
    }

    public void onPrimaryNavigationFragmentChanged(boolean isPrimaryNavigationFragment) {
    }

    public void onPause() {
        this.mCalled = true;
    }

    public void onStop() {
        this.mCalled = true;
    }

    public void onLowMemory() {
        this.mCalled = true;
    }

    public void onDestroyView() {
        this.mCalled = true;
    }

    public void onDestroy() {
        this.mCalled = true;
    }

    /* access modifiers changed from: 0000 */
    public void initState() {
        initLifecycle();
        this.mWho = UUID.randomUUID().toString();
        this.mAdded = false;
        this.mRemoving = false;
        this.mFromLayout = false;
        this.mInLayout = false;
        this.mRestored = false;
        this.mBackStackNesting = 0;
        this.mFragmentManager = null;
        this.mChildFragmentManager = new FragmentManagerImpl();
        this.mHost = null;
        this.mFragmentId = 0;
        this.mContainerId = 0;
        this.mTag = null;
        this.mHidden = false;
        this.mDetached = false;
    }

    public void onDetach() {
        this.mCalled = true;
    }

    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
    }

    public void onPrepareOptionsMenu(Menu menu) {
    }

    public void onDestroyOptionsMenu() {
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        return false;
    }

    public void onOptionsMenuClosed(Menu menu) {
    }

    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenuInfo menuInfo) {
        requireActivity().onCreateContextMenu(menu, v, menuInfo);
    }

    public void registerForContextMenu(View view) {
        view.setOnCreateContextMenuListener(this);
    }

    public void unregisterForContextMenu(View view) {
        view.setOnCreateContextMenuListener(null);
    }

    public boolean onContextItemSelected(MenuItem item) {
        return false;
    }

    public void setEnterSharedElementCallback(SharedElementCallback callback) {
        ensureAnimationInfo().mEnterTransitionCallback = callback;
    }

    public void setExitSharedElementCallback(SharedElementCallback callback) {
        ensureAnimationInfo().mExitTransitionCallback = callback;
    }

    public void setEnterTransition(Object transition) {
        ensureAnimationInfo().mEnterTransition = transition;
    }

    public Object getEnterTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mEnterTransition;
    }

    public void setReturnTransition(Object transition) {
        ensureAnimationInfo().mReturnTransition = transition;
    }

    public Object getReturnTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mReturnTransition == USE_DEFAULT_TRANSITION ? getEnterTransition() : this.mAnimationInfo.mReturnTransition;
    }

    public void setExitTransition(Object transition) {
        ensureAnimationInfo().mExitTransition = transition;
    }

    public Object getExitTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mExitTransition;
    }

    public void setReenterTransition(Object transition) {
        ensureAnimationInfo().mReenterTransition = transition;
    }

    public Object getReenterTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mReenterTransition == USE_DEFAULT_TRANSITION ? getExitTransition() : this.mAnimationInfo.mReenterTransition;
    }

    public void setSharedElementEnterTransition(Object transition) {
        ensureAnimationInfo().mSharedElementEnterTransition = transition;
    }

    public Object getSharedElementEnterTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mSharedElementEnterTransition;
    }

    public void setSharedElementReturnTransition(Object transition) {
        ensureAnimationInfo().mSharedElementReturnTransition = transition;
    }

    public Object getSharedElementReturnTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mSharedElementReturnTransition == USE_DEFAULT_TRANSITION ? getSharedElementEnterTransition() : this.mAnimationInfo.mSharedElementReturnTransition;
    }

    public void setAllowEnterTransitionOverlap(boolean allow) {
        ensureAnimationInfo().mAllowEnterTransitionOverlap = Boolean.valueOf(allow);
    }

    public boolean getAllowEnterTransitionOverlap() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null || animationInfo.mAllowEnterTransitionOverlap == null) {
            return true;
        }
        return this.mAnimationInfo.mAllowEnterTransitionOverlap.booleanValue();
    }

    public void setAllowReturnTransitionOverlap(boolean allow) {
        ensureAnimationInfo().mAllowReturnTransitionOverlap = Boolean.valueOf(allow);
    }

    public boolean getAllowReturnTransitionOverlap() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null || animationInfo.mAllowReturnTransitionOverlap == null) {
            return true;
        }
        return this.mAnimationInfo.mAllowReturnTransitionOverlap.booleanValue();
    }

    public void postponeEnterTransition() {
        ensureAnimationInfo().mEnterTransitionPostponed = true;
    }

    public final void postponeEnterTransition(long duration, TimeUnit timeUnit) {
        Handler handler;
        ensureAnimationInfo().mEnterTransitionPostponed = true;
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl != null) {
            handler = fragmentManagerImpl.mHost.getHandler();
        } else {
            handler = new Handler(Looper.getMainLooper());
        }
        handler.removeCallbacks(this.mPostponedDurationRunnable);
        handler.postDelayed(this.mPostponedDurationRunnable, timeUnit.toMillis(duration));
    }

    public void startPostponedEnterTransition() {
        FragmentManagerImpl fragmentManagerImpl = this.mFragmentManager;
        if (fragmentManagerImpl == null || fragmentManagerImpl.mHost == null) {
            ensureAnimationInfo().mEnterTransitionPostponed = false;
        } else if (Looper.myLooper() != this.mFragmentManager.mHost.getHandler().getLooper()) {
            this.mFragmentManager.mHost.getHandler().postAtFrontOfQueue(new Runnable() {
                public void run() {
                    Fragment.this.callStartTransitionListener();
                }
            });
        } else {
            callStartTransitionListener();
        }
    }

    /* access modifiers changed from: 0000 */
    public void callStartTransitionListener() {
        OnStartEnterTransitionListener listener;
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            listener = null;
        } else {
            animationInfo.mEnterTransitionPostponed = false;
            listener = this.mAnimationInfo.mStartEnterTransitionListener;
            this.mAnimationInfo.mStartEnterTransitionListener = null;
        }
        if (listener != null) {
            listener.onStartEnterTransition();
        }
    }

    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        writer.print(prefix);
        writer.print("mFragmentId=#");
        writer.print(Integer.toHexString(this.mFragmentId));
        writer.print(" mContainerId=#");
        writer.print(Integer.toHexString(this.mContainerId));
        writer.print(" mTag=");
        writer.println(this.mTag);
        writer.print(prefix);
        writer.print("mState=");
        writer.print(this.mState);
        writer.print(" mWho=");
        writer.print(this.mWho);
        writer.print(" mBackStackNesting=");
        writer.println(this.mBackStackNesting);
        writer.print(prefix);
        writer.print("mAdded=");
        writer.print(this.mAdded);
        writer.print(" mRemoving=");
        writer.print(this.mRemoving);
        writer.print(" mFromLayout=");
        writer.print(this.mFromLayout);
        writer.print(" mInLayout=");
        writer.println(this.mInLayout);
        writer.print(prefix);
        writer.print("mHidden=");
        writer.print(this.mHidden);
        writer.print(" mDetached=");
        writer.print(this.mDetached);
        writer.print(" mMenuVisible=");
        writer.print(this.mMenuVisible);
        writer.print(" mHasMenu=");
        writer.println(this.mHasMenu);
        writer.print(prefix);
        writer.print("mRetainInstance=");
        writer.print(this.mRetainInstance);
        writer.print(" mUserVisibleHint=");
        writer.println(this.mUserVisibleHint);
        if (this.mFragmentManager != null) {
            writer.print(prefix);
            writer.print("mFragmentManager=");
            writer.println(this.mFragmentManager);
        }
        if (this.mHost != null) {
            writer.print(prefix);
            writer.print("mHost=");
            writer.println(this.mHost);
        }
        if (this.mParentFragment != null) {
            writer.print(prefix);
            writer.print("mParentFragment=");
            writer.println(this.mParentFragment);
        }
        if (this.mArguments != null) {
            writer.print(prefix);
            writer.print("mArguments=");
            writer.println(this.mArguments);
        }
        if (this.mSavedFragmentState != null) {
            writer.print(prefix);
            writer.print("mSavedFragmentState=");
            writer.println(this.mSavedFragmentState);
        }
        if (this.mSavedViewState != null) {
            writer.print(prefix);
            writer.print("mSavedViewState=");
            writer.println(this.mSavedViewState);
        }
        Fragment target = getTargetFragment();
        if (target != null) {
            writer.print(prefix);
            writer.print("mTarget=");
            writer.print(target);
            writer.print(" mTargetRequestCode=");
            writer.println(this.mTargetRequestCode);
        }
        if (getNextAnim() != 0) {
            writer.print(prefix);
            writer.print("mNextAnim=");
            writer.println(getNextAnim());
        }
        if (this.mContainer != null) {
            writer.print(prefix);
            writer.print("mContainer=");
            writer.println(this.mContainer);
        }
        if (this.mView != null) {
            writer.print(prefix);
            writer.print("mView=");
            writer.println(this.mView);
        }
        if (this.mInnerView != null) {
            writer.print(prefix);
            writer.print("mInnerView=");
            writer.println(this.mView);
        }
        if (getAnimatingAway() != null) {
            writer.print(prefix);
            writer.print("mAnimatingAway=");
            writer.println(getAnimatingAway());
            writer.print(prefix);
            writer.print("mStateAfterAnimating=");
            writer.println(getStateAfterAnimating());
        }
        if (getContext() != null) {
            LoaderManager.getInstance(this).dump(prefix, fd, writer, args);
        }
        writer.print(prefix);
        StringBuilder sb = new StringBuilder();
        sb.append("Child ");
        sb.append(this.mChildFragmentManager);
        sb.append(":");
        writer.println(sb.toString());
        FragmentManagerImpl fragmentManagerImpl = this.mChildFragmentManager;
        StringBuilder sb2 = new StringBuilder();
        sb2.append(prefix);
        sb2.append("  ");
        fragmentManagerImpl.dump(sb2.toString(), fd, writer, args);
    }

    /* access modifiers changed from: 0000 */
    public Fragment findFragmentByWho(String who) {
        if (who.equals(this.mWho)) {
            return this;
        }
        return this.mChildFragmentManager.findFragmentByWho(who);
    }

    /* access modifiers changed from: 0000 */
    public void performAttach() {
        this.mChildFragmentManager.attachController(this.mHost, new FragmentContainer() {
            public View onFindViewById(int id) {
                if (Fragment.this.mView != null) {
                    return Fragment.this.mView.findViewById(id);
                }
                StringBuilder sb = new StringBuilder();
                sb.append("Fragment ");
                sb.append(this);
                sb.append(" does not have a view");
                throw new IllegalStateException(sb.toString());
            }

            public boolean onHasView() {
                return Fragment.this.mView != null;
            }
        }, this);
        this.mCalled = false;
        onAttach(this.mHost.getContext());
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onAttach()");
            throw new SuperNotCalledException(sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void performCreate(Bundle savedInstanceState) {
        this.mChildFragmentManager.noteStateNotSaved();
        this.mState = 1;
        this.mCalled = false;
        this.mSavedStateRegistryController.performRestore(savedInstanceState);
        onCreate(savedInstanceState);
        this.mIsCreated = true;
        if (this.mCalled) {
            this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_CREATE);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not call through to super.onCreate()");
        throw new SuperNotCalledException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void performCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.mChildFragmentManager.noteStateNotSaved();
        this.mPerformedCreateView = true;
        this.mViewLifecycleOwner = new FragmentViewLifecycleOwner();
        View onCreateView = onCreateView(inflater, container, savedInstanceState);
        this.mView = onCreateView;
        if (onCreateView != null) {
            this.mViewLifecycleOwner.initialize();
            this.mViewLifecycleOwnerLiveData.setValue(this.mViewLifecycleOwner);
        } else if (!this.mViewLifecycleOwner.isInitialized()) {
            this.mViewLifecycleOwner = null;
        } else {
            throw new IllegalStateException("Called getViewLifecycleOwner() but onCreateView() returned null");
        }
    }

    /* access modifiers changed from: 0000 */
    public void performActivityCreated(Bundle savedInstanceState) {
        this.mChildFragmentManager.noteStateNotSaved();
        this.mState = 2;
        this.mCalled = false;
        onActivityCreated(savedInstanceState);
        if (this.mCalled) {
            this.mChildFragmentManager.dispatchActivityCreated();
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not call through to super.onActivityCreated()");
        throw new SuperNotCalledException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void performStart() {
        this.mChildFragmentManager.noteStateNotSaved();
        this.mChildFragmentManager.execPendingActions();
        this.mState = 3;
        this.mCalled = false;
        onStart();
        if (this.mCalled) {
            this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_START);
            if (this.mView != null) {
                this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_START);
            }
            this.mChildFragmentManager.dispatchStart();
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not call through to super.onStart()");
        throw new SuperNotCalledException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void performResume() {
        this.mChildFragmentManager.noteStateNotSaved();
        this.mChildFragmentManager.execPendingActions();
        this.mState = 4;
        this.mCalled = false;
        onResume();
        if (this.mCalled) {
            this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_RESUME);
            if (this.mView != null) {
                this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_RESUME);
            }
            this.mChildFragmentManager.dispatchResume();
            this.mChildFragmentManager.execPendingActions();
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not call through to super.onResume()");
        throw new SuperNotCalledException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void noteStateNotSaved() {
        this.mChildFragmentManager.noteStateNotSaved();
    }

    /* access modifiers changed from: 0000 */
    public void performPrimaryNavigationFragmentChanged() {
        boolean isPrimaryNavigationFragment = this.mFragmentManager.isPrimaryNavigation(this);
        Boolean bool = this.mIsPrimaryNavigationFragment;
        if (bool == null || bool.booleanValue() != isPrimaryNavigationFragment) {
            this.mIsPrimaryNavigationFragment = Boolean.valueOf(isPrimaryNavigationFragment);
            onPrimaryNavigationFragmentChanged(isPrimaryNavigationFragment);
            this.mChildFragmentManager.dispatchPrimaryNavigationFragmentChanged();
        }
    }

    /* access modifiers changed from: 0000 */
    public void performMultiWindowModeChanged(boolean isInMultiWindowMode) {
        onMultiWindowModeChanged(isInMultiWindowMode);
        this.mChildFragmentManager.dispatchMultiWindowModeChanged(isInMultiWindowMode);
    }

    /* access modifiers changed from: 0000 */
    public void performPictureInPictureModeChanged(boolean isInPictureInPictureMode) {
        onPictureInPictureModeChanged(isInPictureInPictureMode);
        this.mChildFragmentManager.dispatchPictureInPictureModeChanged(isInPictureInPictureMode);
    }

    /* access modifiers changed from: 0000 */
    public void performConfigurationChanged(Configuration newConfig) {
        onConfigurationChanged(newConfig);
        this.mChildFragmentManager.dispatchConfigurationChanged(newConfig);
    }

    /* access modifiers changed from: 0000 */
    public void performLowMemory() {
        onLowMemory();
        this.mChildFragmentManager.dispatchLowMemory();
    }

    /* access modifiers changed from: 0000 */
    public boolean performCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        boolean show = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            show = true;
            onCreateOptionsMenu(menu, inflater);
        }
        return show | this.mChildFragmentManager.dispatchCreateOptionsMenu(menu, inflater);
    }

    /* access modifiers changed from: 0000 */
    public boolean performPrepareOptionsMenu(Menu menu) {
        boolean show = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            show = true;
            onPrepareOptionsMenu(menu);
        }
        return show | this.mChildFragmentManager.dispatchPrepareOptionsMenu(menu);
    }

    /* access modifiers changed from: 0000 */
    public boolean performOptionsItemSelected(MenuItem item) {
        if (this.mHidden || ((!this.mHasMenu || !this.mMenuVisible || !onOptionsItemSelected(item)) && !this.mChildFragmentManager.dispatchOptionsItemSelected(item))) {
            return false;
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    public boolean performContextItemSelected(MenuItem item) {
        if (this.mHidden || (!onContextItemSelected(item) && !this.mChildFragmentManager.dispatchContextItemSelected(item))) {
            return false;
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    public void performOptionsMenuClosed(Menu menu) {
        if (!this.mHidden) {
            if (this.mHasMenu && this.mMenuVisible) {
                onOptionsMenuClosed(menu);
            }
            this.mChildFragmentManager.dispatchOptionsMenuClosed(menu);
        }
    }

    /* access modifiers changed from: 0000 */
    public void performSaveInstanceState(Bundle outState) {
        onSaveInstanceState(outState);
        this.mSavedStateRegistryController.performSave(outState);
        Parcelable p = this.mChildFragmentManager.saveAllState();
        if (p != null) {
            outState.putParcelable("android:support:fragments", p);
        }
    }

    /* access modifiers changed from: 0000 */
    public void performPause() {
        this.mChildFragmentManager.dispatchPause();
        if (this.mView != null) {
            this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_PAUSE);
        }
        this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_PAUSE);
        this.mState = 3;
        this.mCalled = false;
        onPause();
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onPause()");
            throw new SuperNotCalledException(sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void performStop() {
        this.mChildFragmentManager.dispatchStop();
        if (this.mView != null) {
            this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_STOP);
        }
        this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_STOP);
        this.mState = 2;
        this.mCalled = false;
        onStop();
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onStop()");
            throw new SuperNotCalledException(sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void performDestroyView() {
        this.mChildFragmentManager.dispatchDestroyView();
        if (this.mView != null) {
            this.mViewLifecycleOwner.handleLifecycleEvent(Event.ON_DESTROY);
        }
        this.mState = 1;
        this.mCalled = false;
        onDestroyView();
        if (this.mCalled) {
            LoaderManager.getInstance(this).markForRedelivery();
            this.mPerformedCreateView = false;
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Fragment ");
        sb.append(this);
        sb.append(" did not call through to super.onDestroyView()");
        throw new SuperNotCalledException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void performDestroy() {
        this.mChildFragmentManager.dispatchDestroy();
        this.mLifecycleRegistry.handleLifecycleEvent(Event.ON_DESTROY);
        this.mState = 0;
        this.mCalled = false;
        this.mIsCreated = false;
        onDestroy();
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onDestroy()");
            throw new SuperNotCalledException(sb.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void performDetach() {
        this.mCalled = false;
        onDetach();
        this.mLayoutInflater = null;
        if (!this.mCalled) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(this);
            sb.append(" did not call through to super.onDetach()");
            throw new SuperNotCalledException(sb.toString());
        } else if (!this.mChildFragmentManager.isDestroyed()) {
            this.mChildFragmentManager.dispatchDestroy();
            this.mChildFragmentManager = new FragmentManagerImpl();
        }
    }

    /* access modifiers changed from: 0000 */
    public void setOnStartEnterTransitionListener(OnStartEnterTransitionListener listener) {
        ensureAnimationInfo();
        if (listener != this.mAnimationInfo.mStartEnterTransitionListener) {
            if (listener == null || this.mAnimationInfo.mStartEnterTransitionListener == null) {
                if (this.mAnimationInfo.mEnterTransitionPostponed) {
                    this.mAnimationInfo.mStartEnterTransitionListener = listener;
                }
                if (listener != null) {
                    listener.startListening();
                }
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Trying to set a replacement startPostponedEnterTransition on ");
            sb.append(this);
            throw new IllegalStateException(sb.toString());
        }
    }

    private AnimationInfo ensureAnimationInfo() {
        if (this.mAnimationInfo == null) {
            this.mAnimationInfo = new AnimationInfo();
        }
        return this.mAnimationInfo;
    }

    /* access modifiers changed from: 0000 */
    public int getNextAnim() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return 0;
        }
        return animationInfo.mNextAnim;
    }

    /* access modifiers changed from: 0000 */
    public void setNextAnim(int animResourceId) {
        if (this.mAnimationInfo != null || animResourceId != 0) {
            ensureAnimationInfo().mNextAnim = animResourceId;
        }
    }

    /* access modifiers changed from: 0000 */
    public int getNextTransition() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return 0;
        }
        return animationInfo.mNextTransition;
    }

    /* access modifiers changed from: 0000 */
    public void setNextTransition(int nextTransition, int nextTransitionStyle) {
        if (this.mAnimationInfo != null || nextTransition != 0 || nextTransitionStyle != 0) {
            ensureAnimationInfo();
            this.mAnimationInfo.mNextTransition = nextTransition;
            this.mAnimationInfo.mNextTransitionStyle = nextTransitionStyle;
        }
    }

    /* access modifiers changed from: 0000 */
    public int getNextTransitionStyle() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return 0;
        }
        return animationInfo.mNextTransitionStyle;
    }

    /* access modifiers changed from: 0000 */
    public SharedElementCallback getEnterTransitionCallback() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mEnterTransitionCallback;
    }

    /* access modifiers changed from: 0000 */
    public SharedElementCallback getExitTransitionCallback() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mExitTransitionCallback;
    }

    /* access modifiers changed from: 0000 */
    public View getAnimatingAway() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mAnimatingAway;
    }

    /* access modifiers changed from: 0000 */
    public void setAnimatingAway(View view) {
        ensureAnimationInfo().mAnimatingAway = view;
    }

    /* access modifiers changed from: 0000 */
    public void setAnimator(Animator animator) {
        ensureAnimationInfo().mAnimator = animator;
    }

    /* access modifiers changed from: 0000 */
    public Animator getAnimator() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return null;
        }
        return animationInfo.mAnimator;
    }

    /* access modifiers changed from: 0000 */
    public int getStateAfterAnimating() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return 0;
        }
        return animationInfo.mStateAfterAnimating;
    }

    /* access modifiers changed from: 0000 */
    public void setStateAfterAnimating(int state) {
        ensureAnimationInfo().mStateAfterAnimating = state;
    }

    /* access modifiers changed from: 0000 */
    public boolean isPostponed() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return false;
        }
        return animationInfo.mEnterTransitionPostponed;
    }

    /* access modifiers changed from: 0000 */
    public boolean isHideReplaced() {
        AnimationInfo animationInfo = this.mAnimationInfo;
        if (animationInfo == null) {
            return false;
        }
        return animationInfo.mIsHideReplaced;
    }

    /* access modifiers changed from: 0000 */
    public void setHideReplaced(boolean replaced) {
        ensureAnimationInfo().mIsHideReplaced = replaced;
    }
}
