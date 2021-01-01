package androidx.fragment.app;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.BaseSavedState;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;
import android.widget.LinearLayout;
import android.widget.TabHost;
import android.widget.TabHost.OnTabChangeListener;
import android.widget.TabHost.TabContentFactory;
import android.widget.TabHost.TabSpec;
import android.widget.TabWidget;
import java.util.ArrayList;

@Deprecated
public class FragmentTabHost extends TabHost implements OnTabChangeListener {
    private boolean mAttached;
    private int mContainerId;
    private Context mContext;
    private FragmentManager mFragmentManager;
    private TabInfo mLastTab;
    private OnTabChangeListener mOnTabChangeListener;
    private FrameLayout mRealTabContent;
    private final ArrayList<TabInfo> mTabs = new ArrayList<>();

    static class DummyTabFactory implements TabContentFactory {
        private final Context mContext;

        public DummyTabFactory(Context context) {
            this.mContext = context;
        }

        public View createTabContent(String tag) {
            View v = new View(this.mContext);
            v.setMinimumWidth(0);
            v.setMinimumHeight(0);
            return v;
        }
    }

    static class SavedState extends BaseSavedState {
        public static final Creator<SavedState> CREATOR = new Creator<SavedState>() {
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        String curTab;

        SavedState(Parcelable superState) {
            super(superState);
        }

        SavedState(Parcel in) {
            super(in);
            this.curTab = in.readString();
        }

        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeString(this.curTab);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("FragmentTabHost.SavedState{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" curTab=");
            sb.append(this.curTab);
            sb.append("}");
            return sb.toString();
        }
    }

    static final class TabInfo {
        final Bundle args;
        final Class<?> clss;
        Fragment fragment;
        final String tag;

        TabInfo(String _tag, Class<?> _class, Bundle _args) {
            this.tag = _tag;
            this.clss = _class;
            this.args = _args;
        }
    }

    @Deprecated
    public FragmentTabHost(Context context) {
        super(context, null);
        initFragmentTabHost(context, null);
    }

    @Deprecated
    public FragmentTabHost(Context context, AttributeSet attrs) {
        super(context, attrs);
        initFragmentTabHost(context, attrs);
    }

    private void initFragmentTabHost(Context context, AttributeSet attrs) {
        TypedArray a = context.obtainStyledAttributes(attrs, new int[]{16842995}, 0, 0);
        this.mContainerId = a.getResourceId(0, 0);
        a.recycle();
        super.setOnTabChangedListener(this);
    }

    private void ensureHierarchy(Context context) {
        if (findViewById(16908307) == null) {
            LinearLayout ll = new LinearLayout(context);
            ll.setOrientation(1);
            addView(ll, new LayoutParams(-1, -1));
            TabWidget tw = new TabWidget(context);
            tw.setId(16908307);
            tw.setOrientation(0);
            ll.addView(tw, new LinearLayout.LayoutParams(-1, -2, 0.0f));
            FrameLayout fl = new FrameLayout(context);
            fl.setId(16908305);
            ll.addView(fl, new LinearLayout.LayoutParams(0, 0, 0.0f));
            FrameLayout frameLayout = new FrameLayout(context);
            FrameLayout fl2 = frameLayout;
            this.mRealTabContent = frameLayout;
            frameLayout.setId(this.mContainerId);
            ll.addView(fl2, new LinearLayout.LayoutParams(-1, 0, 1.0f));
        }
    }

    @Deprecated
    public void setup() {
        throw new IllegalStateException("Must call setup() that takes a Context and FragmentManager");
    }

    @Deprecated
    public void setup(Context context, FragmentManager manager) {
        ensureHierarchy(context);
        super.setup();
        this.mContext = context;
        this.mFragmentManager = manager;
        ensureContent();
    }

    @Deprecated
    public void setup(Context context, FragmentManager manager, int containerId) {
        ensureHierarchy(context);
        super.setup();
        this.mContext = context;
        this.mFragmentManager = manager;
        this.mContainerId = containerId;
        ensureContent();
        this.mRealTabContent.setId(containerId);
        if (getId() == -1) {
            setId(16908306);
        }
    }

    private void ensureContent() {
        if (this.mRealTabContent == null) {
            FrameLayout frameLayout = (FrameLayout) findViewById(this.mContainerId);
            this.mRealTabContent = frameLayout;
            if (frameLayout == null) {
                StringBuilder sb = new StringBuilder();
                sb.append("No tab content FrameLayout found for id ");
                sb.append(this.mContainerId);
                throw new IllegalStateException(sb.toString());
            }
        }
    }

    @Deprecated
    public void setOnTabChangedListener(OnTabChangeListener l) {
        this.mOnTabChangeListener = l;
    }

    @Deprecated
    public void addTab(TabSpec tabSpec, Class<?> clss, Bundle args) {
        tabSpec.setContent(new DummyTabFactory(this.mContext));
        String tag = tabSpec.getTag();
        TabInfo info = new TabInfo(tag, clss, args);
        if (this.mAttached) {
            info.fragment = this.mFragmentManager.findFragmentByTag(tag);
            if (info.fragment != null && !info.fragment.isDetached()) {
                FragmentTransaction ft = this.mFragmentManager.beginTransaction();
                ft.detach(info.fragment);
                ft.commit();
            }
        }
        this.mTabs.add(info);
        addTab(tabSpec);
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        String currentTag = getCurrentTabTag();
        FragmentTransaction ft = null;
        int count = this.mTabs.size();
        for (int i = 0; i < count; i++) {
            TabInfo tab = (TabInfo) this.mTabs.get(i);
            tab.fragment = this.mFragmentManager.findFragmentByTag(tab.tag);
            if (tab.fragment != null && !tab.fragment.isDetached()) {
                if (tab.tag.equals(currentTag)) {
                    this.mLastTab = tab;
                } else {
                    if (ft == null) {
                        ft = this.mFragmentManager.beginTransaction();
                    }
                    ft.detach(tab.fragment);
                }
            }
        }
        this.mAttached = true;
        FragmentTransaction ft2 = doTabChanged(currentTag, ft);
        if (ft2 != null) {
            ft2.commit();
            this.mFragmentManager.executePendingTransactions();
        }
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.mAttached = false;
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        ss.curTab = getCurrentTabTag();
        return ss;
    }

    /* access modifiers changed from: protected */
    @Deprecated
    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        setCurrentTabByTag(ss.curTab);
    }

    @Deprecated
    public void onTabChanged(String tabId) {
        if (this.mAttached) {
            FragmentTransaction ft = doTabChanged(tabId, null);
            if (ft != null) {
                ft.commit();
            }
        }
        OnTabChangeListener onTabChangeListener = this.mOnTabChangeListener;
        if (onTabChangeListener != null) {
            onTabChangeListener.onTabChanged(tabId);
        }
    }

    private FragmentTransaction doTabChanged(String tag, FragmentTransaction ft) {
        TabInfo newTab = getTabInfoForTag(tag);
        if (this.mLastTab != newTab) {
            if (ft == null) {
                ft = this.mFragmentManager.beginTransaction();
            }
            TabInfo tabInfo = this.mLastTab;
            if (!(tabInfo == null || tabInfo.fragment == null)) {
                ft.detach(this.mLastTab.fragment);
            }
            if (newTab != null) {
                if (newTab.fragment == null) {
                    newTab.fragment = this.mFragmentManager.getFragmentFactory().instantiate(this.mContext.getClassLoader(), newTab.clss.getName());
                    newTab.fragment.setArguments(newTab.args);
                    ft.add(this.mContainerId, newTab.fragment, newTab.tag);
                } else {
                    ft.attach(newTab.fragment);
                }
            }
            this.mLastTab = newTab;
        }
        return ft;
    }

    private TabInfo getTabInfoForTag(String tabId) {
        int count = this.mTabs.size();
        for (int i = 0; i < count; i++) {
            TabInfo tab = (TabInfo) this.mTabs.get(i);
            if (tab.tag.equals(tabId)) {
                return tab;
            }
        }
        return null;
    }
}
