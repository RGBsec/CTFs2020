package androidx.viewpager.widget;

import android.content.Context;
import android.content.res.Resources.NotFoundException;
import android.content.res.TypedArray;
import android.database.DataSetObserver;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.util.Log;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.SoundEffectConstants;
import android.view.VelocityTracker;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.animation.Interpolator;
import android.widget.EdgeEffect;
import android.widget.Scroller;
import androidx.core.content.ContextCompat;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.OnApplyWindowInsetsListener;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.customview.view.AbsSavedState;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class ViewPager extends ViewGroup {
    private static final int CLOSE_ENOUGH = 2;
    private static final Comparator<ItemInfo> COMPARATOR = new Comparator<ItemInfo>() {
        public int compare(ItemInfo lhs, ItemInfo rhs) {
            return lhs.position - rhs.position;
        }
    };
    private static final boolean DEBUG = false;
    private static final int DEFAULT_GUTTER_SIZE = 16;
    private static final int DEFAULT_OFFSCREEN_PAGES = 1;
    private static final int DRAW_ORDER_DEFAULT = 0;
    private static final int DRAW_ORDER_FORWARD = 1;
    private static final int DRAW_ORDER_REVERSE = 2;
    private static final int INVALID_POINTER = -1;
    static final int[] LAYOUT_ATTRS = {16842931};
    private static final int MAX_SETTLE_DURATION = 600;
    private static final int MIN_DISTANCE_FOR_FLING = 25;
    private static final int MIN_FLING_VELOCITY = 400;
    public static final int SCROLL_STATE_DRAGGING = 1;
    public static final int SCROLL_STATE_IDLE = 0;
    public static final int SCROLL_STATE_SETTLING = 2;
    private static final String TAG = "ViewPager";
    private static final boolean USE_CACHE = false;
    private static final Interpolator sInterpolator = new Interpolator() {
        public float getInterpolation(float t) {
            float t2 = t - 1.0f;
            return (t2 * t2 * t2 * t2 * t2) + 1.0f;
        }
    };
    private static final ViewPositionComparator sPositionComparator = new ViewPositionComparator();
    private int mActivePointerId = -1;
    PagerAdapter mAdapter;
    private List<OnAdapterChangeListener> mAdapterChangeListeners;
    private int mBottomPageBounds;
    private boolean mCalledSuper;
    private int mChildHeightMeasureSpec;
    private int mChildWidthMeasureSpec;
    private int mCloseEnough;
    int mCurItem;
    private int mDecorChildCount;
    private int mDefaultGutterSize;
    private int mDrawingOrder;
    private ArrayList<View> mDrawingOrderedChildren;
    private final Runnable mEndScrollRunnable = new Runnable() {
        public void run() {
            ViewPager.this.setScrollState(0);
            ViewPager.this.populate();
        }
    };
    private int mExpectedAdapterCount;
    private long mFakeDragBeginTime;
    private boolean mFakeDragging;
    private boolean mFirstLayout = true;
    private float mFirstOffset = -3.4028235E38f;
    private int mFlingDistance;
    private int mGutterSize;
    private boolean mInLayout;
    private float mInitialMotionX;
    private float mInitialMotionY;
    private OnPageChangeListener mInternalPageChangeListener;
    private boolean mIsBeingDragged;
    private boolean mIsScrollStarted;
    private boolean mIsUnableToDrag;
    private final ArrayList<ItemInfo> mItems = new ArrayList<>();
    private float mLastMotionX;
    private float mLastMotionY;
    private float mLastOffset = Float.MAX_VALUE;
    private EdgeEffect mLeftEdge;
    private Drawable mMarginDrawable;
    private int mMaximumVelocity;
    private int mMinimumVelocity;
    private boolean mNeedCalculatePageOffsets = false;
    private PagerObserver mObserver;
    private int mOffscreenPageLimit = 1;
    private OnPageChangeListener mOnPageChangeListener;
    private List<OnPageChangeListener> mOnPageChangeListeners;
    private int mPageMargin;
    private PageTransformer mPageTransformer;
    private int mPageTransformerLayerType;
    private boolean mPopulatePending;
    private Parcelable mRestoredAdapterState = null;
    private ClassLoader mRestoredClassLoader = null;
    private int mRestoredCurItem = -1;
    private EdgeEffect mRightEdge;
    private int mScrollState = 0;
    private Scroller mScroller;
    private boolean mScrollingCacheEnabled;
    private final ItemInfo mTempItem = new ItemInfo();
    private final Rect mTempRect = new Rect();
    private int mTopPageBounds;
    private int mTouchSlop;
    private VelocityTracker mVelocityTracker;

    @Inherited
    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.RUNTIME)
    public @interface DecorView {
    }

    static class ItemInfo {
        Object object;
        float offset;
        int position;
        boolean scrolling;
        float widthFactor;

        ItemInfo() {
        }
    }

    public static class LayoutParams extends android.view.ViewGroup.LayoutParams {
        int childIndex;
        public int gravity;
        public boolean isDecor;
        boolean needsMeasure;
        int position;
        float widthFactor = 0.0f;

        public LayoutParams() {
            super(-1, -1);
        }

        public LayoutParams(Context context, AttributeSet attrs) {
            super(context, attrs);
            TypedArray a = context.obtainStyledAttributes(attrs, ViewPager.LAYOUT_ATTRS);
            this.gravity = a.getInteger(0, 48);
            a.recycle();
        }
    }

    class MyAccessibilityDelegate extends AccessibilityDelegateCompat {
        MyAccessibilityDelegate() {
        }

        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            super.onInitializeAccessibilityEvent(host, event);
            event.setClassName(ViewPager.class.getName());
            event.setScrollable(canScroll());
            if (event.getEventType() == 4096 && ViewPager.this.mAdapter != null) {
                event.setItemCount(ViewPager.this.mAdapter.getCount());
                event.setFromIndex(ViewPager.this.mCurItem);
                event.setToIndex(ViewPager.this.mCurItem);
            }
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
            super.onInitializeAccessibilityNodeInfo(host, info);
            info.setClassName(ViewPager.class.getName());
            info.setScrollable(canScroll());
            if (ViewPager.this.canScrollHorizontally(1)) {
                info.addAction(4096);
            }
            if (ViewPager.this.canScrollHorizontally(-1)) {
                info.addAction(8192);
            }
        }

        public boolean performAccessibilityAction(View host, int action, Bundle args) {
            if (super.performAccessibilityAction(host, action, args)) {
                return true;
            }
            if (action != 4096) {
                if (action != 8192 || !ViewPager.this.canScrollHorizontally(-1)) {
                    return false;
                }
                ViewPager viewPager = ViewPager.this;
                viewPager.setCurrentItem(viewPager.mCurItem - 1);
                return true;
            } else if (!ViewPager.this.canScrollHorizontally(1)) {
                return false;
            } else {
                ViewPager viewPager2 = ViewPager.this;
                viewPager2.setCurrentItem(viewPager2.mCurItem + 1);
                return true;
            }
        }

        private boolean canScroll() {
            return ViewPager.this.mAdapter != null && ViewPager.this.mAdapter.getCount() > 1;
        }
    }

    public interface OnAdapterChangeListener {
        void onAdapterChanged(ViewPager viewPager, PagerAdapter pagerAdapter, PagerAdapter pagerAdapter2);
    }

    public interface OnPageChangeListener {
        void onPageScrollStateChanged(int i);

        void onPageScrolled(int i, float f, int i2);

        void onPageSelected(int i);
    }

    public interface PageTransformer {
        void transformPage(View view, float f);
    }

    private class PagerObserver extends DataSetObserver {
        PagerObserver() {
        }

        public void onChanged() {
            ViewPager.this.dataSetChanged();
        }

        public void onInvalidated() {
            ViewPager.this.dataSetChanged();
        }
    }

    public static class SavedState extends AbsSavedState {
        public static final Creator<SavedState> CREATOR = new ClassLoaderCreator<SavedState>() {
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        Parcelable adapterState;
        ClassLoader loader;
        int position;

        public SavedState(Parcelable superState) {
            super(superState);
        }

        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.position);
            out.writeParcelable(this.adapterState, flags);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("FragmentPager.SavedState{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" position=");
            sb.append(this.position);
            sb.append("}");
            return sb.toString();
        }

        SavedState(Parcel in, ClassLoader loader2) {
            super(in, loader2);
            if (loader2 == null) {
                loader2 = getClass().getClassLoader();
            }
            this.position = in.readInt();
            this.adapterState = in.readParcelable(loader2);
            this.loader = loader2;
        }
    }

    public static class SimpleOnPageChangeListener implements OnPageChangeListener {
        public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
        }

        public void onPageSelected(int position) {
        }

        public void onPageScrollStateChanged(int state) {
        }
    }

    static class ViewPositionComparator implements Comparator<View> {
        ViewPositionComparator() {
        }

        public int compare(View lhs, View rhs) {
            LayoutParams llp = (LayoutParams) lhs.getLayoutParams();
            LayoutParams rlp = (LayoutParams) rhs.getLayoutParams();
            if (llp.isDecor == rlp.isDecor) {
                return llp.position - rlp.position;
            }
            return llp.isDecor ? 1 : -1;
        }
    }

    public ViewPager(Context context) {
        super(context);
        initViewPager();
    }

    public ViewPager(Context context, AttributeSet attrs) {
        super(context, attrs);
        initViewPager();
    }

    /* access modifiers changed from: 0000 */
    public void initViewPager() {
        setWillNotDraw(false);
        setDescendantFocusability(262144);
        setFocusable(true);
        Context context = getContext();
        this.mScroller = new Scroller(context, sInterpolator);
        ViewConfiguration configuration = ViewConfiguration.get(context);
        float density = context.getResources().getDisplayMetrics().density;
        this.mTouchSlop = configuration.getScaledPagingTouchSlop();
        this.mMinimumVelocity = (int) (400.0f * density);
        this.mMaximumVelocity = configuration.getScaledMaximumFlingVelocity();
        this.mLeftEdge = new EdgeEffect(context);
        this.mRightEdge = new EdgeEffect(context);
        this.mFlingDistance = (int) (25.0f * density);
        this.mCloseEnough = (int) (2.0f * density);
        this.mDefaultGutterSize = (int) (16.0f * density);
        ViewCompat.setAccessibilityDelegate(this, new MyAccessibilityDelegate());
        if (ViewCompat.getImportantForAccessibility(this) == 0) {
            ViewCompat.setImportantForAccessibility(this, 1);
        }
        ViewCompat.setOnApplyWindowInsetsListener(this, new OnApplyWindowInsetsListener() {
            private final Rect mTempRect = new Rect();

            public WindowInsetsCompat onApplyWindowInsets(View v, WindowInsetsCompat originalInsets) {
                WindowInsetsCompat applied = ViewCompat.onApplyWindowInsets(v, originalInsets);
                if (applied.isConsumed()) {
                    return applied;
                }
                Rect res = this.mTempRect;
                res.left = applied.getSystemWindowInsetLeft();
                res.top = applied.getSystemWindowInsetTop();
                res.right = applied.getSystemWindowInsetRight();
                res.bottom = applied.getSystemWindowInsetBottom();
                int count = ViewPager.this.getChildCount();
                for (int i = 0; i < count; i++) {
                    WindowInsetsCompat childInsets = ViewCompat.dispatchApplyWindowInsets(ViewPager.this.getChildAt(i), applied);
                    res.left = Math.min(childInsets.getSystemWindowInsetLeft(), res.left);
                    res.top = Math.min(childInsets.getSystemWindowInsetTop(), res.top);
                    res.right = Math.min(childInsets.getSystemWindowInsetRight(), res.right);
                    res.bottom = Math.min(childInsets.getSystemWindowInsetBottom(), res.bottom);
                }
                return applied.replaceSystemWindowInsets(res.left, res.top, res.right, res.bottom);
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onDetachedFromWindow() {
        removeCallbacks(this.mEndScrollRunnable);
        Scroller scroller = this.mScroller;
        if (scroller != null && !scroller.isFinished()) {
            this.mScroller.abortAnimation();
        }
        super.onDetachedFromWindow();
    }

    /* access modifiers changed from: 0000 */
    public void setScrollState(int newState) {
        if (this.mScrollState != newState) {
            this.mScrollState = newState;
            if (this.mPageTransformer != null) {
                enableLayers(newState != 0);
            }
            dispatchOnScrollStateChanged(newState);
        }
    }

    public void setAdapter(PagerAdapter adapter) {
        PagerAdapter pagerAdapter = this.mAdapter;
        if (pagerAdapter != null) {
            pagerAdapter.setViewPagerObserver(null);
            this.mAdapter.startUpdate((ViewGroup) this);
            for (int i = 0; i < this.mItems.size(); i++) {
                ItemInfo ii = (ItemInfo) this.mItems.get(i);
                this.mAdapter.destroyItem((ViewGroup) this, ii.position, ii.object);
            }
            this.mAdapter.finishUpdate((ViewGroup) this);
            this.mItems.clear();
            removeNonDecorViews();
            this.mCurItem = 0;
            scrollTo(0, 0);
        }
        PagerAdapter oldAdapter = this.mAdapter;
        this.mAdapter = adapter;
        this.mExpectedAdapterCount = 0;
        if (adapter != null) {
            if (this.mObserver == null) {
                this.mObserver = new PagerObserver();
            }
            this.mAdapter.setViewPagerObserver(this.mObserver);
            this.mPopulatePending = false;
            boolean wasFirstLayout = this.mFirstLayout;
            this.mFirstLayout = true;
            this.mExpectedAdapterCount = this.mAdapter.getCount();
            if (this.mRestoredCurItem >= 0) {
                this.mAdapter.restoreState(this.mRestoredAdapterState, this.mRestoredClassLoader);
                setCurrentItemInternal(this.mRestoredCurItem, false, true);
                this.mRestoredCurItem = -1;
                this.mRestoredAdapterState = null;
                this.mRestoredClassLoader = null;
            } else if (!wasFirstLayout) {
                populate();
            } else {
                requestLayout();
            }
        }
        List<OnAdapterChangeListener> list = this.mAdapterChangeListeners;
        if (list != null && !list.isEmpty()) {
            int count = this.mAdapterChangeListeners.size();
            for (int i2 = 0; i2 < count; i2++) {
                ((OnAdapterChangeListener) this.mAdapterChangeListeners.get(i2)).onAdapterChanged(this, oldAdapter, adapter);
            }
        }
    }

    private void removeNonDecorViews() {
        int i = 0;
        while (i < getChildCount()) {
            if (!((LayoutParams) getChildAt(i).getLayoutParams()).isDecor) {
                removeViewAt(i);
                i--;
            }
            i++;
        }
    }

    public PagerAdapter getAdapter() {
        return this.mAdapter;
    }

    public void addOnAdapterChangeListener(OnAdapterChangeListener listener) {
        if (this.mAdapterChangeListeners == null) {
            this.mAdapterChangeListeners = new ArrayList();
        }
        this.mAdapterChangeListeners.add(listener);
    }

    public void removeOnAdapterChangeListener(OnAdapterChangeListener listener) {
        List<OnAdapterChangeListener> list = this.mAdapterChangeListeners;
        if (list != null) {
            list.remove(listener);
        }
    }

    private int getClientWidth() {
        return (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
    }

    public void setCurrentItem(int item) {
        this.mPopulatePending = false;
        setCurrentItemInternal(item, !this.mFirstLayout, false);
    }

    public void setCurrentItem(int item, boolean smoothScroll) {
        this.mPopulatePending = false;
        setCurrentItemInternal(item, smoothScroll, false);
    }

    public int getCurrentItem() {
        return this.mCurItem;
    }

    /* access modifiers changed from: 0000 */
    public void setCurrentItemInternal(int item, boolean smoothScroll, boolean always) {
        setCurrentItemInternal(item, smoothScroll, always, 0);
    }

    /* access modifiers changed from: 0000 */
    public void setCurrentItemInternal(int item, boolean smoothScroll, boolean always, int velocity) {
        PagerAdapter pagerAdapter = this.mAdapter;
        boolean z = false;
        if (pagerAdapter == null || pagerAdapter.getCount() <= 0) {
            setScrollingCacheEnabled(false);
        } else if (always || this.mCurItem != item || this.mItems.size() == 0) {
            if (item < 0) {
                item = 0;
            } else if (item >= this.mAdapter.getCount()) {
                item = this.mAdapter.getCount() - 1;
            }
            int pageLimit = this.mOffscreenPageLimit;
            int i = this.mCurItem;
            if (item > i + pageLimit || item < i - pageLimit) {
                for (int i2 = 0; i2 < this.mItems.size(); i2++) {
                    ((ItemInfo) this.mItems.get(i2)).scrolling = true;
                }
            }
            if (this.mCurItem != item) {
                z = true;
            }
            boolean dispatchSelected = z;
            if (this.mFirstLayout) {
                this.mCurItem = item;
                if (dispatchSelected) {
                    dispatchOnPageSelected(item);
                }
                requestLayout();
            } else {
                populate(item);
                scrollToItem(item, smoothScroll, velocity, dispatchSelected);
            }
        } else {
            setScrollingCacheEnabled(false);
        }
    }

    private void scrollToItem(int item, boolean smoothScroll, int velocity, boolean dispatchSelected) {
        ItemInfo curInfo = infoForPosition(item);
        int destX = 0;
        if (curInfo != null) {
            destX = (int) (((float) getClientWidth()) * Math.max(this.mFirstOffset, Math.min(curInfo.offset, this.mLastOffset)));
        }
        if (smoothScroll) {
            smoothScrollTo(destX, 0, velocity);
            if (dispatchSelected) {
                dispatchOnPageSelected(item);
                return;
            }
            return;
        }
        if (dispatchSelected) {
            dispatchOnPageSelected(item);
        }
        completeScroll(false);
        scrollTo(destX, 0);
        pageScrolled(destX);
    }

    @Deprecated
    public void setOnPageChangeListener(OnPageChangeListener listener) {
        this.mOnPageChangeListener = listener;
    }

    public void addOnPageChangeListener(OnPageChangeListener listener) {
        if (this.mOnPageChangeListeners == null) {
            this.mOnPageChangeListeners = new ArrayList();
        }
        this.mOnPageChangeListeners.add(listener);
    }

    public void removeOnPageChangeListener(OnPageChangeListener listener) {
        List<OnPageChangeListener> list = this.mOnPageChangeListeners;
        if (list != null) {
            list.remove(listener);
        }
    }

    public void clearOnPageChangeListeners() {
        List<OnPageChangeListener> list = this.mOnPageChangeListeners;
        if (list != null) {
            list.clear();
        }
    }

    public void setPageTransformer(boolean reverseDrawingOrder, PageTransformer transformer) {
        setPageTransformer(reverseDrawingOrder, transformer, 2);
    }

    public void setPageTransformer(boolean reverseDrawingOrder, PageTransformer transformer, int pageLayerType) {
        int i = 1;
        boolean hasTransformer = transformer != null;
        boolean needsPopulate = hasTransformer != (this.mPageTransformer != null);
        this.mPageTransformer = transformer;
        setChildrenDrawingOrderEnabled(hasTransformer);
        if (hasTransformer) {
            if (reverseDrawingOrder) {
                i = 2;
            }
            this.mDrawingOrder = i;
            this.mPageTransformerLayerType = pageLayerType;
        } else {
            this.mDrawingOrder = 0;
        }
        if (needsPopulate) {
            populate();
        }
    }

    /* access modifiers changed from: protected */
    public int getChildDrawingOrder(int childCount, int i) {
        return ((LayoutParams) ((View) this.mDrawingOrderedChildren.get(this.mDrawingOrder == 2 ? (childCount - 1) - i : i)).getLayoutParams()).childIndex;
    }

    /* access modifiers changed from: 0000 */
    public OnPageChangeListener setInternalPageChangeListener(OnPageChangeListener listener) {
        OnPageChangeListener oldListener = this.mInternalPageChangeListener;
        this.mInternalPageChangeListener = listener;
        return oldListener;
    }

    public int getOffscreenPageLimit() {
        return this.mOffscreenPageLimit;
    }

    public void setOffscreenPageLimit(int limit) {
        if (limit < 1) {
            StringBuilder sb = new StringBuilder();
            sb.append("Requested offscreen page limit ");
            sb.append(limit);
            sb.append(" too small; defaulting to ");
            sb.append(1);
            Log.w(TAG, sb.toString());
            limit = 1;
        }
        if (limit != this.mOffscreenPageLimit) {
            this.mOffscreenPageLimit = limit;
            populate();
        }
    }

    public void setPageMargin(int marginPixels) {
        int oldMargin = this.mPageMargin;
        this.mPageMargin = marginPixels;
        int width = getWidth();
        recomputeScrollPosition(width, width, marginPixels, oldMargin);
        requestLayout();
    }

    public int getPageMargin() {
        return this.mPageMargin;
    }

    public void setPageMarginDrawable(Drawable d) {
        this.mMarginDrawable = d;
        if (d != null) {
            refreshDrawableState();
        }
        setWillNotDraw(d == null);
        invalidate();
    }

    public void setPageMarginDrawable(int resId) {
        setPageMarginDrawable(ContextCompat.getDrawable(getContext(), resId));
    }

    /* access modifiers changed from: protected */
    public boolean verifyDrawable(Drawable who) {
        return super.verifyDrawable(who) || who == this.mMarginDrawable;
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        super.drawableStateChanged();
        Drawable d = this.mMarginDrawable;
        if (d != null && d.isStateful()) {
            d.setState(getDrawableState());
        }
    }

    /* access modifiers changed from: 0000 */
    public float distanceInfluenceForSnapDuration(float f) {
        return (float) Math.sin((double) ((f - 0.5f) * 0.47123894f));
    }

    /* access modifiers changed from: 0000 */
    public void smoothScrollTo(int x, int y) {
        smoothScrollTo(x, y, 0);
    }

    /* access modifiers changed from: 0000 */
    public void smoothScrollTo(int x, int y, int velocity) {
        int sx;
        int duration;
        if (getChildCount() == 0) {
            setScrollingCacheEnabled(false);
            return;
        }
        Scroller scroller = this.mScroller;
        if (scroller != null && !scroller.isFinished()) {
            sx = this.mIsScrollStarted ? this.mScroller.getCurrX() : this.mScroller.getStartX();
            this.mScroller.abortAnimation();
            setScrollingCacheEnabled(false);
        } else {
            sx = getScrollX();
        }
        int sy = getScrollY();
        int dx = x - sx;
        int dy = y - sy;
        if (dx == 0 && dy == 0) {
            completeScroll(false);
            populate();
            setScrollState(0);
            return;
        }
        setScrollingCacheEnabled(true);
        setScrollState(2);
        int width = getClientWidth();
        int halfWidth = width / 2;
        float distance = ((float) halfWidth) + (((float) halfWidth) * distanceInfluenceForSnapDuration(Math.min(1.0f, (((float) Math.abs(dx)) * 1.0f) / ((float) width))));
        int velocity2 = Math.abs(velocity);
        if (velocity2 > 0) {
            duration = Math.round(Math.abs(distance / ((float) velocity2)) * 1000.0f) * 4;
        } else {
            duration = (int) ((1.0f + (((float) Math.abs(dx)) / (((float) this.mPageMargin) + (((float) width) * this.mAdapter.getPageWidth(this.mCurItem))))) * 100.0f);
        }
        int duration2 = Math.min(duration, MAX_SETTLE_DURATION);
        this.mIsScrollStarted = false;
        int i = velocity2;
        this.mScroller.startScroll(sx, sy, dx, dy, duration2);
        ViewCompat.postInvalidateOnAnimation(this);
    }

    /* access modifiers changed from: 0000 */
    public ItemInfo addNewItem(int position, int index) {
        ItemInfo ii = new ItemInfo();
        ii.position = position;
        ii.object = this.mAdapter.instantiateItem((ViewGroup) this, position);
        ii.widthFactor = this.mAdapter.getPageWidth(position);
        if (index < 0 || index >= this.mItems.size()) {
            this.mItems.add(ii);
        } else {
            this.mItems.add(index, ii);
        }
        return ii;
    }

    /* access modifiers changed from: 0000 */
    public void dataSetChanged() {
        int adapterCount = this.mAdapter.getCount();
        this.mExpectedAdapterCount = adapterCount;
        boolean needPopulate = this.mItems.size() < (this.mOffscreenPageLimit * 2) + 1 && this.mItems.size() < adapterCount;
        int newCurrItem = this.mCurItem;
        boolean isUpdating = false;
        int i = 0;
        while (i < this.mItems.size()) {
            ItemInfo ii = (ItemInfo) this.mItems.get(i);
            int newPos = this.mAdapter.getItemPosition(ii.object);
            if (newPos != -1) {
                if (newPos == -2) {
                    this.mItems.remove(i);
                    i--;
                    if (!isUpdating) {
                        this.mAdapter.startUpdate((ViewGroup) this);
                        isUpdating = true;
                    }
                    this.mAdapter.destroyItem((ViewGroup) this, ii.position, ii.object);
                    needPopulate = true;
                    if (this.mCurItem == ii.position) {
                        newCurrItem = Math.max(0, Math.min(this.mCurItem, adapterCount - 1));
                        needPopulate = true;
                    }
                } else if (ii.position != newPos) {
                    if (ii.position == this.mCurItem) {
                        newCurrItem = newPos;
                    }
                    ii.position = newPos;
                    needPopulate = true;
                }
            }
            i++;
        }
        if (isUpdating) {
            this.mAdapter.finishUpdate((ViewGroup) this);
        }
        Collections.sort(this.mItems, COMPARATOR);
        if (needPopulate) {
            int childCount = getChildCount();
            for (int i2 = 0; i2 < childCount; i2++) {
                LayoutParams lp = (LayoutParams) getChildAt(i2).getLayoutParams();
                if (!lp.isDecor) {
                    lp.widthFactor = 0.0f;
                }
            }
            setCurrentItemInternal(newCurrItem, false, true);
            requestLayout();
        }
    }

    /* access modifiers changed from: 0000 */
    public void populate() {
        populate(this.mCurItem);
    }

    /* access modifiers changed from: 0000 */
    public void populate(int newCurrentItem) {
        ItemInfo oldCurInfo;
        String resName;
        float f;
        float rightWidthNeeded;
        int startPos;
        int pageLimit;
        int i = newCurrentItem;
        int i2 = this.mCurItem;
        if (i2 != i) {
            ItemInfo oldCurInfo2 = infoForPosition(i2);
            this.mCurItem = i;
            oldCurInfo = oldCurInfo2;
        } else {
            oldCurInfo = null;
        }
        if (this.mAdapter == null) {
            sortChildDrawingOrder();
        } else if (this.mPopulatePending) {
            sortChildDrawingOrder();
        } else if (getWindowToken() != null) {
            this.mAdapter.startUpdate((ViewGroup) this);
            int pageLimit2 = this.mOffscreenPageLimit;
            int startPos2 = Math.max(0, this.mCurItem - pageLimit2);
            int N = this.mAdapter.getCount();
            int endPos = Math.min(N - 1, this.mCurItem + pageLimit2);
            if (N == this.mExpectedAdapterCount) {
                ItemInfo curItem = null;
                int curIndex = 0;
                while (true) {
                    if (curIndex >= this.mItems.size()) {
                        break;
                    }
                    ItemInfo ii = (ItemInfo) this.mItems.get(curIndex);
                    if (ii.position < this.mCurItem) {
                        curIndex++;
                    } else if (ii.position == this.mCurItem) {
                        curItem = ii;
                    }
                }
                if (curItem == null && N > 0) {
                    curItem = addNewItem(this.mCurItem, curIndex);
                }
                if (curItem != null) {
                    float extraWidthLeft = 0.0f;
                    int itemIndex = curIndex - 1;
                    ItemInfo ii2 = itemIndex >= 0 ? (ItemInfo) this.mItems.get(itemIndex) : null;
                    int clientWidth = getClientWidth();
                    if (clientWidth <= 0) {
                        f = 0.0f;
                    } else {
                        f = (2.0f - curItem.widthFactor) + (((float) getPaddingLeft()) / ((float) clientWidth));
                    }
                    float leftWidthNeeded = f;
                    int pos = this.mCurItem - 1;
                    while (pos >= 0) {
                        if (extraWidthLeft < leftWidthNeeded || pos >= startPos2) {
                            if (ii2 == null || pos != ii2.position) {
                                extraWidthLeft += addNewItem(pos, itemIndex + 1).widthFactor;
                                curIndex++;
                                ii2 = itemIndex >= 0 ? (ItemInfo) this.mItems.get(itemIndex) : null;
                            } else {
                                extraWidthLeft += ii2.widthFactor;
                                itemIndex--;
                                ii2 = itemIndex >= 0 ? (ItemInfo) this.mItems.get(itemIndex) : null;
                            }
                        } else if (ii2 == null) {
                            break;
                        } else if (pos == ii2.position && !ii2.scrolling) {
                            this.mItems.remove(itemIndex);
                            this.mAdapter.destroyItem((ViewGroup) this, pos, ii2.object);
                            itemIndex--;
                            curIndex--;
                            ii2 = itemIndex >= 0 ? (ItemInfo) this.mItems.get(itemIndex) : null;
                        }
                        pos--;
                        int i3 = newCurrentItem;
                    }
                    float extraWidthRight = curItem.widthFactor;
                    int itemIndex2 = curIndex + 1;
                    if (extraWidthRight < 2.0f) {
                        ItemInfo ii3 = itemIndex2 < this.mItems.size() ? (ItemInfo) this.mItems.get(itemIndex2) : null;
                        if (clientWidth <= 0) {
                            rightWidthNeeded = 0.0f;
                        } else {
                            rightWidthNeeded = (((float) getPaddingRight()) / ((float) clientWidth)) + 2.0f;
                        }
                        int pos2 = this.mCurItem + 1;
                        while (true) {
                            if (pos2 >= N) {
                                int i4 = startPos2;
                                break;
                            }
                            if (extraWidthRight < rightWidthNeeded || pos2 <= endPos) {
                                pageLimit = pageLimit2;
                                startPos = startPos2;
                                if (ii3 == null || pos2 != ii3.position) {
                                    ItemInfo ii4 = addNewItem(pos2, itemIndex2);
                                    itemIndex2++;
                                    extraWidthRight += ii4.widthFactor;
                                    ii3 = itemIndex2 < this.mItems.size() ? (ItemInfo) this.mItems.get(itemIndex2) : null;
                                } else {
                                    extraWidthRight += ii3.widthFactor;
                                    itemIndex2++;
                                    ii3 = itemIndex2 < this.mItems.size() ? (ItemInfo) this.mItems.get(itemIndex2) : null;
                                }
                            } else if (ii3 == null) {
                                int i5 = pageLimit2;
                                int i6 = startPos2;
                                break;
                            } else {
                                pageLimit = pageLimit2;
                                if (pos2 != ii3.position || ii3.scrolling) {
                                    startPos = startPos2;
                                } else {
                                    this.mItems.remove(itemIndex2);
                                    startPos = startPos2;
                                    this.mAdapter.destroyItem((ViewGroup) this, pos2, ii3.object);
                                    ii3 = itemIndex2 < this.mItems.size() ? (ItemInfo) this.mItems.get(itemIndex2) : null;
                                }
                            }
                            pos2++;
                            pageLimit2 = pageLimit;
                            startPos2 = startPos;
                        }
                        ItemInfo itemInfo = ii3;
                    } else {
                        int i7 = startPos2;
                    }
                    calculatePageOffsets(curItem, curIndex, oldCurInfo);
                    this.mAdapter.setPrimaryItem((ViewGroup) this, this.mCurItem, curItem.object);
                } else {
                    int i8 = startPos2;
                }
                this.mAdapter.finishUpdate((ViewGroup) this);
                int childCount = getChildCount();
                for (int i9 = 0; i9 < childCount; i9++) {
                    View child = getChildAt(i9);
                    LayoutParams lp = (LayoutParams) child.getLayoutParams();
                    lp.childIndex = i9;
                    if (!lp.isDecor) {
                        if (lp.widthFactor == 0.0f) {
                            ItemInfo ii5 = infoForChild(child);
                            if (ii5 != null) {
                                lp.widthFactor = ii5.widthFactor;
                                lp.position = ii5.position;
                            }
                        }
                    }
                }
                sortChildDrawingOrder();
                if (hasFocus()) {
                    View currentFocused = findFocus();
                    ItemInfo ii6 = currentFocused != null ? infoForAnyChild(currentFocused) : null;
                    if (ii6 == null || ii6.position != this.mCurItem) {
                        for (int i10 = 0; i10 < getChildCount(); i10++) {
                            View child2 = getChildAt(i10);
                            ItemInfo ii7 = infoForChild(child2);
                            if (ii7 != null && ii7.position == this.mCurItem && child2.requestFocus(2)) {
                                break;
                            }
                        }
                    }
                }
                return;
            }
            int i11 = startPos2;
            try {
                resName = getResources().getResourceName(getId());
            } catch (NotFoundException e) {
                resName = Integer.toHexString(getId());
            }
            StringBuilder sb = new StringBuilder();
            sb.append("The application's PagerAdapter changed the adapter's contents without calling PagerAdapter#notifyDataSetChanged! Expected adapter item count: ");
            sb.append(this.mExpectedAdapterCount);
            sb.append(", found: ");
            sb.append(N);
            sb.append(" Pager id: ");
            sb.append(resName);
            sb.append(" Pager class: ");
            sb.append(getClass());
            sb.append(" Problematic adapter: ");
            sb.append(this.mAdapter.getClass());
            throw new IllegalStateException(sb.toString());
        }
    }

    private void sortChildDrawingOrder() {
        if (this.mDrawingOrder != 0) {
            ArrayList<View> arrayList = this.mDrawingOrderedChildren;
            if (arrayList == null) {
                this.mDrawingOrderedChildren = new ArrayList<>();
            } else {
                arrayList.clear();
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                this.mDrawingOrderedChildren.add(getChildAt(i));
            }
            Collections.sort(this.mDrawingOrderedChildren, sPositionComparator);
        }
    }

    private void calculatePageOffsets(ItemInfo curItem, int curIndex, ItemInfo oldCurInfo) {
        ItemInfo ii;
        ItemInfo ii2;
        int N = this.mAdapter.getCount();
        int width = getClientWidth();
        float marginOffset = width > 0 ? ((float) this.mPageMargin) / ((float) width) : 0.0f;
        if (oldCurInfo != null) {
            int oldCurPosition = oldCurInfo.position;
            if (oldCurPosition < curItem.position) {
                int itemIndex = 0;
                float offset = oldCurInfo.offset + oldCurInfo.widthFactor + marginOffset;
                int pos = oldCurPosition + 1;
                while (pos <= curItem.position && itemIndex < this.mItems.size()) {
                    Object obj = this.mItems.get(itemIndex);
                    while (true) {
                        ii2 = (ItemInfo) obj;
                        if (pos > ii2.position && itemIndex < this.mItems.size() - 1) {
                            itemIndex++;
                            obj = this.mItems.get(itemIndex);
                        }
                    }
                    while (pos < ii2.position) {
                        offset += this.mAdapter.getPageWidth(pos) + marginOffset;
                        pos++;
                    }
                    ii2.offset = offset;
                    offset += ii2.widthFactor + marginOffset;
                    pos++;
                }
            } else if (oldCurPosition > curItem.position) {
                int itemIndex2 = this.mItems.size() - 1;
                float offset2 = oldCurInfo.offset;
                int pos2 = oldCurPosition - 1;
                while (pos2 >= curItem.position && itemIndex2 >= 0) {
                    Object obj2 = this.mItems.get(itemIndex2);
                    while (true) {
                        ii = (ItemInfo) obj2;
                        if (pos2 < ii.position && itemIndex2 > 0) {
                            itemIndex2--;
                            obj2 = this.mItems.get(itemIndex2);
                        }
                    }
                    while (pos2 > ii.position) {
                        offset2 -= this.mAdapter.getPageWidth(pos2) + marginOffset;
                        pos2--;
                    }
                    offset2 -= ii.widthFactor + marginOffset;
                    ii.offset = offset2;
                    pos2--;
                }
            }
        }
        int itemCount = this.mItems.size();
        float offset3 = curItem.offset;
        int pos3 = curItem.position - 1;
        this.mFirstOffset = curItem.position == 0 ? curItem.offset : -3.4028235E38f;
        this.mLastOffset = curItem.position == N + -1 ? (curItem.offset + curItem.widthFactor) - 1.0f : Float.MAX_VALUE;
        int i = curIndex - 1;
        while (i >= 0) {
            ItemInfo ii3 = (ItemInfo) this.mItems.get(i);
            while (pos3 > ii3.position) {
                offset3 -= this.mAdapter.getPageWidth(pos3) + marginOffset;
                pos3--;
            }
            offset3 -= ii3.widthFactor + marginOffset;
            ii3.offset = offset3;
            if (ii3.position == 0) {
                this.mFirstOffset = offset3;
            }
            i--;
            pos3--;
        }
        float offset4 = curItem.offset + curItem.widthFactor + marginOffset;
        int pos4 = curItem.position + 1;
        int i2 = curIndex + 1;
        while (i2 < itemCount) {
            ItemInfo ii4 = (ItemInfo) this.mItems.get(i2);
            while (pos4 < ii4.position) {
                offset4 += this.mAdapter.getPageWidth(pos4) + marginOffset;
                pos4++;
            }
            if (ii4.position == N - 1) {
                this.mLastOffset = (ii4.widthFactor + offset4) - 1.0f;
            }
            ii4.offset = offset4;
            offset4 += ii4.widthFactor + marginOffset;
            i2++;
            pos4++;
        }
        this.mNeedCalculatePageOffsets = false;
    }

    public Parcelable onSaveInstanceState() {
        SavedState ss = new SavedState(super.onSaveInstanceState());
        ss.position = this.mCurItem;
        PagerAdapter pagerAdapter = this.mAdapter;
        if (pagerAdapter != null) {
            ss.adapterState = pagerAdapter.saveState();
        }
        return ss;
    }

    public void onRestoreInstanceState(Parcelable state) {
        if (!(state instanceof SavedState)) {
            super.onRestoreInstanceState(state);
            return;
        }
        SavedState ss = (SavedState) state;
        super.onRestoreInstanceState(ss.getSuperState());
        PagerAdapter pagerAdapter = this.mAdapter;
        if (pagerAdapter != null) {
            pagerAdapter.restoreState(ss.adapterState, ss.loader);
            setCurrentItemInternal(ss.position, false, true);
        } else {
            this.mRestoredCurItem = ss.position;
            this.mRestoredAdapterState = ss.adapterState;
            this.mRestoredClassLoader = ss.loader;
        }
    }

    public void addView(View child, int index, android.view.ViewGroup.LayoutParams params) {
        if (!checkLayoutParams(params)) {
            params = generateLayoutParams(params);
        }
        LayoutParams lp = (LayoutParams) params;
        lp.isDecor |= isDecorView(child);
        if (!this.mInLayout) {
            super.addView(child, index, params);
        } else if (lp == null || !lp.isDecor) {
            lp.needsMeasure = true;
            addViewInLayout(child, index, params);
        } else {
            throw new IllegalStateException("Cannot add pager decor view during layout");
        }
    }

    private static boolean isDecorView(View view) {
        return view.getClass().getAnnotation(DecorView.class) != null;
    }

    public void removeView(View view) {
        if (this.mInLayout) {
            removeViewInLayout(view);
        } else {
            super.removeView(view);
        }
    }

    /* access modifiers changed from: 0000 */
    public ItemInfo infoForChild(View child) {
        for (int i = 0; i < this.mItems.size(); i++) {
            ItemInfo ii = (ItemInfo) this.mItems.get(i);
            if (this.mAdapter.isViewFromObject(child, ii.object)) {
                return ii;
            }
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public ItemInfo infoForAnyChild(View child) {
        while (true) {
            ViewParent parent = child.getParent();
            ViewParent parent2 = parent;
            if (parent == this) {
                return infoForChild(child);
            }
            if (parent2 != null && (parent2 instanceof View)) {
                child = (View) parent2;
            }
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public ItemInfo infoForPosition(int position) {
        for (int i = 0; i < this.mItems.size(); i++) {
            ItemInfo ii = (ItemInfo) this.mItems.get(i);
            if (ii.position == position) {
                return ii;
            }
        }
        return null;
    }

    /* access modifiers changed from: protected */
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.mFirstLayout = true;
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int measuredWidth;
        int heightMode;
        int widthSize;
        int heightSize;
        int heightMode2;
        setMeasuredDimension(getDefaultSize(0, widthMeasureSpec), getDefaultSize(0, heightMeasureSpec));
        int measuredWidth2 = getMeasuredWidth();
        int maxGutterSize = measuredWidth2 / 10;
        this.mGutterSize = Math.min(maxGutterSize, this.mDefaultGutterSize);
        int childWidthSize = (measuredWidth2 - getPaddingLeft()) - getPaddingRight();
        int childHeightSize = (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom();
        int size = getChildCount();
        int i = 0;
        while (i < size) {
            View child = getChildAt(i);
            if (child.getVisibility() != 8) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp == null || !lp.isDecor) {
                    measuredWidth = measuredWidth2;
                    heightMode = maxGutterSize;
                } else {
                    int hgrav = lp.gravity & 7;
                    int vgrav = lp.gravity & 112;
                    int widthMode = Integer.MIN_VALUE;
                    int heightMode3 = Integer.MIN_VALUE;
                    boolean consumeVertical = vgrav == 48 || vgrav == 80;
                    boolean consumeHorizontal = hgrav == 3 || hgrav == 5;
                    if (consumeVertical) {
                        widthMode = 1073741824;
                    } else if (consumeHorizontal) {
                        heightMode3 = 1073741824;
                    }
                    int widthSize2 = childWidthSize;
                    int heightSize2 = childHeightSize;
                    measuredWidth = measuredWidth2;
                    if (lp.width != -2) {
                        widthMode = 1073741824;
                        if (lp.width != -1) {
                            widthSize = lp.width;
                        } else {
                            widthSize = widthSize2;
                        }
                    } else {
                        widthSize = widthSize2;
                    }
                    if (lp.height == -2) {
                        heightMode2 = heightMode3;
                        heightSize = heightSize2;
                    } else if (lp.height != -1) {
                        heightSize = lp.height;
                        heightMode2 = 1073741824;
                    } else {
                        heightMode2 = 1073741824;
                        heightSize = heightSize2;
                    }
                    heightMode = maxGutterSize;
                    int i2 = widthSize;
                    child.measure(MeasureSpec.makeMeasureSpec(widthSize, widthMode), MeasureSpec.makeMeasureSpec(heightSize, heightMode2));
                    if (consumeVertical) {
                        childHeightSize -= child.getMeasuredHeight();
                    } else if (consumeHorizontal) {
                        childWidthSize -= child.getMeasuredWidth();
                    }
                }
            } else {
                measuredWidth = measuredWidth2;
                heightMode = maxGutterSize;
            }
            i++;
            int i3 = widthMeasureSpec;
            int i4 = heightMeasureSpec;
            maxGutterSize = heightMode;
            measuredWidth2 = measuredWidth;
        }
        int i5 = maxGutterSize;
        this.mChildWidthMeasureSpec = MeasureSpec.makeMeasureSpec(childWidthSize, 1073741824);
        this.mChildHeightMeasureSpec = MeasureSpec.makeMeasureSpec(childHeightSize, 1073741824);
        this.mInLayout = true;
        populate();
        this.mInLayout = false;
        int size2 = getChildCount();
        for (int i6 = 0; i6 < size2; i6++) {
            View child2 = getChildAt(i6);
            if (child2.getVisibility() != 8) {
                LayoutParams lp2 = (LayoutParams) child2.getLayoutParams();
                if (lp2 == null || !lp2.isDecor) {
                    child2.measure(MeasureSpec.makeMeasureSpec((int) (((float) childWidthSize) * lp2.widthFactor), 1073741824), this.mChildHeightMeasureSpec);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (w != oldw) {
            int i = this.mPageMargin;
            recomputeScrollPosition(w, oldw, i, i);
        }
    }

    private void recomputeScrollPosition(int width, int oldWidth, int margin, int oldMargin) {
        if (oldWidth <= 0 || this.mItems.isEmpty()) {
            ItemInfo ii = infoForPosition(this.mCurItem);
            int scrollPos = (int) (((float) ((width - getPaddingLeft()) - getPaddingRight())) * (ii != null ? Math.min(ii.offset, this.mLastOffset) : 0.0f));
            if (scrollPos != getScrollX()) {
                completeScroll(false);
                scrollTo(scrollPos, getScrollY());
            }
        } else if (!this.mScroller.isFinished()) {
            this.mScroller.setFinalX(getCurrentItem() * getClientWidth());
        } else {
            scrollTo((int) (((float) (((width - getPaddingLeft()) - getPaddingRight()) + margin)) * (((float) getScrollX()) / ((float) (((oldWidth - getPaddingLeft()) - getPaddingRight()) + oldMargin)))), getScrollY());
        }
    }

    /* access modifiers changed from: protected */
    public void onLayout(boolean changed, int l, int t, int r, int b) {
        int i;
        boolean z;
        int paddingLeft;
        int width;
        int count;
        int childLeft;
        int childTop;
        int count2 = getChildCount();
        int width2 = r - l;
        int height = b - t;
        int paddingLeft2 = getPaddingLeft();
        int paddingTop = getPaddingTop();
        int paddingRight = getPaddingRight();
        int paddingBottom = getPaddingBottom();
        int scrollX = getScrollX();
        int decorCount = 0;
        int i2 = 0;
        while (true) {
            i = 8;
            if (i2 >= count2) {
                break;
            }
            View child = getChildAt(i2);
            if (child.getVisibility() != 8) {
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp.isDecor) {
                    int hgrav = lp.gravity & 7;
                    int vgrav = lp.gravity & 112;
                    LayoutParams layoutParams = lp;
                    if (hgrav == 1) {
                        childLeft = Math.max((width2 - child.getMeasuredWidth()) / 2, paddingLeft2);
                    } else if (hgrav == 3) {
                        childLeft = paddingLeft2;
                        paddingLeft2 += child.getMeasuredWidth();
                    } else if (hgrav != 5) {
                        childLeft = paddingLeft2;
                    } else {
                        childLeft = (width2 - paddingRight) - child.getMeasuredWidth();
                        paddingRight += child.getMeasuredWidth();
                    }
                    int paddingLeft3 = paddingLeft2;
                    if (vgrav == 16) {
                        childTop = Math.max((height - child.getMeasuredHeight()) / 2, paddingTop);
                    } else if (vgrav == 48) {
                        childTop = paddingTop;
                        paddingTop += child.getMeasuredHeight();
                    } else if (vgrav != 80) {
                        childTop = paddingTop;
                    } else {
                        childTop = (height - paddingBottom) - child.getMeasuredHeight();
                        paddingBottom += child.getMeasuredHeight();
                    }
                    int childLeft2 = childLeft + scrollX;
                    int paddingTop2 = paddingTop;
                    child.layout(childLeft2, childTop, child.getMeasuredWidth() + childLeft2, childTop + child.getMeasuredHeight());
                    decorCount++;
                    paddingLeft2 = paddingLeft3;
                    paddingTop = paddingTop2;
                }
            }
            i2++;
        }
        int childWidth = (width2 - paddingLeft2) - paddingRight;
        int i3 = 0;
        while (i3 < count2) {
            View child2 = getChildAt(i3);
            if (child2.getVisibility() != i) {
                LayoutParams lp2 = (LayoutParams) child2.getLayoutParams();
                if (!lp2.isDecor) {
                    ItemInfo infoForChild = infoForChild(child2);
                    ItemInfo ii = infoForChild;
                    if (infoForChild != null) {
                        ItemInfo ii2 = ii;
                        count = count2;
                        int loff = (int) (((float) childWidth) * ii2.offset);
                        int childLeft3 = paddingLeft2 + loff;
                        int childTop2 = paddingTop;
                        int i4 = loff;
                        if (lp2.needsMeasure != 0) {
                            lp2.needsMeasure = false;
                            width = width2;
                            paddingLeft = paddingLeft2;
                            child2.measure(MeasureSpec.makeMeasureSpec((int) (((float) childWidth) * lp2.widthFactor), 1073741824), MeasureSpec.makeMeasureSpec((height - paddingTop) - paddingBottom, 1073741824));
                        } else {
                            width = width2;
                            paddingLeft = paddingLeft2;
                        }
                        int childTop3 = childTop2;
                        child2.layout(childLeft3, childTop3, child2.getMeasuredWidth() + childLeft3, child2.getMeasuredHeight() + childTop3);
                    } else {
                        width = width2;
                        paddingLeft = paddingLeft2;
                        ItemInfo itemInfo = ii;
                        count = count2;
                    }
                } else {
                    count = count2;
                    width = width2;
                    paddingLeft = paddingLeft2;
                }
            } else {
                count = count2;
                width = width2;
                paddingLeft = paddingLeft2;
            }
            i3++;
            count2 = count;
            width2 = width;
            paddingLeft2 = paddingLeft;
            i = 8;
        }
        int i5 = width2;
        int i6 = paddingLeft2;
        this.mTopPageBounds = paddingTop;
        this.mBottomPageBounds = height - paddingBottom;
        this.mDecorChildCount = decorCount;
        if (this.mFirstLayout) {
            z = false;
            scrollToItem(this.mCurItem, false, 0, false);
        } else {
            z = false;
        }
        this.mFirstLayout = z;
    }

    public void computeScroll() {
        this.mIsScrollStarted = true;
        if (this.mScroller.isFinished() || !this.mScroller.computeScrollOffset()) {
            completeScroll(true);
            return;
        }
        int oldX = getScrollX();
        int oldY = getScrollY();
        int x = this.mScroller.getCurrX();
        int y = this.mScroller.getCurrY();
        if (!(oldX == x && oldY == y)) {
            scrollTo(x, y);
            if (!pageScrolled(x)) {
                this.mScroller.abortAnimation();
                scrollTo(0, y);
            }
        }
        ViewCompat.postInvalidateOnAnimation(this);
    }

    private boolean pageScrolled(int xpos) {
        String str = "onPageScrolled did not call superclass implementation";
        if (this.mItems.size() != 0) {
            ItemInfo ii = infoForCurrentScrollPosition();
            int width = getClientWidth();
            int i = this.mPageMargin;
            int widthWithMargin = width + i;
            float marginOffset = ((float) i) / ((float) width);
            int currentPage = ii.position;
            float pageOffset = ((((float) xpos) / ((float) width)) - ii.offset) / (ii.widthFactor + marginOffset);
            int offsetPixels = (int) (((float) widthWithMargin) * pageOffset);
            this.mCalledSuper = false;
            onPageScrolled(currentPage, pageOffset, offsetPixels);
            if (this.mCalledSuper) {
                return true;
            }
            throw new IllegalStateException(str);
        } else if (this.mFirstLayout) {
            return false;
        } else {
            this.mCalledSuper = false;
            onPageScrolled(0, 0.0f, 0);
            if (this.mCalledSuper) {
                return false;
            }
            throw new IllegalStateException(str);
        }
    }

    /* access modifiers changed from: protected */
    public void onPageScrolled(int position, float offset, int offsetPixels) {
        int childLeft;
        if (this.mDecorChildCount > 0) {
            int scrollX = getScrollX();
            int paddingLeft = getPaddingLeft();
            int paddingRight = getPaddingRight();
            int width = getWidth();
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                View child = getChildAt(i);
                LayoutParams lp = (LayoutParams) child.getLayoutParams();
                if (lp.isDecor) {
                    int hgrav = lp.gravity & 7;
                    if (hgrav == 1) {
                        childLeft = Math.max((width - child.getMeasuredWidth()) / 2, paddingLeft);
                    } else if (hgrav == 3) {
                        childLeft = paddingLeft;
                        paddingLeft += child.getWidth();
                    } else if (hgrav != 5) {
                        childLeft = paddingLeft;
                    } else {
                        childLeft = (width - paddingRight) - child.getMeasuredWidth();
                        paddingRight += child.getMeasuredWidth();
                    }
                    int childOffset = (childLeft + scrollX) - child.getLeft();
                    if (childOffset != 0) {
                        child.offsetLeftAndRight(childOffset);
                    }
                }
            }
        }
        dispatchOnPageScrolled(position, offset, offsetPixels);
        if (this.mPageTransformer != null) {
            int scrollX2 = getScrollX();
            int childCount2 = getChildCount();
            for (int i2 = 0; i2 < childCount2; i2++) {
                View child2 = getChildAt(i2);
                if (!((LayoutParams) child2.getLayoutParams()).isDecor) {
                    this.mPageTransformer.transformPage(child2, ((float) (child2.getLeft() - scrollX2)) / ((float) getClientWidth()));
                }
            }
        }
        this.mCalledSuper = true;
    }

    private void dispatchOnPageScrolled(int position, float offset, int offsetPixels) {
        OnPageChangeListener onPageChangeListener = this.mOnPageChangeListener;
        if (onPageChangeListener != null) {
            onPageChangeListener.onPageScrolled(position, offset, offsetPixels);
        }
        List<OnPageChangeListener> list = this.mOnPageChangeListeners;
        if (list != null) {
            int z = list.size();
            for (int i = 0; i < z; i++) {
                OnPageChangeListener listener = (OnPageChangeListener) this.mOnPageChangeListeners.get(i);
                if (listener != null) {
                    listener.onPageScrolled(position, offset, offsetPixels);
                }
            }
        }
        OnPageChangeListener onPageChangeListener2 = this.mInternalPageChangeListener;
        if (onPageChangeListener2 != null) {
            onPageChangeListener2.onPageScrolled(position, offset, offsetPixels);
        }
    }

    private void dispatchOnPageSelected(int position) {
        OnPageChangeListener onPageChangeListener = this.mOnPageChangeListener;
        if (onPageChangeListener != null) {
            onPageChangeListener.onPageSelected(position);
        }
        List<OnPageChangeListener> list = this.mOnPageChangeListeners;
        if (list != null) {
            int z = list.size();
            for (int i = 0; i < z; i++) {
                OnPageChangeListener listener = (OnPageChangeListener) this.mOnPageChangeListeners.get(i);
                if (listener != null) {
                    listener.onPageSelected(position);
                }
            }
        }
        OnPageChangeListener onPageChangeListener2 = this.mInternalPageChangeListener;
        if (onPageChangeListener2 != null) {
            onPageChangeListener2.onPageSelected(position);
        }
    }

    private void dispatchOnScrollStateChanged(int state) {
        OnPageChangeListener onPageChangeListener = this.mOnPageChangeListener;
        if (onPageChangeListener != null) {
            onPageChangeListener.onPageScrollStateChanged(state);
        }
        List<OnPageChangeListener> list = this.mOnPageChangeListeners;
        if (list != null) {
            int z = list.size();
            for (int i = 0; i < z; i++) {
                OnPageChangeListener listener = (OnPageChangeListener) this.mOnPageChangeListeners.get(i);
                if (listener != null) {
                    listener.onPageScrollStateChanged(state);
                }
            }
        }
        OnPageChangeListener onPageChangeListener2 = this.mInternalPageChangeListener;
        if (onPageChangeListener2 != null) {
            onPageChangeListener2.onPageScrollStateChanged(state);
        }
    }

    private void completeScroll(boolean postEvents) {
        boolean needPopulate = this.mScrollState == 2;
        if (needPopulate) {
            setScrollingCacheEnabled(false);
            if (true ^ this.mScroller.isFinished()) {
                this.mScroller.abortAnimation();
                int oldX = getScrollX();
                int oldY = getScrollY();
                int x = this.mScroller.getCurrX();
                int y = this.mScroller.getCurrY();
                if (!(oldX == x && oldY == y)) {
                    scrollTo(x, y);
                    if (x != oldX) {
                        pageScrolled(x);
                    }
                }
            }
        }
        this.mPopulatePending = false;
        for (int i = 0; i < this.mItems.size(); i++) {
            ItemInfo ii = (ItemInfo) this.mItems.get(i);
            if (ii.scrolling) {
                needPopulate = true;
                ii.scrolling = false;
            }
        }
        if (!needPopulate) {
            return;
        }
        if (postEvents) {
            ViewCompat.postOnAnimation(this, this.mEndScrollRunnable);
        } else {
            this.mEndScrollRunnable.run();
        }
    }

    private boolean isGutterDrag(float x, float dx) {
        return (x < ((float) this.mGutterSize) && dx > 0.0f) || (x > ((float) (getWidth() - this.mGutterSize)) && dx < 0.0f);
    }

    private void enableLayers(boolean enable) {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            getChildAt(i).setLayerType(enable ? this.mPageTransformerLayerType : 0, null);
        }
    }

    public boolean onInterceptTouchEvent(MotionEvent ev) {
        float y;
        MotionEvent motionEvent = ev;
        int action = ev.getAction() & 255;
        if (action == 3 || action == 1) {
            resetTouch();
            return false;
        }
        if (action != 0) {
            if (this.mIsBeingDragged) {
                return true;
            }
            if (this.mIsUnableToDrag) {
                return false;
            }
        }
        if (action == 0) {
            float x = ev.getX();
            this.mInitialMotionX = x;
            this.mLastMotionX = x;
            float y2 = ev.getY();
            this.mInitialMotionY = y2;
            this.mLastMotionY = y2;
            this.mActivePointerId = motionEvent.getPointerId(0);
            this.mIsUnableToDrag = false;
            this.mIsScrollStarted = true;
            this.mScroller.computeScrollOffset();
            if (this.mScrollState != 2 || Math.abs(this.mScroller.getFinalX() - this.mScroller.getCurrX()) <= this.mCloseEnough) {
                completeScroll(false);
                this.mIsBeingDragged = false;
            } else {
                this.mScroller.abortAnimation();
                this.mPopulatePending = false;
                populate();
                this.mIsBeingDragged = true;
                requestParentDisallowInterceptTouchEvent(true);
                setScrollState(1);
            }
        } else if (action == 2) {
            int activePointerId = this.mActivePointerId;
            if (activePointerId != -1) {
                int pointerIndex = motionEvent.findPointerIndex(activePointerId);
                float x2 = motionEvent.getX(pointerIndex);
                float dx = x2 - this.mLastMotionX;
                float xDiff = Math.abs(dx);
                float y3 = motionEvent.getY(pointerIndex);
                float yDiff = Math.abs(y3 - this.mInitialMotionY);
                if (dx == 0.0f || isGutterDrag(this.mLastMotionX, dx)) {
                    y = y3;
                } else {
                    y = y3;
                    if (canScroll(this, false, (int) dx, (int) x2, (int) y3)) {
                        this.mLastMotionX = x2;
                        this.mLastMotionY = y;
                        this.mIsUnableToDrag = true;
                        return false;
                    }
                }
                if (xDiff > ((float) this.mTouchSlop) && 0.5f * xDiff > yDiff) {
                    this.mIsBeingDragged = true;
                    requestParentDisallowInterceptTouchEvent(true);
                    setScrollState(1);
                    this.mLastMotionX = dx > 0.0f ? this.mInitialMotionX + ((float) this.mTouchSlop) : this.mInitialMotionX - ((float) this.mTouchSlop);
                    this.mLastMotionY = y;
                    setScrollingCacheEnabled(true);
                } else if (yDiff > ((float) this.mTouchSlop)) {
                    this.mIsUnableToDrag = true;
                }
                if (this.mIsBeingDragged && performDrag(x2)) {
                    ViewCompat.postInvalidateOnAnimation(this);
                }
            }
        } else if (action == 6) {
            onSecondaryPointerUp(ev);
        }
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        }
        this.mVelocityTracker.addMovement(motionEvent);
        return this.mIsBeingDragged;
    }

    public boolean onTouchEvent(MotionEvent ev) {
        MotionEvent motionEvent = ev;
        if (this.mFakeDragging) {
            return true;
        }
        if (ev.getAction() == 0 && ev.getEdgeFlags() != 0) {
            return false;
        }
        PagerAdapter pagerAdapter = this.mAdapter;
        if (pagerAdapter == null || pagerAdapter.getCount() == 0) {
            return false;
        }
        if (this.mVelocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        }
        this.mVelocityTracker.addMovement(motionEvent);
        int action = ev.getAction();
        boolean needsInvalidate = false;
        int i = action & 255;
        if (i == 0) {
            this.mScroller.abortAnimation();
            this.mPopulatePending = false;
            populate();
            float x = ev.getX();
            this.mInitialMotionX = x;
            this.mLastMotionX = x;
            float y = ev.getY();
            this.mInitialMotionY = y;
            this.mLastMotionY = y;
            this.mActivePointerId = motionEvent.getPointerId(0);
        } else if (i != 1) {
            if (i == 2) {
                if (!this.mIsBeingDragged) {
                    int pointerIndex = motionEvent.findPointerIndex(this.mActivePointerId);
                    if (pointerIndex == -1) {
                        needsInvalidate = resetTouch();
                        int i2 = action;
                    } else {
                        float x2 = motionEvent.getX(pointerIndex);
                        float xDiff = Math.abs(x2 - this.mLastMotionX);
                        float y2 = motionEvent.getY(pointerIndex);
                        float yDiff = Math.abs(y2 - this.mLastMotionY);
                        if (xDiff > ((float) this.mTouchSlop) && xDiff > yDiff) {
                            this.mIsBeingDragged = true;
                            requestParentDisallowInterceptTouchEvent(true);
                            float f = this.mInitialMotionX;
                            this.mLastMotionX = x2 - f > 0.0f ? f + ((float) this.mTouchSlop) : f - ((float) this.mTouchSlop);
                            this.mLastMotionY = y2;
                            setScrollState(1);
                            setScrollingCacheEnabled(true);
                            ViewParent parent = getParent();
                            if (parent != null) {
                                parent.requestDisallowInterceptTouchEvent(true);
                            }
                        }
                    }
                }
                if (this.mIsBeingDragged != 0) {
                    needsInvalidate = false | performDrag(motionEvent.getX(motionEvent.findPointerIndex(this.mActivePointerId)));
                    int i3 = action;
                } else {
                    int i4 = action;
                }
            } else if (i != 3) {
                if (i == 5) {
                    int index = ev.getActionIndex();
                    this.mLastMotionX = motionEvent.getX(index);
                    this.mActivePointerId = motionEvent.getPointerId(index);
                    int i5 = action;
                } else if (i != 6) {
                    int i6 = action;
                } else {
                    onSecondaryPointerUp(ev);
                    this.mLastMotionX = motionEvent.getX(motionEvent.findPointerIndex(this.mActivePointerId));
                    int i7 = action;
                }
            } else if (this.mIsBeingDragged) {
                scrollToItem(this.mCurItem, true, 0, false);
                needsInvalidate = resetTouch();
                int i8 = action;
            } else {
                int i9 = action;
            }
        } else if (this.mIsBeingDragged) {
            VelocityTracker velocityTracker = this.mVelocityTracker;
            velocityTracker.computeCurrentVelocity(1000, (float) this.mMaximumVelocity);
            int initialVelocity = (int) velocityTracker.getXVelocity(this.mActivePointerId);
            this.mPopulatePending = true;
            int width = getClientWidth();
            int scrollX = getScrollX();
            ItemInfo ii = infoForCurrentScrollPosition();
            int i10 = action;
            setCurrentItemInternal(determineTargetPage(ii.position, ((((float) scrollX) / ((float) width)) - ii.offset) / (ii.widthFactor + (((float) this.mPageMargin) / ((float) width))), initialVelocity, (int) (motionEvent.getX(motionEvent.findPointerIndex(this.mActivePointerId)) - this.mInitialMotionX)), true, true, initialVelocity);
            needsInvalidate = resetTouch();
        }
        if (needsInvalidate) {
            ViewCompat.postInvalidateOnAnimation(this);
        }
        return true;
    }

    private boolean resetTouch() {
        this.mActivePointerId = -1;
        endDrag();
        this.mLeftEdge.onRelease();
        this.mRightEdge.onRelease();
        return this.mLeftEdge.isFinished() || this.mRightEdge.isFinished();
    }

    private void requestParentDisallowInterceptTouchEvent(boolean disallowIntercept) {
        ViewParent parent = getParent();
        if (parent != null) {
            parent.requestDisallowInterceptTouchEvent(disallowIntercept);
        }
    }

    private boolean performDrag(float x) {
        float f = x;
        boolean needsInvalidate = false;
        float deltaX = this.mLastMotionX - f;
        this.mLastMotionX = f;
        float scrollX = ((float) getScrollX()) + deltaX;
        int width = getClientWidth();
        float leftBound = ((float) width) * this.mFirstOffset;
        float rightBound = ((float) width) * this.mLastOffset;
        boolean leftAbsolute = true;
        boolean rightAbsolute = true;
        ItemInfo firstItem = (ItemInfo) this.mItems.get(0);
        ArrayList<ItemInfo> arrayList = this.mItems;
        ItemInfo lastItem = (ItemInfo) arrayList.get(arrayList.size() - 1);
        if (firstItem.position != 0) {
            leftAbsolute = false;
            leftBound = firstItem.offset * ((float) width);
        }
        if (lastItem.position != this.mAdapter.getCount() - 1) {
            rightAbsolute = false;
            rightBound = lastItem.offset * ((float) width);
        }
        if (scrollX < leftBound) {
            if (leftAbsolute) {
                this.mLeftEdge.onPull(Math.abs(leftBound - scrollX) / ((float) width));
                needsInvalidate = true;
            }
            scrollX = leftBound;
        } else if (scrollX > rightBound) {
            if (rightAbsolute) {
                this.mRightEdge.onPull(Math.abs(scrollX - rightBound) / ((float) width));
                needsInvalidate = true;
            }
            scrollX = rightBound;
        }
        this.mLastMotionX += scrollX - ((float) ((int) scrollX));
        scrollTo((int) scrollX, getScrollY());
        pageScrolled((int) scrollX);
        return needsInvalidate;
    }

    private ItemInfo infoForCurrentScrollPosition() {
        int width = getClientWidth();
        float marginOffset = 0.0f;
        float scrollOffset = width > 0 ? ((float) getScrollX()) / ((float) width) : 0.0f;
        if (width > 0) {
            marginOffset = ((float) this.mPageMargin) / ((float) width);
        }
        int lastPos = -1;
        float lastOffset = 0.0f;
        float lastWidth = 0.0f;
        boolean first = true;
        ItemInfo lastItem = null;
        int i = 0;
        while (i < this.mItems.size()) {
            ItemInfo ii = (ItemInfo) this.mItems.get(i);
            if (!first && ii.position != lastPos + 1) {
                ii = this.mTempItem;
                ii.offset = lastOffset + lastWidth + marginOffset;
                ii.position = lastPos + 1;
                ii.widthFactor = this.mAdapter.getPageWidth(ii.position);
                i--;
            }
            float offset = ii.offset;
            float leftBound = offset;
            float rightBound = ii.widthFactor + offset + marginOffset;
            if (!first && scrollOffset < leftBound) {
                return lastItem;
            }
            if (scrollOffset < rightBound || i == this.mItems.size() - 1) {
                return ii;
            }
            first = false;
            lastPos = ii.position;
            lastOffset = offset;
            lastWidth = ii.widthFactor;
            lastItem = ii;
            i++;
        }
        return lastItem;
    }

    private int determineTargetPage(int currentPage, float pageOffset, int velocity, int deltaX) {
        int targetPage;
        if (Math.abs(deltaX) <= this.mFlingDistance || Math.abs(velocity) <= this.mMinimumVelocity) {
            targetPage = ((int) (pageOffset + (currentPage >= this.mCurItem ? 0.4f : 0.6f))) + currentPage;
        } else {
            targetPage = velocity > 0 ? currentPage : currentPage + 1;
        }
        if (this.mItems.size() <= 0) {
            return targetPage;
        }
        ItemInfo firstItem = (ItemInfo) this.mItems.get(0);
        ArrayList<ItemInfo> arrayList = this.mItems;
        return Math.max(firstItem.position, Math.min(targetPage, ((ItemInfo) arrayList.get(arrayList.size() - 1)).position));
    }

    /* JADX WARNING: Code restructure failed: missing block: B:7:0x0015, code lost:
        if (r3.getCount() > 1) goto L_0x0024;
     */
    /* JADX WARNING: Removed duplicated region for block: B:16:0x00a9  */
    /* JADX WARNING: Removed duplicated region for block: B:18:? A[RETURN, SYNTHETIC] */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void draw(android.graphics.Canvas r9) {
        /*
            r8 = this;
            super.draw(r9)
            r0 = 0
            int r1 = r8.getOverScrollMode()
            if (r1 == 0) goto L_0x0024
            r2 = 1
            if (r1 != r2) goto L_0x0018
            androidx.viewpager.widget.PagerAdapter r3 = r8.mAdapter
            if (r3 == 0) goto L_0x0018
            int r3 = r3.getCount()
            if (r3 <= r2) goto L_0x0018
            goto L_0x0024
        L_0x0018:
            android.widget.EdgeEffect r2 = r8.mLeftEdge
            r2.finish()
            android.widget.EdgeEffect r2 = r8.mRightEdge
            r2.finish()
            goto L_0x00a7
        L_0x0024:
            android.widget.EdgeEffect r2 = r8.mLeftEdge
            boolean r2 = r2.isFinished()
            if (r2 != 0) goto L_0x0064
            int r2 = r9.save()
            int r3 = r8.getHeight()
            int r4 = r8.getPaddingTop()
            int r3 = r3 - r4
            int r4 = r8.getPaddingBottom()
            int r3 = r3 - r4
            int r4 = r8.getWidth()
            r5 = 1132920832(0x43870000, float:270.0)
            r9.rotate(r5)
            int r5 = -r3
            int r6 = r8.getPaddingTop()
            int r5 = r5 + r6
            float r5 = (float) r5
            float r6 = r8.mFirstOffset
            float r7 = (float) r4
            float r6 = r6 * r7
            r9.translate(r5, r6)
            android.widget.EdgeEffect r5 = r8.mLeftEdge
            r5.setSize(r3, r4)
            android.widget.EdgeEffect r5 = r8.mLeftEdge
            boolean r5 = r5.draw(r9)
            r0 = r0 | r5
            r9.restoreToCount(r2)
        L_0x0064:
            android.widget.EdgeEffect r2 = r8.mRightEdge
            boolean r2 = r2.isFinished()
            if (r2 != 0) goto L_0x00a7
            int r2 = r9.save()
            int r3 = r8.getWidth()
            int r4 = r8.getHeight()
            int r5 = r8.getPaddingTop()
            int r4 = r4 - r5
            int r5 = r8.getPaddingBottom()
            int r4 = r4 - r5
            r5 = 1119092736(0x42b40000, float:90.0)
            r9.rotate(r5)
            int r5 = r8.getPaddingTop()
            int r5 = -r5
            float r5 = (float) r5
            float r6 = r8.mLastOffset
            r7 = 1065353216(0x3f800000, float:1.0)
            float r6 = r6 + r7
            float r6 = -r6
            float r7 = (float) r3
            float r6 = r6 * r7
            r9.translate(r5, r6)
            android.widget.EdgeEffect r5 = r8.mRightEdge
            r5.setSize(r4, r3)
            android.widget.EdgeEffect r5 = r8.mRightEdge
            boolean r5 = r5.draw(r9)
            r0 = r0 | r5
            r9.restoreToCount(r2)
        L_0x00a7:
            if (r0 == 0) goto L_0x00ac
            androidx.core.view.ViewCompat.postInvalidateOnAnimation(r8)
        L_0x00ac:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.draw(android.graphics.Canvas):void");
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        float widthFactor;
        float marginOffset;
        super.onDraw(canvas);
        if (this.mPageMargin <= 0 || this.mMarginDrawable == null || this.mItems.size() <= 0 || this.mAdapter == null) {
            Canvas canvas2 = canvas;
            return;
        }
        int scrollX = getScrollX();
        int width = getWidth();
        float marginOffset2 = ((float) this.mPageMargin) / ((float) width);
        int itemIndex = 0;
        ItemInfo ii = (ItemInfo) this.mItems.get(0);
        float offset = ii.offset;
        int itemCount = this.mItems.size();
        int firstPos = ii.position;
        int lastPos = ((ItemInfo) this.mItems.get(itemCount - 1)).position;
        int pos = firstPos;
        while (pos < lastPos) {
            while (pos > ii.position && itemIndex < itemCount) {
                itemIndex++;
                ii = (ItemInfo) this.mItems.get(itemIndex);
            }
            if (pos == ii.position) {
                widthFactor = (ii.offset + ii.widthFactor) * ((float) width);
                offset = ii.offset + ii.widthFactor + marginOffset2;
            } else {
                float widthFactor2 = this.mAdapter.getPageWidth(pos);
                float drawAt = (offset + widthFactor2) * ((float) width);
                offset += widthFactor2 + marginOffset2;
                widthFactor = drawAt;
            }
            if (((float) this.mPageMargin) + widthFactor > ((float) scrollX)) {
                marginOffset = marginOffset2;
                this.mMarginDrawable.setBounds(Math.round(widthFactor), this.mTopPageBounds, Math.round(((float) this.mPageMargin) + widthFactor), this.mBottomPageBounds);
                this.mMarginDrawable.draw(canvas);
            } else {
                Canvas canvas3 = canvas;
                marginOffset = marginOffset2;
            }
            if (widthFactor <= ((float) (scrollX + width))) {
                pos++;
                marginOffset2 = marginOffset;
            } else {
                return;
            }
        }
        Canvas canvas4 = canvas;
        float f = marginOffset2;
    }

    public boolean beginFakeDrag() {
        if (this.mIsBeingDragged) {
            return false;
        }
        this.mFakeDragging = true;
        setScrollState(1);
        this.mLastMotionX = 0.0f;
        this.mInitialMotionX = 0.0f;
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker == null) {
            this.mVelocityTracker = VelocityTracker.obtain();
        } else {
            velocityTracker.clear();
        }
        long time = SystemClock.uptimeMillis();
        MotionEvent ev = MotionEvent.obtain(time, time, 0, 0.0f, 0.0f, 0);
        this.mVelocityTracker.addMovement(ev);
        ev.recycle();
        this.mFakeDragBeginTime = time;
        return true;
    }

    public void endFakeDrag() {
        if (this.mFakeDragging) {
            if (this.mAdapter != null) {
                VelocityTracker velocityTracker = this.mVelocityTracker;
                velocityTracker.computeCurrentVelocity(1000, (float) this.mMaximumVelocity);
                int initialVelocity = (int) velocityTracker.getXVelocity(this.mActivePointerId);
                this.mPopulatePending = true;
                int width = getClientWidth();
                int scrollX = getScrollX();
                ItemInfo ii = infoForCurrentScrollPosition();
                setCurrentItemInternal(determineTargetPage(ii.position, ((((float) scrollX) / ((float) width)) - ii.offset) / ii.widthFactor, initialVelocity, (int) (this.mLastMotionX - this.mInitialMotionX)), true, true, initialVelocity);
            }
            endDrag();
            this.mFakeDragging = false;
            return;
        }
        throw new IllegalStateException("No fake drag in progress. Call beginFakeDrag first.");
    }

    public void fakeDragBy(float xOffset) {
        if (!this.mFakeDragging) {
            throw new IllegalStateException("No fake drag in progress. Call beginFakeDrag first.");
        } else if (this.mAdapter != null) {
            this.mLastMotionX += xOffset;
            float scrollX = ((float) getScrollX()) - xOffset;
            int width = getClientWidth();
            float leftBound = ((float) width) * this.mFirstOffset;
            float rightBound = ((float) width) * this.mLastOffset;
            ItemInfo firstItem = (ItemInfo) this.mItems.get(0);
            ArrayList<ItemInfo> arrayList = this.mItems;
            ItemInfo lastItem = (ItemInfo) arrayList.get(arrayList.size() - 1);
            if (firstItem.position != 0) {
                leftBound = firstItem.offset * ((float) width);
            }
            if (lastItem.position != this.mAdapter.getCount() - 1) {
                rightBound = lastItem.offset * ((float) width);
            }
            if (scrollX < leftBound) {
                scrollX = leftBound;
            } else if (scrollX > rightBound) {
                scrollX = rightBound;
            }
            this.mLastMotionX += scrollX - ((float) ((int) scrollX));
            scrollTo((int) scrollX, getScrollY());
            pageScrolled((int) scrollX);
            MotionEvent ev = MotionEvent.obtain(this.mFakeDragBeginTime, SystemClock.uptimeMillis(), 2, this.mLastMotionX, 0.0f, 0);
            this.mVelocityTracker.addMovement(ev);
            ev.recycle();
        }
    }

    public boolean isFakeDragging() {
        return this.mFakeDragging;
    }

    private void onSecondaryPointerUp(MotionEvent ev) {
        int pointerIndex = ev.getActionIndex();
        if (ev.getPointerId(pointerIndex) == this.mActivePointerId) {
            int newPointerIndex = pointerIndex == 0 ? 1 : 0;
            this.mLastMotionX = ev.getX(newPointerIndex);
            this.mActivePointerId = ev.getPointerId(newPointerIndex);
            VelocityTracker velocityTracker = this.mVelocityTracker;
            if (velocityTracker != null) {
                velocityTracker.clear();
            }
        }
    }

    private void endDrag() {
        this.mIsBeingDragged = false;
        this.mIsUnableToDrag = false;
        VelocityTracker velocityTracker = this.mVelocityTracker;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.mVelocityTracker = null;
        }
    }

    private void setScrollingCacheEnabled(boolean enabled) {
        if (this.mScrollingCacheEnabled != enabled) {
            this.mScrollingCacheEnabled = enabled;
        }
    }

    public boolean canScrollHorizontally(int direction) {
        boolean z = false;
        if (this.mAdapter == null) {
            return false;
        }
        int width = getClientWidth();
        int scrollX = getScrollX();
        if (direction < 0) {
            if (scrollX > ((int) (((float) width) * this.mFirstOffset))) {
                z = true;
            }
            return z;
        } else if (direction <= 0) {
            return false;
        } else {
            if (scrollX < ((int) (((float) width) * this.mLastOffset))) {
                z = true;
            }
            return z;
        }
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0065, code lost:
        if (r15.canScrollHorizontally(-r17) != false) goto L_0x006b;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean canScroll(android.view.View r15, boolean r16, int r17, int r18, int r19) {
        /*
            r14 = this;
            r0 = r15
            boolean r1 = r0 instanceof android.view.ViewGroup
            r2 = 1
            if (r1 == 0) goto L_0x005c
            r1 = r0
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
            int r3 = r15.getScrollX()
            int r4 = r15.getScrollY()
            int r5 = r1.getChildCount()
            int r6 = r5 + -1
        L_0x0017:
            if (r6 < 0) goto L_0x005c
            android.view.View r13 = r1.getChildAt(r6)
            int r7 = r18 + r3
            int r8 = r13.getLeft()
            if (r7 < r8) goto L_0x0059
            int r7 = r18 + r3
            int r8 = r13.getRight()
            if (r7 >= r8) goto L_0x0059
            int r7 = r19 + r4
            int r8 = r13.getTop()
            if (r7 < r8) goto L_0x0059
            int r7 = r19 + r4
            int r8 = r13.getBottom()
            if (r7 >= r8) goto L_0x0059
            r9 = 1
            int r7 = r18 + r3
            int r8 = r13.getLeft()
            int r11 = r7 - r8
            int r7 = r19 + r4
            int r8 = r13.getTop()
            int r12 = r7 - r8
            r7 = r14
            r8 = r13
            r10 = r17
            boolean r7 = r7.canScroll(r8, r9, r10, r11, r12)
            if (r7 == 0) goto L_0x0059
            return r2
        L_0x0059:
            int r6 = r6 + -1
            goto L_0x0017
        L_0x005c:
            if (r16 == 0) goto L_0x0068
            r1 = r17
            int r3 = -r1
            boolean r3 = r15.canScrollHorizontally(r3)
            if (r3 == 0) goto L_0x006a
            goto L_0x006b
        L_0x0068:
            r1 = r17
        L_0x006a:
            r2 = 0
        L_0x006b:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.canScroll(android.view.View, boolean, int, int, int):boolean");
    }

    public boolean dispatchKeyEvent(KeyEvent event) {
        return super.dispatchKeyEvent(event) || executeKeyEvent(event);
    }

    public boolean executeKeyEvent(KeyEvent event) {
        if (event.getAction() != 0) {
            return false;
        }
        int keyCode = event.getKeyCode();
        if (keyCode != 21) {
            if (keyCode != 22) {
                if (keyCode != 61) {
                    return false;
                }
                if (event.hasNoModifiers()) {
                    return arrowScroll(2);
                }
                if (event.hasModifiers(1)) {
                    return arrowScroll(1);
                }
                return false;
            } else if (event.hasModifiers(2)) {
                return pageRight();
            } else {
                return arrowScroll(66);
            }
        } else if (event.hasModifiers(2)) {
            return pageLeft();
        } else {
            return arrowScroll(17);
        }
    }

    public boolean arrowScroll(int direction) {
        View currentFocused = findFocus();
        if (currentFocused == this) {
            currentFocused = null;
        } else if (currentFocused != null) {
            boolean isChild = false;
            ViewParent parent = currentFocused.getParent();
            while (true) {
                if (!(parent instanceof ViewGroup)) {
                    break;
                } else if (parent == this) {
                    isChild = true;
                    break;
                } else {
                    parent = parent.getParent();
                }
            }
            if (!isChild) {
                StringBuilder sb = new StringBuilder();
                sb.append(currentFocused.getClass().getSimpleName());
                for (ViewParent parent2 = currentFocused.getParent(); parent2 instanceof ViewGroup; parent2 = parent2.getParent()) {
                    sb.append(" => ");
                    sb.append(parent2.getClass().getSimpleName());
                }
                StringBuilder sb2 = new StringBuilder();
                sb2.append("arrowScroll tried to find focus based on non-child current focused view ");
                sb2.append(sb.toString());
                Log.e(TAG, sb2.toString());
                currentFocused = null;
            }
        }
        boolean handled = false;
        View nextFocused = FocusFinder.getInstance().findNextFocus(this, currentFocused, direction);
        if (nextFocused == null || nextFocused == currentFocused) {
            if (direction == 17 || direction == 1) {
                handled = pageLeft();
            } else if (direction == 66 || direction == 2) {
                handled = pageRight();
            }
        } else if (direction == 17) {
            handled = (currentFocused == null || getChildRectInPagerCoordinates(this.mTempRect, nextFocused).left < getChildRectInPagerCoordinates(this.mTempRect, currentFocused).left) ? nextFocused.requestFocus() : pageLeft();
        } else if (direction == 66) {
            handled = (currentFocused == null || getChildRectInPagerCoordinates(this.mTempRect, nextFocused).left > getChildRectInPagerCoordinates(this.mTempRect, currentFocused).left) ? nextFocused.requestFocus() : pageRight();
        }
        if (handled) {
            playSoundEffect(SoundEffectConstants.getContantForFocusDirection(direction));
        }
        return handled;
    }

    private Rect getChildRectInPagerCoordinates(Rect outRect, View child) {
        if (outRect == null) {
            outRect = new Rect();
        }
        if (child == null) {
            outRect.set(0, 0, 0, 0);
            return outRect;
        }
        outRect.left = child.getLeft();
        outRect.right = child.getRight();
        outRect.top = child.getTop();
        outRect.bottom = child.getBottom();
        ViewParent parent = child.getParent();
        while ((parent instanceof ViewGroup) && parent != this) {
            ViewGroup group = (ViewGroup) parent;
            outRect.left += group.getLeft();
            outRect.right += group.getRight();
            outRect.top += group.getTop();
            outRect.bottom += group.getBottom();
            parent = group.getParent();
        }
        return outRect;
    }

    /* access modifiers changed from: 0000 */
    public boolean pageLeft() {
        int i = this.mCurItem;
        if (i <= 0) {
            return false;
        }
        setCurrentItem(i - 1, true);
        return true;
    }

    /* access modifiers changed from: 0000 */
    public boolean pageRight() {
        PagerAdapter pagerAdapter = this.mAdapter;
        if (pagerAdapter == null || this.mCurItem >= pagerAdapter.getCount() - 1) {
            return false;
        }
        setCurrentItem(this.mCurItem + 1, true);
        return true;
    }

    public void addFocusables(ArrayList<View> views, int direction, int focusableMode) {
        int focusableCount = views.size();
        int descendantFocusability = getDescendantFocusability();
        if (descendantFocusability != 393216) {
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i);
                if (child.getVisibility() == 0) {
                    ItemInfo ii = infoForChild(child);
                    if (ii != null && ii.position == this.mCurItem) {
                        child.addFocusables(views, direction, focusableMode);
                    }
                }
            }
        }
        if ((descendantFocusability == 262144 && focusableCount != views.size()) || !isFocusable()) {
            return;
        }
        if (((focusableMode & 1) != 1 || !isInTouchMode() || isFocusableInTouchMode()) && views != null) {
            views.add(this);
        }
    }

    public void addTouchables(ArrayList<View> views) {
        for (int i = 0; i < getChildCount(); i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == 0) {
                ItemInfo ii = infoForChild(child);
                if (ii != null && ii.position == this.mCurItem) {
                    child.addTouchables(views);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public boolean onRequestFocusInDescendants(int direction, Rect previouslyFocusedRect) {
        int end;
        int increment;
        int index;
        int count = getChildCount();
        if ((direction & 2) != 0) {
            index = 0;
            increment = 1;
            end = count;
        } else {
            index = count - 1;
            increment = -1;
            end = -1;
        }
        for (int i = index; i != end; i += increment) {
            View child = getChildAt(i);
            if (child.getVisibility() == 0) {
                ItemInfo ii = infoForChild(child);
                if (ii != null && ii.position == this.mCurItem && child.requestFocus(direction, previouslyFocusedRect)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == 4096) {
            return super.dispatchPopulateAccessibilityEvent(event);
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == 0) {
                ItemInfo ii = infoForChild(child);
                if (ii != null && ii.position == this.mCurItem && child.dispatchPopulateAccessibilityEvent(event)) {
                    return true;
                }
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public android.view.ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams();
    }

    /* access modifiers changed from: protected */
    public android.view.ViewGroup.LayoutParams generateLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return generateDefaultLayoutParams();
    }

    /* access modifiers changed from: protected */
    public boolean checkLayoutParams(android.view.ViewGroup.LayoutParams p) {
        return (p instanceof LayoutParams) && super.checkLayoutParams(p);
    }

    public android.view.ViewGroup.LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }
}
