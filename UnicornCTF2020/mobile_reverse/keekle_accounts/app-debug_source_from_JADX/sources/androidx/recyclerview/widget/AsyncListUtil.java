package androidx.recyclerview.widget;

import android.util.Log;
import android.util.SparseBooleanArray;
import android.util.SparseIntArray;
import androidx.recyclerview.widget.ThreadUtil.BackgroundCallback;
import androidx.recyclerview.widget.ThreadUtil.MainThreadCallback;
import androidx.recyclerview.widget.TileList.Tile;

public class AsyncListUtil<T> {
    static final boolean DEBUG = false;
    static final String TAG = "AsyncListUtil";
    boolean mAllowScrollHints;
    private final BackgroundCallback<T> mBackgroundCallback = new BackgroundCallback<T>() {
        private int mFirstRequiredTileStart;
        private int mGeneration;
        private int mItemCount;
        private int mLastRequiredTileStart;
        final SparseBooleanArray mLoadedTiles = new SparseBooleanArray();
        private Tile<T> mRecycledRoot;

        public void refresh(int generation) {
            this.mGeneration = generation;
            this.mLoadedTiles.clear();
            this.mItemCount = AsyncListUtil.this.mDataCallback.refreshData();
            AsyncListUtil.this.mMainThreadProxy.updateItemCount(this.mGeneration, this.mItemCount);
        }

        public void updateRange(int rangeStart, int rangeEnd, int extRangeStart, int extRangeEnd, int scrollHint) {
            if (rangeStart <= rangeEnd) {
                int firstVisibleTileStart = getTileStart(rangeStart);
                int lastVisibleTileStart = getTileStart(rangeEnd);
                this.mFirstRequiredTileStart = getTileStart(extRangeStart);
                int tileStart = getTileStart(extRangeEnd);
                this.mLastRequiredTileStart = tileStart;
                if (scrollHint == 1) {
                    requestTiles(this.mFirstRequiredTileStart, lastVisibleTileStart, scrollHint, true);
                    requestTiles(AsyncListUtil.this.mTileSize + lastVisibleTileStart, this.mLastRequiredTileStart, scrollHint, false);
                } else {
                    requestTiles(firstVisibleTileStart, tileStart, scrollHint, false);
                    requestTiles(this.mFirstRequiredTileStart, firstVisibleTileStart - AsyncListUtil.this.mTileSize, scrollHint, true);
                }
            }
        }

        private int getTileStart(int position) {
            return position - (position % AsyncListUtil.this.mTileSize);
        }

        private void requestTiles(int firstTileStart, int lastTileStart, int scrollHint, boolean backwards) {
            int i = firstTileStart;
            while (i <= lastTileStart) {
                AsyncListUtil.this.mBackgroundProxy.loadTile(backwards ? (lastTileStart + firstTileStart) - i : i, scrollHint);
                i += AsyncListUtil.this.mTileSize;
            }
        }

        public void loadTile(int position, int scrollHint) {
            if (!isTileLoaded(position)) {
                Tile<T> tile = acquireTile();
                tile.mStartPosition = position;
                tile.mItemCount = Math.min(AsyncListUtil.this.mTileSize, this.mItemCount - tile.mStartPosition);
                AsyncListUtil.this.mDataCallback.fillData(tile.mItems, tile.mStartPosition, tile.mItemCount);
                flushTileCache(scrollHint);
                addTile(tile);
            }
        }

        public void recycleTile(Tile<T> tile) {
            AsyncListUtil.this.mDataCallback.recycleData(tile.mItems, tile.mItemCount);
            tile.mNext = this.mRecycledRoot;
            this.mRecycledRoot = tile;
        }

        private Tile<T> acquireTile() {
            Tile<T> tile = this.mRecycledRoot;
            if (tile == null) {
                return new Tile<>(AsyncListUtil.this.mTClass, AsyncListUtil.this.mTileSize);
            }
            Tile<T> result = this.mRecycledRoot;
            this.mRecycledRoot = tile.mNext;
            return result;
        }

        private boolean isTileLoaded(int position) {
            return this.mLoadedTiles.get(position);
        }

        private void addTile(Tile<T> tile) {
            this.mLoadedTiles.put(tile.mStartPosition, true);
            AsyncListUtil.this.mMainThreadProxy.addTile(this.mGeneration, tile);
        }

        private void removeTile(int position) {
            this.mLoadedTiles.delete(position);
            AsyncListUtil.this.mMainThreadProxy.removeTile(this.mGeneration, position);
        }

        private void flushTileCache(int scrollHint) {
            int cacheSizeLimit = AsyncListUtil.this.mDataCallback.getMaxCachedTiles();
            while (this.mLoadedTiles.size() >= cacheSizeLimit) {
                int firstLoadedTileStart = this.mLoadedTiles.keyAt(0);
                SparseBooleanArray sparseBooleanArray = this.mLoadedTiles;
                int lastLoadedTileStart = sparseBooleanArray.keyAt(sparseBooleanArray.size() - 1);
                int startMargin = this.mFirstRequiredTileStart - firstLoadedTileStart;
                int endMargin = lastLoadedTileStart - this.mLastRequiredTileStart;
                if (startMargin > 0 && (startMargin >= endMargin || scrollHint == 2)) {
                    removeTile(firstLoadedTileStart);
                } else if (endMargin > 0 && (startMargin < endMargin || scrollHint == 1)) {
                    removeTile(lastLoadedTileStart);
                } else {
                    return;
                }
            }
        }

        private void log(String s, Object... args) {
            StringBuilder sb = new StringBuilder();
            sb.append("[BKGR] ");
            sb.append(String.format(s, args));
            Log.d(AsyncListUtil.TAG, sb.toString());
        }
    };
    final BackgroundCallback<T> mBackgroundProxy;
    final DataCallback<T> mDataCallback;
    int mDisplayedGeneration = 0;
    int mItemCount = 0;
    private final MainThreadCallback<T> mMainThreadCallback = new MainThreadCallback<T>() {
        public void updateItemCount(int generation, int itemCount) {
            if (isRequestedGeneration(generation)) {
                AsyncListUtil.this.mItemCount = itemCount;
                AsyncListUtil.this.mViewCallback.onDataRefresh();
                AsyncListUtil asyncListUtil = AsyncListUtil.this;
                asyncListUtil.mDisplayedGeneration = asyncListUtil.mRequestedGeneration;
                recycleAllTiles();
                AsyncListUtil.this.mAllowScrollHints = false;
                AsyncListUtil.this.updateRange();
            }
        }

        public void addTile(int generation, Tile<T> tile) {
            if (!isRequestedGeneration(generation)) {
                AsyncListUtil.this.mBackgroundProxy.recycleTile(tile);
                return;
            }
            Tile<T> duplicate = AsyncListUtil.this.mTileList.addOrReplace(tile);
            if (duplicate != null) {
                StringBuilder sb = new StringBuilder();
                sb.append("duplicate tile @");
                sb.append(duplicate.mStartPosition);
                Log.e(AsyncListUtil.TAG, sb.toString());
                AsyncListUtil.this.mBackgroundProxy.recycleTile(duplicate);
            }
            int endPosition = tile.mStartPosition + tile.mItemCount;
            int index = 0;
            while (index < AsyncListUtil.this.mMissingPositions.size()) {
                int position = AsyncListUtil.this.mMissingPositions.keyAt(index);
                if (tile.mStartPosition > position || position >= endPosition) {
                    index++;
                } else {
                    AsyncListUtil.this.mMissingPositions.removeAt(index);
                    AsyncListUtil.this.mViewCallback.onItemLoaded(position);
                }
            }
        }

        public void removeTile(int generation, int position) {
            if (isRequestedGeneration(generation)) {
                Tile<T> tile = AsyncListUtil.this.mTileList.removeAtPos(position);
                if (tile == null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append("tile not found @");
                    sb.append(position);
                    Log.e(AsyncListUtil.TAG, sb.toString());
                    return;
                }
                AsyncListUtil.this.mBackgroundProxy.recycleTile(tile);
            }
        }

        private void recycleAllTiles() {
            for (int i = 0; i < AsyncListUtil.this.mTileList.size(); i++) {
                AsyncListUtil.this.mBackgroundProxy.recycleTile(AsyncListUtil.this.mTileList.getAtIndex(i));
            }
            AsyncListUtil.this.mTileList.clear();
        }

        private boolean isRequestedGeneration(int generation) {
            return generation == AsyncListUtil.this.mRequestedGeneration;
        }
    };
    final MainThreadCallback<T> mMainThreadProxy;
    final SparseIntArray mMissingPositions = new SparseIntArray();
    final int[] mPrevRange = new int[2];
    int mRequestedGeneration = 0;
    private int mScrollHint = 0;
    final Class<T> mTClass;
    final TileList<T> mTileList;
    final int mTileSize;
    final int[] mTmpRange = new int[2];
    final int[] mTmpRangeExtended = new int[2];
    final ViewCallback mViewCallback;

    public static abstract class DataCallback<T> {
        public abstract void fillData(T[] tArr, int i, int i2);

        public abstract int refreshData();

        public void recycleData(T[] tArr, int itemCount) {
        }

        public int getMaxCachedTiles() {
            return 10;
        }
    }

    public static abstract class ViewCallback {
        public static final int HINT_SCROLL_ASC = 2;
        public static final int HINT_SCROLL_DESC = 1;
        public static final int HINT_SCROLL_NONE = 0;

        public abstract void getItemRangeInto(int[] iArr);

        public abstract void onDataRefresh();

        public abstract void onItemLoaded(int i);

        public void extendRangeInto(int[] range, int[] outRange, int scrollHint) {
            int fullRange = (range[1] - range[0]) + 1;
            int halfRange = fullRange / 2;
            outRange[0] = range[0] - (scrollHint == 1 ? fullRange : halfRange);
            outRange[1] = range[1] + (scrollHint == 2 ? fullRange : halfRange);
        }
    }

    /* access modifiers changed from: 0000 */
    public void log(String s, Object... args) {
        StringBuilder sb = new StringBuilder();
        sb.append("[MAIN] ");
        sb.append(String.format(s, args));
        Log.d(TAG, sb.toString());
    }

    public AsyncListUtil(Class<T> klass, int tileSize, DataCallback<T> dataCallback, ViewCallback viewCallback) {
        this.mTClass = klass;
        this.mTileSize = tileSize;
        this.mDataCallback = dataCallback;
        this.mViewCallback = viewCallback;
        this.mTileList = new TileList<>(this.mTileSize);
        ThreadUtil<T> threadUtil = new MessageThreadUtil<>();
        this.mMainThreadProxy = threadUtil.getMainThreadProxy(this.mMainThreadCallback);
        this.mBackgroundProxy = threadUtil.getBackgroundProxy(this.mBackgroundCallback);
        refresh();
    }

    private boolean isRefreshPending() {
        return this.mRequestedGeneration != this.mDisplayedGeneration;
    }

    public void onRangeChanged() {
        if (!isRefreshPending()) {
            updateRange();
            this.mAllowScrollHints = true;
        }
    }

    public void refresh() {
        this.mMissingPositions.clear();
        BackgroundCallback<T> backgroundCallback = this.mBackgroundProxy;
        int i = this.mRequestedGeneration + 1;
        this.mRequestedGeneration = i;
        backgroundCallback.refresh(i);
    }

    public T getItem(int position) {
        if (position < 0 || position >= this.mItemCount) {
            StringBuilder sb = new StringBuilder();
            sb.append(position);
            sb.append(" is not within 0 and ");
            sb.append(this.mItemCount);
            throw new IndexOutOfBoundsException(sb.toString());
        }
        T item = this.mTileList.getItemAt(position);
        if (item == null && !isRefreshPending()) {
            this.mMissingPositions.put(position, 0);
        }
        return item;
    }

    public int getItemCount() {
        return this.mItemCount;
    }

    /* access modifiers changed from: 0000 */
    public void updateRange() {
        this.mViewCallback.getItemRangeInto(this.mTmpRange);
        int[] iArr = this.mTmpRange;
        if (iArr[0] <= iArr[1] && iArr[0] >= 0 && iArr[1] < this.mItemCount) {
            if (!this.mAllowScrollHints) {
                this.mScrollHint = 0;
            } else {
                int i = iArr[0];
                int[] iArr2 = this.mPrevRange;
                if (i > iArr2[1] || iArr2[0] > iArr[1]) {
                    this.mScrollHint = 0;
                } else if (iArr[0] < iArr2[0]) {
                    this.mScrollHint = 1;
                } else if (iArr[0] > iArr2[0]) {
                    this.mScrollHint = 2;
                }
            }
            int[] iArr3 = this.mPrevRange;
            int[] iArr4 = this.mTmpRange;
            iArr3[0] = iArr4[0];
            iArr3[1] = iArr4[1];
            this.mViewCallback.extendRangeInto(iArr4, this.mTmpRangeExtended, this.mScrollHint);
            int[] iArr5 = this.mTmpRangeExtended;
            iArr5[0] = Math.min(this.mTmpRange[0], Math.max(iArr5[0], 0));
            int[] iArr6 = this.mTmpRangeExtended;
            iArr6[1] = Math.max(this.mTmpRange[1], Math.min(iArr6[1], this.mItemCount - 1));
            BackgroundCallback<T> backgroundCallback = this.mBackgroundProxy;
            int[] iArr7 = this.mTmpRange;
            int i2 = iArr7[0];
            int i3 = iArr7[1];
            int[] iArr8 = this.mTmpRangeExtended;
            backgroundCallback.updateRange(i2, i3, iArr8[0], iArr8[1], this.mScrollHint);
        }
    }
}
