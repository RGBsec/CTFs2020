package androidx.recyclerview.widget;

import android.view.View;
import android.view.ViewGroup.LayoutParams;
import androidx.recyclerview.widget.RecyclerView.ViewHolder;
import java.util.ArrayList;
import java.util.List;

class ChildHelper {
    private static final boolean DEBUG = false;
    private static final String TAG = "ChildrenHelper";
    final Bucket mBucket = new Bucket();
    final Callback mCallback;
    final List<View> mHiddenViews = new ArrayList();

    static class Bucket {
        static final int BITS_PER_WORD = 64;
        static final long LAST_BIT = Long.MIN_VALUE;
        long mData = 0;
        Bucket mNext;

        Bucket() {
        }

        /* access modifiers changed from: 0000 */
        public void set(int index) {
            if (index >= 64) {
                ensureNext();
                this.mNext.set(index - 64);
                return;
            }
            this.mData |= 1 << index;
        }

        private void ensureNext() {
            if (this.mNext == null) {
                this.mNext = new Bucket();
            }
        }

        /* access modifiers changed from: 0000 */
        public void clear(int index) {
            if (index >= 64) {
                Bucket bucket = this.mNext;
                if (bucket != null) {
                    bucket.clear(index - 64);
                    return;
                }
                return;
            }
            this.mData &= ~(1 << index);
        }

        /* access modifiers changed from: 0000 */
        public boolean get(int index) {
            if (index >= 64) {
                ensureNext();
                return this.mNext.get(index - 64);
            }
            return (this.mData & (1 << index)) != 0;
        }

        /* access modifiers changed from: 0000 */
        public void reset() {
            this.mData = 0;
            Bucket bucket = this.mNext;
            if (bucket != null) {
                bucket.reset();
            }
        }

        /* access modifiers changed from: 0000 */
        public void insert(int index, boolean value) {
            if (index >= 64) {
                ensureNext();
                this.mNext.insert(index - 64, value);
                return;
            }
            boolean lastBit = (this.mData & LAST_BIT) != 0;
            long mask = (1 << index) - 1;
            long j = this.mData;
            this.mData = (j & mask) | ((j & (~mask)) << 1);
            if (value) {
                set(index);
            } else {
                clear(index);
            }
            if (lastBit || this.mNext != null) {
                ensureNext();
                this.mNext.insert(0, lastBit);
            }
        }

        /* access modifiers changed from: 0000 */
        public boolean remove(int index) {
            if (index >= 64) {
                ensureNext();
                return this.mNext.remove(index - 64);
            }
            long mask = 1 << index;
            boolean value = (this.mData & mask) != 0;
            long j = this.mData & (~mask);
            this.mData = j;
            long mask2 = mask - 1;
            this.mData = (j & mask2) | Long.rotateRight(j & (~mask2), 1);
            Bucket bucket = this.mNext;
            if (bucket != null) {
                if (bucket.get(0)) {
                    set(63);
                }
                this.mNext.remove(0);
            }
            return value;
        }

        /* access modifiers changed from: 0000 */
        public int countOnesBefore(int index) {
            Bucket bucket = this.mNext;
            if (bucket == null) {
                if (index >= 64) {
                    return Long.bitCount(this.mData);
                }
                return Long.bitCount(this.mData & ((1 << index) - 1));
            } else if (index < 64) {
                return Long.bitCount(this.mData & ((1 << index) - 1));
            } else {
                return bucket.countOnesBefore(index - 64) + Long.bitCount(this.mData);
            }
        }

        public String toString() {
            if (this.mNext == null) {
                return Long.toBinaryString(this.mData);
            }
            StringBuilder sb = new StringBuilder();
            sb.append(this.mNext.toString());
            sb.append("xx");
            sb.append(Long.toBinaryString(this.mData));
            return sb.toString();
        }
    }

    interface Callback {
        void addView(View view, int i);

        void attachViewToParent(View view, int i, LayoutParams layoutParams);

        void detachViewFromParent(int i);

        View getChildAt(int i);

        int getChildCount();

        ViewHolder getChildViewHolder(View view);

        int indexOfChild(View view);

        void onEnteredHiddenState(View view);

        void onLeftHiddenState(View view);

        void removeAllViews();

        void removeViewAt(int i);
    }

    ChildHelper(Callback callback) {
        this.mCallback = callback;
    }

    private void hideViewInternal(View child) {
        this.mHiddenViews.add(child);
        this.mCallback.onEnteredHiddenState(child);
    }

    private boolean unhideViewInternal(View child) {
        if (!this.mHiddenViews.remove(child)) {
            return false;
        }
        this.mCallback.onLeftHiddenState(child);
        return true;
    }

    /* access modifiers changed from: 0000 */
    public void addView(View child, boolean hidden) {
        addView(child, -1, hidden);
    }

    /* access modifiers changed from: 0000 */
    public void addView(View child, int index, boolean hidden) {
        int offset;
        if (index < 0) {
            offset = this.mCallback.getChildCount();
        } else {
            offset = getOffset(index);
        }
        this.mBucket.insert(offset, hidden);
        if (hidden) {
            hideViewInternal(child);
        }
        this.mCallback.addView(child, offset);
    }

    private int getOffset(int index) {
        if (index < 0) {
            return -1;
        }
        int limit = this.mCallback.getChildCount();
        int offset = index;
        while (offset < limit) {
            int diff = index - (offset - this.mBucket.countOnesBefore(offset));
            if (diff == 0) {
                while (this.mBucket.get(offset)) {
                    offset++;
                }
                return offset;
            }
            offset += diff;
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public void removeView(View view) {
        int index = this.mCallback.indexOfChild(view);
        if (index >= 0) {
            if (this.mBucket.remove(index)) {
                unhideViewInternal(view);
            }
            this.mCallback.removeViewAt(index);
        }
    }

    /* access modifiers changed from: 0000 */
    public void removeViewAt(int index) {
        int offset = getOffset(index);
        View view = this.mCallback.getChildAt(offset);
        if (view != null) {
            if (this.mBucket.remove(offset)) {
                unhideViewInternal(view);
            }
            this.mCallback.removeViewAt(offset);
        }
    }

    /* access modifiers changed from: 0000 */
    public View getChildAt(int index) {
        return this.mCallback.getChildAt(getOffset(index));
    }

    /* access modifiers changed from: 0000 */
    public void removeAllViewsUnfiltered() {
        this.mBucket.reset();
        for (int i = this.mHiddenViews.size() - 1; i >= 0; i--) {
            this.mCallback.onLeftHiddenState((View) this.mHiddenViews.get(i));
            this.mHiddenViews.remove(i);
        }
        this.mCallback.removeAllViews();
    }

    /* access modifiers changed from: 0000 */
    public View findHiddenNonRemovedView(int position) {
        int count = this.mHiddenViews.size();
        for (int i = 0; i < count; i++) {
            View view = (View) this.mHiddenViews.get(i);
            ViewHolder holder = this.mCallback.getChildViewHolder(view);
            if (holder.getLayoutPosition() == position && !holder.isInvalid() && !holder.isRemoved()) {
                return view;
            }
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public void attachViewToParent(View child, int index, LayoutParams layoutParams, boolean hidden) {
        int offset;
        if (index < 0) {
            offset = this.mCallback.getChildCount();
        } else {
            offset = getOffset(index);
        }
        this.mBucket.insert(offset, hidden);
        if (hidden) {
            hideViewInternal(child);
        }
        this.mCallback.attachViewToParent(child, offset, layoutParams);
    }

    /* access modifiers changed from: 0000 */
    public int getChildCount() {
        return this.mCallback.getChildCount() - this.mHiddenViews.size();
    }

    /* access modifiers changed from: 0000 */
    public int getUnfilteredChildCount() {
        return this.mCallback.getChildCount();
    }

    /* access modifiers changed from: 0000 */
    public View getUnfilteredChildAt(int index) {
        return this.mCallback.getChildAt(index);
    }

    /* access modifiers changed from: 0000 */
    public void detachViewFromParent(int index) {
        int offset = getOffset(index);
        this.mBucket.remove(offset);
        this.mCallback.detachViewFromParent(offset);
    }

    /* access modifiers changed from: 0000 */
    public int indexOfChild(View child) {
        int index = this.mCallback.indexOfChild(child);
        if (index != -1 && !this.mBucket.get(index)) {
            return index - this.mBucket.countOnesBefore(index);
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public boolean isHidden(View view) {
        return this.mHiddenViews.contains(view);
    }

    /* access modifiers changed from: 0000 */
    public void hide(View view) {
        int offset = this.mCallback.indexOfChild(view);
        if (offset >= 0) {
            this.mBucket.set(offset);
            hideViewInternal(view);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("view is not a child, cannot hide ");
        sb.append(view);
        throw new IllegalArgumentException(sb.toString());
    }

    /* access modifiers changed from: 0000 */
    public void unhide(View view) {
        int offset = this.mCallback.indexOfChild(view);
        if (offset < 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("view is not a child, cannot hide ");
            sb.append(view);
            throw new IllegalArgumentException(sb.toString());
        } else if (this.mBucket.get(offset)) {
            this.mBucket.clear(offset);
            unhideViewInternal(view);
        } else {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("trying to unhide a view that was not hidden");
            sb2.append(view);
            throw new RuntimeException(sb2.toString());
        }
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.mBucket.toString());
        sb.append(", hidden list:");
        sb.append(this.mHiddenViews.size());
        return sb.toString();
    }

    /* access modifiers changed from: 0000 */
    public boolean removeViewIfHidden(View view) {
        int index = this.mCallback.indexOfChild(view);
        if (index == -1) {
            unhideViewInternal(view);
            return true;
        } else if (!this.mBucket.get(index)) {
            return false;
        } else {
            this.mBucket.remove(index);
            unhideViewInternal(view);
            this.mCallback.removeViewAt(index);
            return true;
        }
    }
}
