package androidx.recyclerview.widget;

public class BatchingListUpdateCallback implements ListUpdateCallback {
    private static final int TYPE_ADD = 1;
    private static final int TYPE_CHANGE = 3;
    private static final int TYPE_NONE = 0;
    private static final int TYPE_REMOVE = 2;
    int mLastEventCount = -1;
    Object mLastEventPayload = null;
    int mLastEventPosition = -1;
    int mLastEventType = 0;
    final ListUpdateCallback mWrapped;

    public BatchingListUpdateCallback(ListUpdateCallback callback) {
        this.mWrapped = callback;
    }

    public void dispatchLastEvent() {
        int i = this.mLastEventType;
        if (i != 0) {
            if (i == 1) {
                this.mWrapped.onInserted(this.mLastEventPosition, this.mLastEventCount);
            } else if (i == 2) {
                this.mWrapped.onRemoved(this.mLastEventPosition, this.mLastEventCount);
            } else if (i == 3) {
                this.mWrapped.onChanged(this.mLastEventPosition, this.mLastEventCount, this.mLastEventPayload);
            }
            this.mLastEventPayload = null;
            this.mLastEventType = 0;
        }
    }

    public void onInserted(int position, int count) {
        if (this.mLastEventType == 1) {
            int i = this.mLastEventPosition;
            if (position >= i) {
                int i2 = this.mLastEventCount;
                if (position <= i + i2) {
                    this.mLastEventCount = i2 + count;
                    this.mLastEventPosition = Math.min(position, i);
                    return;
                }
            }
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventType = 1;
    }

    public void onRemoved(int position, int count) {
        if (this.mLastEventType == 2) {
            int i = this.mLastEventPosition;
            if (i >= position && i <= position + count) {
                this.mLastEventCount += count;
                this.mLastEventPosition = position;
                return;
            }
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventType = 2;
    }

    public void onMoved(int fromPosition, int toPosition) {
        dispatchLastEvent();
        this.mWrapped.onMoved(fromPosition, toPosition);
    }

    public void onChanged(int position, int count, Object payload) {
        if (this.mLastEventType == 3) {
            int i = this.mLastEventPosition;
            int i2 = this.mLastEventCount;
            if (position <= i + i2 && position + count >= i && this.mLastEventPayload == payload) {
                int previousEnd = i2 + i;
                this.mLastEventPosition = Math.min(position, i);
                this.mLastEventCount = Math.max(previousEnd, position + count) - this.mLastEventPosition;
                return;
            }
        }
        dispatchLastEvent();
        this.mLastEventPosition = position;
        this.mLastEventCount = count;
        this.mLastEventPayload = payload;
        this.mLastEventType = 3;
    }
}
