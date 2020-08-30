package androidx.lifecycle;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public abstract class ViewModel {
    private final Map<String, Object> mBagOfTags = new HashMap();
    private volatile boolean mCleared = false;

    /* access modifiers changed from: protected */
    public void onCleared() {
    }

    /* access modifiers changed from: 0000 */
    public final void clear() {
        this.mCleared = true;
        Map<String, Object> map = this.mBagOfTags;
        if (map != null) {
            synchronized (map) {
                for (Object value : this.mBagOfTags.values()) {
                    closeWithRuntimeException(value);
                }
            }
        }
        onCleared();
    }

    /* access modifiers changed from: 0000 */
    public <T> T setTagIfAbsent(String key, T newValue) {
        T previous;
        synchronized (this.mBagOfTags) {
            previous = this.mBagOfTags.get(key);
            if (previous == null) {
                this.mBagOfTags.put(key, newValue);
            }
        }
        T result = previous == null ? newValue : previous;
        if (this.mCleared) {
            closeWithRuntimeException(result);
        }
        return result;
    }

    /* access modifiers changed from: 0000 */
    public <T> T getTag(String key) {
        T t;
        synchronized (this.mBagOfTags) {
            t = this.mBagOfTags.get(key);
        }
        return t;
    }

    private static void closeWithRuntimeException(Object obj) {
        if (obj instanceof Closeable) {
            try {
                ((Closeable) obj).close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
