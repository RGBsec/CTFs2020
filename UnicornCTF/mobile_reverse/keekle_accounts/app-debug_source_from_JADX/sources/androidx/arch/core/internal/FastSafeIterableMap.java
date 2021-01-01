package androidx.arch.core.internal;

import java.util.HashMap;
import java.util.Map.Entry;

public class FastSafeIterableMap<K, V> extends SafeIterableMap<K, V> {
    private HashMap<K, Entry<K, V>> mHashMap = new HashMap<>();

    /* access modifiers changed from: protected */
    public Entry<K, V> get(K k) {
        return (Entry) this.mHashMap.get(k);
    }

    public V putIfAbsent(K key, V v) {
        Entry<K, V> current = get(key);
        if (current != null) {
            return current.mValue;
        }
        this.mHashMap.put(key, put(key, v));
        return null;
    }

    public V remove(K key) {
        V removed = super.remove(key);
        this.mHashMap.remove(key);
        return removed;
    }

    public boolean contains(K key) {
        return this.mHashMap.containsKey(key);
    }

    public Entry<K, V> ceil(K k) {
        if (contains(k)) {
            return ((Entry) this.mHashMap.get(k)).mPrevious;
        }
        return null;
    }
}
