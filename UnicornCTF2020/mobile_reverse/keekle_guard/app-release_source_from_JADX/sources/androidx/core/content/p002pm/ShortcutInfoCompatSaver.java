package androidx.core.content.p002pm;

import java.util.ArrayList;
import java.util.List;

/* renamed from: androidx.core.content.pm.ShortcutInfoCompatSaver */
public abstract class ShortcutInfoCompatSaver<T> {

    /* renamed from: androidx.core.content.pm.ShortcutInfoCompatSaver$NoopImpl */
    public static class NoopImpl extends ShortcutInfoCompatSaver<Void> {
        public Void addShortcuts(List<ShortcutInfoCompat> list) {
            return null;
        }

        public Void removeAllShortcuts() {
            return null;
        }

        public Void removeShortcuts(List<String> list) {
            return null;
        }
    }

    public abstract T addShortcuts(List<ShortcutInfoCompat> list);

    public abstract T removeAllShortcuts();

    public abstract T removeShortcuts(List<String> list);

    public List<ShortcutInfoCompat> getShortcuts() throws Exception {
        return new ArrayList();
    }
}
