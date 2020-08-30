package androidx.core.view;

import android.os.Build.VERSION;
import android.os.Bundle;
import android.text.style.ClickableSpan;
import android.util.SparseArray;
import android.view.View;
import android.view.View.AccessibilityDelegate;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityNodeProvider;
import androidx.core.C0020R;
import androidx.core.view.accessibility.AccessibilityClickableSpanCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat;
import androidx.core.view.accessibility.AccessibilityNodeProviderCompat;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.List;

public class AccessibilityDelegateCompat {
    private static final AccessibilityDelegate DEFAULT_DELEGATE = new AccessibilityDelegate();
    private final AccessibilityDelegate mBridge;
    private final AccessibilityDelegate mOriginalDelegate;

    static final class AccessibilityDelegateAdapter extends AccessibilityDelegate {
        final AccessibilityDelegateCompat mCompat;

        AccessibilityDelegateAdapter(AccessibilityDelegateCompat compat) {
            this.mCompat = compat;
        }

        public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            return this.mCompat.dispatchPopulateAccessibilityEvent(host, event);
        }

        public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
            this.mCompat.onInitializeAccessibilityEvent(host, event);
        }

        public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
            AccessibilityNodeInfoCompat nodeInfoCompat = AccessibilityNodeInfoCompat.wrap(info);
            nodeInfoCompat.setScreenReaderFocusable(ViewCompat.isScreenReaderFocusable(host));
            nodeInfoCompat.setHeading(ViewCompat.isAccessibilityHeading(host));
            nodeInfoCompat.setPaneTitle(ViewCompat.getAccessibilityPaneTitle(host));
            this.mCompat.onInitializeAccessibilityNodeInfo(host, nodeInfoCompat);
            nodeInfoCompat.addSpansToExtras(info.getText(), host);
            List<AccessibilityActionCompat> actions = AccessibilityDelegateCompat.getActionList(host);
            for (int i = 0; i < actions.size(); i++) {
                nodeInfoCompat.addAction((AccessibilityActionCompat) actions.get(i));
            }
        }

        public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
            this.mCompat.onPopulateAccessibilityEvent(host, event);
        }

        public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
            return this.mCompat.onRequestSendAccessibilityEvent(host, child, event);
        }

        public void sendAccessibilityEvent(View host, int eventType) {
            this.mCompat.sendAccessibilityEvent(host, eventType);
        }

        public void sendAccessibilityEventUnchecked(View host, AccessibilityEvent event) {
            this.mCompat.sendAccessibilityEventUnchecked(host, event);
        }

        public AccessibilityNodeProvider getAccessibilityNodeProvider(View host) {
            AccessibilityNodeProviderCompat provider = this.mCompat.getAccessibilityNodeProvider(host);
            if (provider != null) {
                return (AccessibilityNodeProvider) provider.getProvider();
            }
            return null;
        }

        public boolean performAccessibilityAction(View host, int action, Bundle args) {
            return this.mCompat.performAccessibilityAction(host, action, args);
        }
    }

    public AccessibilityDelegateCompat() {
        this(DEFAULT_DELEGATE);
    }

    public AccessibilityDelegateCompat(AccessibilityDelegate originalDelegate) {
        this.mOriginalDelegate = originalDelegate;
        this.mBridge = new AccessibilityDelegateAdapter(this);
    }

    /* access modifiers changed from: 0000 */
    public AccessibilityDelegate getBridge() {
        return this.mBridge;
    }

    public void sendAccessibilityEvent(View host, int eventType) {
        this.mOriginalDelegate.sendAccessibilityEvent(host, eventType);
    }

    public void sendAccessibilityEventUnchecked(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.sendAccessibilityEventUnchecked(host, event);
    }

    public boolean dispatchPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
        return this.mOriginalDelegate.dispatchPopulateAccessibilityEvent(host, event);
    }

    public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.onPopulateAccessibilityEvent(host, event);
    }

    public void onInitializeAccessibilityEvent(View host, AccessibilityEvent event) {
        this.mOriginalDelegate.onInitializeAccessibilityEvent(host, event);
    }

    public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
        this.mOriginalDelegate.onInitializeAccessibilityNodeInfo(host, info.unwrap());
    }

    public boolean onRequestSendAccessibilityEvent(ViewGroup host, View child, AccessibilityEvent event) {
        return this.mOriginalDelegate.onRequestSendAccessibilityEvent(host, child, event);
    }

    public AccessibilityNodeProviderCompat getAccessibilityNodeProvider(View host) {
        if (VERSION.SDK_INT >= 16) {
            Object provider = this.mOriginalDelegate.getAccessibilityNodeProvider(host);
            if (provider != null) {
                return new AccessibilityNodeProviderCompat(provider);
            }
        }
        return null;
    }

    public boolean performAccessibilityAction(View host, int action, Bundle args) {
        boolean success = false;
        List<AccessibilityActionCompat> actions = getActionList(host);
        int i = 0;
        while (true) {
            if (i >= actions.size()) {
                break;
            }
            AccessibilityActionCompat actionCompat = (AccessibilityActionCompat) actions.get(i);
            if (actionCompat.getId() == action) {
                success = actionCompat.perform(host, args);
                break;
            }
            i++;
        }
        if (!success && VERSION.SDK_INT >= 16) {
            success = this.mOriginalDelegate.performAccessibilityAction(host, action, args);
        }
        if (success || action != C0020R.C0022id.accessibility_action_clickable_span) {
            return success;
        }
        return performClickableSpanAction(args.getInt(AccessibilityClickableSpanCompat.SPAN_ID, -1), host);
    }

    private boolean performClickableSpanAction(int clickableSpanId, View host) {
        SparseArray<WeakReference<ClickableSpan>> spans = (SparseArray) host.getTag(C0020R.C0022id.tag_accessibility_clickable_spans);
        if (spans != null) {
            WeakReference<ClickableSpan> reference = (WeakReference) spans.get(clickableSpanId);
            if (reference != null) {
                ClickableSpan span = (ClickableSpan) reference.get();
                if (isSpanStillValid(span, host)) {
                    span.onClick(host);
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isSpanStillValid(ClickableSpan span, View view) {
        if (span != null) {
            ClickableSpan[] spans = AccessibilityNodeInfoCompat.getClickableSpans(view.createAccessibilityNodeInfo().getText());
            int i = 0;
            while (spans != null && i < spans.length) {
                if (span.equals(spans[i])) {
                    return true;
                }
                i++;
            }
        }
        return false;
    }

    static List<AccessibilityActionCompat> getActionList(View view) {
        List<AccessibilityActionCompat> actions = (List) view.getTag(C0020R.C0022id.tag_accessibility_actions);
        return actions == null ? Collections.emptyList() : actions;
    }
}
