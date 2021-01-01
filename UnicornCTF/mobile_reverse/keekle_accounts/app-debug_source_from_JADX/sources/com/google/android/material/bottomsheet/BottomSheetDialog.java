package com.google.android.material.bottomsheet;

import android.content.Context;
import android.content.DialogInterface.OnCancelListener;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;
import android.widget.FrameLayout;
import androidx.appcompat.app.AppCompatDialog;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.AccessibilityDelegateCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.C0078R;
import com.google.android.material.bottomsheet.BottomSheetBehavior.BottomSheetCallback;

public class BottomSheetDialog extends AppCompatDialog {
    private BottomSheetBehavior<FrameLayout> behavior;
    private BottomSheetCallback bottomSheetCallback;
    boolean cancelable;
    private boolean canceledOnTouchOutside;
    private boolean canceledOnTouchOutsideSet;

    public BottomSheetDialog(Context context) {
        this(context, 0);
    }

    public BottomSheetDialog(Context context, int theme) {
        super(context, getThemeResId(context, theme));
        this.cancelable = true;
        this.canceledOnTouchOutside = true;
        this.bottomSheetCallback = new BottomSheetCallback() {
            public void onStateChanged(View bottomSheet, int newState) {
                if (newState == 5) {
                    BottomSheetDialog.this.cancel();
                }
            }

            public void onSlide(View bottomSheet, float slideOffset) {
            }
        };
        supportRequestWindowFeature(1);
    }

    protected BottomSheetDialog(Context context, boolean cancelable2, OnCancelListener cancelListener) {
        super(context, cancelable2, cancelListener);
        this.cancelable = true;
        this.canceledOnTouchOutside = true;
        this.bottomSheetCallback = new BottomSheetCallback() {
            public void onStateChanged(View bottomSheet, int newState) {
                if (newState == 5) {
                    BottomSheetDialog.this.cancel();
                }
            }

            public void onSlide(View bottomSheet, float slideOffset) {
            }
        };
        supportRequestWindowFeature(1);
        this.cancelable = cancelable2;
    }

    public void setContentView(int layoutResId) {
        super.setContentView(wrapInBottomSheet(layoutResId, null, null));
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Window window = getWindow();
        if (window != null) {
            if (VERSION.SDK_INT >= 21) {
                window.clearFlags(67108864);
                window.addFlags(Integer.MIN_VALUE);
            }
            window.setLayout(-1, -1);
        }
    }

    public void setContentView(View view) {
        super.setContentView(wrapInBottomSheet(0, view, null));
    }

    public void setContentView(View view, LayoutParams params) {
        super.setContentView(wrapInBottomSheet(0, view, params));
    }

    public void setCancelable(boolean cancelable2) {
        super.setCancelable(cancelable2);
        if (this.cancelable != cancelable2) {
            this.cancelable = cancelable2;
            BottomSheetBehavior<FrameLayout> bottomSheetBehavior = this.behavior;
            if (bottomSheetBehavior != null) {
                bottomSheetBehavior.setHideable(cancelable2);
            }
        }
    }

    /* access modifiers changed from: protected */
    public void onStart() {
        super.onStart();
        BottomSheetBehavior<FrameLayout> bottomSheetBehavior = this.behavior;
        if (bottomSheetBehavior != null && bottomSheetBehavior.getState() == 5) {
            this.behavior.setState(4);
        }
    }

    public void setCanceledOnTouchOutside(boolean cancel) {
        super.setCanceledOnTouchOutside(cancel);
        if (cancel && !this.cancelable) {
            this.cancelable = true;
        }
        this.canceledOnTouchOutside = cancel;
        this.canceledOnTouchOutsideSet = true;
    }

    private View wrapInBottomSheet(int layoutResId, View view, LayoutParams params) {
        FrameLayout container = (FrameLayout) View.inflate(getContext(), C0078R.layout.design_bottom_sheet_dialog, null);
        CoordinatorLayout coordinator = (CoordinatorLayout) container.findViewById(C0078R.C0080id.coordinator);
        if (layoutResId != 0 && view == null) {
            view = getLayoutInflater().inflate(layoutResId, coordinator, false);
        }
        FrameLayout bottomSheet = (FrameLayout) coordinator.findViewById(C0078R.C0080id.design_bottom_sheet);
        BottomSheetBehavior<FrameLayout> from = BottomSheetBehavior.from(bottomSheet);
        this.behavior = from;
        from.setBottomSheetCallback(this.bottomSheetCallback);
        this.behavior.setHideable(this.cancelable);
        if (params == null) {
            bottomSheet.addView(view);
        } else {
            bottomSheet.addView(view, params);
        }
        coordinator.findViewById(C0078R.C0080id.touch_outside).setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                if (BottomSheetDialog.this.cancelable && BottomSheetDialog.this.isShowing() && BottomSheetDialog.this.shouldWindowCloseOnTouchOutside()) {
                    BottomSheetDialog.this.cancel();
                }
            }
        });
        ViewCompat.setAccessibilityDelegate(bottomSheet, new AccessibilityDelegateCompat() {
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                if (BottomSheetDialog.this.cancelable) {
                    info.addAction(1048576);
                    info.setDismissable(true);
                    return;
                }
                info.setDismissable(false);
            }

            public boolean performAccessibilityAction(View host, int action, Bundle args) {
                if (action != 1048576 || !BottomSheetDialog.this.cancelable) {
                    return super.performAccessibilityAction(host, action, args);
                }
                BottomSheetDialog.this.cancel();
                return true;
            }
        });
        bottomSheet.setOnTouchListener(new OnTouchListener() {
            public boolean onTouch(View view, MotionEvent event) {
                return true;
            }
        });
        return container;
    }

    /* access modifiers changed from: 0000 */
    public boolean shouldWindowCloseOnTouchOutside() {
        if (!this.canceledOnTouchOutsideSet) {
            TypedArray a = getContext().obtainStyledAttributes(new int[]{16843611});
            this.canceledOnTouchOutside = a.getBoolean(0, true);
            a.recycle();
            this.canceledOnTouchOutsideSet = true;
        }
        return this.canceledOnTouchOutside;
    }

    private static int getThemeResId(Context context, int themeId) {
        if (themeId != 0) {
            return themeId;
        }
        TypedValue outValue = new TypedValue();
        if (context.getTheme().resolveAttribute(C0078R.attr.bottomSheetDialogTheme, outValue, true)) {
            return outValue.resourceId;
        }
        return C0078R.style.Theme_Design_Light_BottomSheetDialog;
    }
}
