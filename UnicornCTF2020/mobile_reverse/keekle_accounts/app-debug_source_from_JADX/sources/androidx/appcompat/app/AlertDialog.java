package androidx.appcompat.app;

import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.DialogInterface.OnKeyListener;
import android.content.DialogInterface.OnMultiChoiceClickListener;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Message;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.KeyEvent;
import android.view.View;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.Button;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.appcompat.C0003R;
import androidx.appcompat.app.AlertController.AlertParams;

public class AlertDialog extends AppCompatDialog implements DialogInterface {
    static final int LAYOUT_HINT_NONE = 0;
    static final int LAYOUT_HINT_SIDE = 1;
    final AlertController mAlert;

    public static class Builder {

        /* renamed from: P */
        private final AlertParams f12P;
        private final int mTheme;

        public Builder(Context context) {
            this(context, AlertDialog.resolveDialogTheme(context, 0));
        }

        public Builder(Context context, int themeResId) {
            this.f12P = new AlertParams(new ContextThemeWrapper(context, AlertDialog.resolveDialogTheme(context, themeResId)));
            this.mTheme = themeResId;
        }

        public Context getContext() {
            return this.f12P.mContext;
        }

        public Builder setTitle(int titleId) {
            AlertParams alertParams = this.f12P;
            alertParams.mTitle = alertParams.mContext.getText(titleId);
            return this;
        }

        public Builder setTitle(CharSequence title) {
            this.f12P.mTitle = title;
            return this;
        }

        public Builder setCustomTitle(View customTitleView) {
            this.f12P.mCustomTitleView = customTitleView;
            return this;
        }

        public Builder setMessage(int messageId) {
            AlertParams alertParams = this.f12P;
            alertParams.mMessage = alertParams.mContext.getText(messageId);
            return this;
        }

        public Builder setMessage(CharSequence message) {
            this.f12P.mMessage = message;
            return this;
        }

        public Builder setIcon(int iconId) {
            this.f12P.mIconId = iconId;
            return this;
        }

        public Builder setIcon(Drawable icon) {
            this.f12P.mIcon = icon;
            return this;
        }

        public Builder setIconAttribute(int attrId) {
            TypedValue out = new TypedValue();
            this.f12P.mContext.getTheme().resolveAttribute(attrId, out, true);
            this.f12P.mIconId = out.resourceId;
            return this;
        }

        public Builder setPositiveButton(int textId, OnClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mPositiveButtonText = alertParams.mContext.getText(textId);
            this.f12P.mPositiveButtonListener = listener;
            return this;
        }

        public Builder setPositiveButton(CharSequence text, OnClickListener listener) {
            this.f12P.mPositiveButtonText = text;
            this.f12P.mPositiveButtonListener = listener;
            return this;
        }

        public Builder setPositiveButtonIcon(Drawable icon) {
            this.f12P.mPositiveButtonIcon = icon;
            return this;
        }

        public Builder setNegativeButton(int textId, OnClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mNegativeButtonText = alertParams.mContext.getText(textId);
            this.f12P.mNegativeButtonListener = listener;
            return this;
        }

        public Builder setNegativeButton(CharSequence text, OnClickListener listener) {
            this.f12P.mNegativeButtonText = text;
            this.f12P.mNegativeButtonListener = listener;
            return this;
        }

        public Builder setNegativeButtonIcon(Drawable icon) {
            this.f12P.mNegativeButtonIcon = icon;
            return this;
        }

        public Builder setNeutralButton(int textId, OnClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mNeutralButtonText = alertParams.mContext.getText(textId);
            this.f12P.mNeutralButtonListener = listener;
            return this;
        }

        public Builder setNeutralButton(CharSequence text, OnClickListener listener) {
            this.f12P.mNeutralButtonText = text;
            this.f12P.mNeutralButtonListener = listener;
            return this;
        }

        public Builder setNeutralButtonIcon(Drawable icon) {
            this.f12P.mNeutralButtonIcon = icon;
            return this;
        }

        public Builder setCancelable(boolean cancelable) {
            this.f12P.mCancelable = cancelable;
            return this;
        }

        public Builder setOnCancelListener(OnCancelListener onCancelListener) {
            this.f12P.mOnCancelListener = onCancelListener;
            return this;
        }

        public Builder setOnDismissListener(OnDismissListener onDismissListener) {
            this.f12P.mOnDismissListener = onDismissListener;
            return this;
        }

        public Builder setOnKeyListener(OnKeyListener onKeyListener) {
            this.f12P.mOnKeyListener = onKeyListener;
            return this;
        }

        public Builder setItems(int itemsId, OnClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mItems = alertParams.mContext.getResources().getTextArray(itemsId);
            this.f12P.mOnClickListener = listener;
            return this;
        }

        public Builder setItems(CharSequence[] items, OnClickListener listener) {
            this.f12P.mItems = items;
            this.f12P.mOnClickListener = listener;
            return this;
        }

        public Builder setAdapter(ListAdapter adapter, OnClickListener listener) {
            this.f12P.mAdapter = adapter;
            this.f12P.mOnClickListener = listener;
            return this;
        }

        public Builder setCursor(Cursor cursor, OnClickListener listener, String labelColumn) {
            this.f12P.mCursor = cursor;
            this.f12P.mLabelColumn = labelColumn;
            this.f12P.mOnClickListener = listener;
            return this;
        }

        public Builder setMultiChoiceItems(int itemsId, boolean[] checkedItems, OnMultiChoiceClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mItems = alertParams.mContext.getResources().getTextArray(itemsId);
            this.f12P.mOnCheckboxClickListener = listener;
            this.f12P.mCheckedItems = checkedItems;
            this.f12P.mIsMultiChoice = true;
            return this;
        }

        public Builder setMultiChoiceItems(CharSequence[] items, boolean[] checkedItems, OnMultiChoiceClickListener listener) {
            this.f12P.mItems = items;
            this.f12P.mOnCheckboxClickListener = listener;
            this.f12P.mCheckedItems = checkedItems;
            this.f12P.mIsMultiChoice = true;
            return this;
        }

        public Builder setMultiChoiceItems(Cursor cursor, String isCheckedColumn, String labelColumn, OnMultiChoiceClickListener listener) {
            this.f12P.mCursor = cursor;
            this.f12P.mOnCheckboxClickListener = listener;
            this.f12P.mIsCheckedColumn = isCheckedColumn;
            this.f12P.mLabelColumn = labelColumn;
            this.f12P.mIsMultiChoice = true;
            return this;
        }

        public Builder setSingleChoiceItems(int itemsId, int checkedItem, OnClickListener listener) {
            AlertParams alertParams = this.f12P;
            alertParams.mItems = alertParams.mContext.getResources().getTextArray(itemsId);
            this.f12P.mOnClickListener = listener;
            this.f12P.mCheckedItem = checkedItem;
            this.f12P.mIsSingleChoice = true;
            return this;
        }

        public Builder setSingleChoiceItems(Cursor cursor, int checkedItem, String labelColumn, OnClickListener listener) {
            this.f12P.mCursor = cursor;
            this.f12P.mOnClickListener = listener;
            this.f12P.mCheckedItem = checkedItem;
            this.f12P.mLabelColumn = labelColumn;
            this.f12P.mIsSingleChoice = true;
            return this;
        }

        public Builder setSingleChoiceItems(CharSequence[] items, int checkedItem, OnClickListener listener) {
            this.f12P.mItems = items;
            this.f12P.mOnClickListener = listener;
            this.f12P.mCheckedItem = checkedItem;
            this.f12P.mIsSingleChoice = true;
            return this;
        }

        public Builder setSingleChoiceItems(ListAdapter adapter, int checkedItem, OnClickListener listener) {
            this.f12P.mAdapter = adapter;
            this.f12P.mOnClickListener = listener;
            this.f12P.mCheckedItem = checkedItem;
            this.f12P.mIsSingleChoice = true;
            return this;
        }

        public Builder setOnItemSelectedListener(OnItemSelectedListener listener) {
            this.f12P.mOnItemSelectedListener = listener;
            return this;
        }

        public Builder setView(int layoutResId) {
            this.f12P.mView = null;
            this.f12P.mViewLayoutResId = layoutResId;
            this.f12P.mViewSpacingSpecified = false;
            return this;
        }

        public Builder setView(View view) {
            this.f12P.mView = view;
            this.f12P.mViewLayoutResId = 0;
            this.f12P.mViewSpacingSpecified = false;
            return this;
        }

        @Deprecated
        public Builder setView(View view, int viewSpacingLeft, int viewSpacingTop, int viewSpacingRight, int viewSpacingBottom) {
            this.f12P.mView = view;
            this.f12P.mViewLayoutResId = 0;
            this.f12P.mViewSpacingSpecified = true;
            this.f12P.mViewSpacingLeft = viewSpacingLeft;
            this.f12P.mViewSpacingTop = viewSpacingTop;
            this.f12P.mViewSpacingRight = viewSpacingRight;
            this.f12P.mViewSpacingBottom = viewSpacingBottom;
            return this;
        }

        @Deprecated
        public Builder setInverseBackgroundForced(boolean useInverseBackground) {
            this.f12P.mForceInverseBackground = useInverseBackground;
            return this;
        }

        public Builder setRecycleOnMeasureEnabled(boolean enabled) {
            this.f12P.mRecycleOnMeasure = enabled;
            return this;
        }

        public AlertDialog create() {
            AlertDialog dialog = new AlertDialog(this.f12P.mContext, this.mTheme);
            this.f12P.apply(dialog.mAlert);
            dialog.setCancelable(this.f12P.mCancelable);
            if (this.f12P.mCancelable) {
                dialog.setCanceledOnTouchOutside(true);
            }
            dialog.setOnCancelListener(this.f12P.mOnCancelListener);
            dialog.setOnDismissListener(this.f12P.mOnDismissListener);
            if (this.f12P.mOnKeyListener != null) {
                dialog.setOnKeyListener(this.f12P.mOnKeyListener);
            }
            return dialog;
        }

        public AlertDialog show() {
            AlertDialog dialog = create();
            dialog.show();
            return dialog;
        }
    }

    protected AlertDialog(Context context) {
        this(context, 0);
    }

    protected AlertDialog(Context context, int themeResId) {
        super(context, resolveDialogTheme(context, themeResId));
        this.mAlert = new AlertController(getContext(), this, getWindow());
    }

    protected AlertDialog(Context context, boolean cancelable, OnCancelListener cancelListener) {
        this(context, 0);
        setCancelable(cancelable);
        setOnCancelListener(cancelListener);
    }

    static int resolveDialogTheme(Context context, int resid) {
        if (((resid >>> 24) & 255) >= 1) {
            return resid;
        }
        TypedValue outValue = new TypedValue();
        context.getTheme().resolveAttribute(C0003R.attr.alertDialogTheme, outValue, true);
        return outValue.resourceId;
    }

    public Button getButton(int whichButton) {
        return this.mAlert.getButton(whichButton);
    }

    public ListView getListView() {
        return this.mAlert.getListView();
    }

    public void setTitle(CharSequence title) {
        super.setTitle(title);
        this.mAlert.setTitle(title);
    }

    public void setCustomTitle(View customTitleView) {
        this.mAlert.setCustomTitle(customTitleView);
    }

    public void setMessage(CharSequence message) {
        this.mAlert.setMessage(message);
    }

    public void setView(View view) {
        this.mAlert.setView(view);
    }

    public void setView(View view, int viewSpacingLeft, int viewSpacingTop, int viewSpacingRight, int viewSpacingBottom) {
        this.mAlert.setView(view, viewSpacingLeft, viewSpacingTop, viewSpacingRight, viewSpacingBottom);
    }

    /* access modifiers changed from: 0000 */
    public void setButtonPanelLayoutHint(int layoutHint) {
        this.mAlert.setButtonPanelLayoutHint(layoutHint);
    }

    public void setButton(int whichButton, CharSequence text, Message msg) {
        this.mAlert.setButton(whichButton, text, null, msg, null);
    }

    public void setButton(int whichButton, CharSequence text, OnClickListener listener) {
        this.mAlert.setButton(whichButton, text, listener, null, null);
    }

    public void setButton(int whichButton, CharSequence text, Drawable icon, OnClickListener listener) {
        this.mAlert.setButton(whichButton, text, listener, null, icon);
    }

    public void setIcon(int resId) {
        this.mAlert.setIcon(resId);
    }

    public void setIcon(Drawable icon) {
        this.mAlert.setIcon(icon);
    }

    public void setIconAttribute(int attrId) {
        TypedValue out = new TypedValue();
        getContext().getTheme().resolveAttribute(attrId, out, true);
        this.mAlert.setIcon(out.resourceId);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.mAlert.installContent();
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (this.mAlert.onKeyDown(keyCode, event)) {
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (this.mAlert.onKeyUp(keyCode, event)) {
            return true;
        }
        return super.onKeyUp(keyCode, event);
    }
}
