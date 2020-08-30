package com.google.android.material.textfield;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewParent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import androidx.appcompat.widget.AppCompatEditText;
import com.google.android.material.C0078R;

public class TextInputEditText extends AppCompatEditText {
    public TextInputEditText(Context context) {
        this(context, null);
    }

    public TextInputEditText(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.editTextStyle);
    }

    public TextInputEditText(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    public CharSequence getHint() {
        TextInputLayout layout = getTextInputLayout();
        if (layout == null || !layout.isProvidingHint()) {
            return super.getHint();
        }
        return layout.getHint();
    }

    public InputConnection onCreateInputConnection(EditorInfo outAttrs) {
        InputConnection ic = super.onCreateInputConnection(outAttrs);
        if (ic != null && outAttrs.hintText == null) {
            outAttrs.hintText = getHintFromLayout();
        }
        return ic;
    }

    private TextInputLayout getTextInputLayout() {
        for (ViewParent parent = getParent(); parent instanceof View; parent = parent.getParent()) {
            if (parent instanceof TextInputLayout) {
                return (TextInputLayout) parent;
            }
        }
        return null;
    }

    private CharSequence getHintFromLayout() {
        TextInputLayout layout = getTextInputLayout();
        if (layout != null) {
            return layout.getHint();
        }
        return null;
    }
}
