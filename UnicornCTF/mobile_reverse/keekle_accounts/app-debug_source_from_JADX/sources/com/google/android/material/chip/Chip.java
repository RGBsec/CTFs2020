package com.google.android.material.chip;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Outline;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextUtils.TruncateAt;
import android.util.AttributeSet;
import android.util.Log;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.PointerIcon;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewOutlineProvider;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.TextView.BufferType;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.core.content.res.ResourcesCompat.FontCallback;
import androidx.core.text.BidiFormatter;
import androidx.core.view.PointerIconCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat.AccessibilityActionCompat;
import androidx.customview.widget.ExploreByTouchHelper;
import com.google.android.material.C0078R;
import com.google.android.material.animation.MotionSpec;
import com.google.android.material.chip.ChipDrawable.Delegate;
import com.google.android.material.resources.TextAppearance;
import com.google.android.material.ripple.RippleUtils;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

public class Chip extends AppCompatCheckBox implements Delegate {
    private static final int CLOSE_ICON_VIRTUAL_ID = 0;
    /* access modifiers changed from: private */
    public static final Rect EMPTY_BOUNDS = new Rect();
    private static final String NAMESPACE_ANDROID = "http://schemas.android.com/apk/res/android";
    private static final int[] SELECTED_STATE = {16842913};
    private static final String TAG = "Chip";
    /* access modifiers changed from: private */
    public ChipDrawable chipDrawable;
    private boolean closeIconFocused;
    private boolean closeIconHovered;
    private boolean closeIconPressed;
    private boolean deferredCheckedValue;
    private int focusedVirtualView;
    private final FontCallback fontCallback;
    private OnCheckedChangeListener onCheckedChangeListenerInternal;
    private OnClickListener onCloseIconClickListener;
    private final Rect rect;
    private final RectF rectF;
    private RippleDrawable ripple;
    private final ChipTouchHelper touchHelper;

    private class ChipTouchHelper extends ExploreByTouchHelper {
        ChipTouchHelper(Chip view) {
            super(view);
        }

        /* access modifiers changed from: protected */
        public int getVirtualViewAt(float x, float y) {
            return (!Chip.this.hasCloseIcon() || !Chip.this.getCloseIconTouchBounds().contains(x, y)) ? -1 : 0;
        }

        /* access modifiers changed from: protected */
        public void getVisibleVirtualViews(List<Integer> virtualViewIds) {
            if (Chip.this.hasCloseIcon()) {
                virtualViewIds.add(Integer.valueOf(0));
            }
        }

        /* access modifiers changed from: protected */
        public void onPopulateNodeForVirtualView(int virtualViewId, AccessibilityNodeInfoCompat node) {
            CharSequence charSequence = "";
            if (Chip.this.hasCloseIcon()) {
                CharSequence closeIconContentDescription = Chip.this.getCloseIconContentDescription();
                if (closeIconContentDescription != null) {
                    node.setContentDescription(closeIconContentDescription);
                } else {
                    CharSequence chipText = Chip.this.getText();
                    Context context = Chip.this.getContext();
                    int i = C0078R.string.mtrl_chip_close_icon_content_description;
                    Object[] objArr = new Object[1];
                    if (!TextUtils.isEmpty(chipText)) {
                        charSequence = chipText;
                    }
                    objArr[0] = charSequence;
                    node.setContentDescription(context.getString(i, objArr).trim());
                }
                node.setBoundsInParent(Chip.this.getCloseIconTouchBoundsInt());
                node.addAction(AccessibilityActionCompat.ACTION_CLICK);
                node.setEnabled(Chip.this.isEnabled());
                return;
            }
            node.setContentDescription(charSequence);
            node.setBoundsInParent(Chip.EMPTY_BOUNDS);
        }

        /* access modifiers changed from: protected */
        public void onPopulateNodeForHost(AccessibilityNodeInfoCompat node) {
            node.setCheckable(Chip.this.chipDrawable != null && Chip.this.chipDrawable.isCheckable());
            node.setClassName(Chip.class.getName());
            CharSequence chipText = Chip.this.getText();
            if (VERSION.SDK_INT >= 23) {
                node.setText(chipText);
            } else {
                node.setContentDescription(chipText);
            }
        }

        /* access modifiers changed from: protected */
        public boolean onPerformActionForVirtualView(int virtualViewId, int action, Bundle arguments) {
            if (action == 16 && virtualViewId == 0) {
                return Chip.this.performCloseIconClick();
            }
            return false;
        }
    }

    public Chip(Context context) {
        this(context, null);
    }

    public Chip(Context context, AttributeSet attrs) {
        this(context, attrs, C0078R.attr.chipStyle);
    }

    public Chip(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.focusedVirtualView = Integer.MIN_VALUE;
        this.rect = new Rect();
        this.rectF = new RectF();
        this.fontCallback = new FontCallback() {
            public void onFontRetrieved(Typeface typeface) {
                Chip chip = Chip.this;
                chip.setText(chip.getText());
                Chip.this.requestLayout();
                Chip.this.invalidate();
            }

            public void onFontRetrievalFailed(int reason) {
            }
        };
        validateAttributes(attrs);
        ChipDrawable drawable = ChipDrawable.createFromAttributes(context, attrs, defStyleAttr, C0078R.style.Widget_MaterialComponents_Chip_Action);
        setChipDrawable(drawable);
        ChipTouchHelper chipTouchHelper = new ChipTouchHelper(this);
        this.touchHelper = chipTouchHelper;
        ViewCompat.setAccessibilityDelegate(this, chipTouchHelper);
        initOutlineProvider();
        setChecked(this.deferredCheckedValue);
        drawable.setShouldDrawText(false);
        setText(drawable.getText());
        setEllipsize(drawable.getEllipsize());
        setIncludeFontPadding(false);
        if (getTextAppearance() != null) {
            updateTextPaintDrawState(getTextAppearance());
        }
        setSingleLine();
        setGravity(8388627);
        updatePaddingInternal();
    }

    private void updatePaddingInternal() {
        if (!TextUtils.isEmpty(getText())) {
            ChipDrawable chipDrawable2 = this.chipDrawable;
            if (chipDrawable2 != null) {
                float paddingEnd = chipDrawable2.getChipStartPadding() + this.chipDrawable.getChipEndPadding() + this.chipDrawable.getTextStartPadding() + this.chipDrawable.getTextEndPadding();
                if ((this.chipDrawable.isChipIconVisible() && this.chipDrawable.getChipIcon() != null) || (this.chipDrawable.getCheckedIcon() != null && this.chipDrawable.isCheckedIconVisible() && isChecked())) {
                    paddingEnd += this.chipDrawable.getIconStartPadding() + this.chipDrawable.getIconEndPadding() + this.chipDrawable.getChipIconSize();
                }
                if (this.chipDrawable.isCloseIconVisible() && this.chipDrawable.getCloseIcon() != null) {
                    paddingEnd += this.chipDrawable.getCloseIconStartPadding() + this.chipDrawable.getCloseIconEndPadding() + this.chipDrawable.getCloseIconSize();
                }
                if (((float) ViewCompat.getPaddingEnd(this)) != paddingEnd) {
                    ViewCompat.setPaddingRelative(this, ViewCompat.getPaddingStart(this), getPaddingTop(), (int) paddingEnd, getPaddingBottom());
                }
            }
        }
    }

    private void validateAttributes(AttributeSet attributeSet) {
        if (attributeSet != null) {
            String str = NAMESPACE_ANDROID;
            if (attributeSet.getAttributeValue(str, "background") != null) {
                throw new UnsupportedOperationException("Do not set the background; Chip manages its own background drawable.");
            } else if (attributeSet.getAttributeValue(str, "drawableLeft") != null) {
                throw new UnsupportedOperationException("Please set left drawable using R.attr#chipIcon.");
            } else if (attributeSet.getAttributeValue(str, "drawableStart") == null) {
                String str2 = "Please set end drawable using R.attr#closeIcon.";
                if (attributeSet.getAttributeValue(str, "drawableEnd") != null) {
                    throw new UnsupportedOperationException(str2);
                } else if (attributeSet.getAttributeValue(str, "drawableRight") != null) {
                    throw new UnsupportedOperationException(str2);
                } else if (attributeSet.getAttributeBooleanValue(str, "singleLine", true) && attributeSet.getAttributeIntValue(str, "lines", 1) == 1 && attributeSet.getAttributeIntValue(str, "minLines", 1) == 1 && attributeSet.getAttributeIntValue(str, "maxLines", 1) == 1) {
                    if (attributeSet.getAttributeIntValue(str, "gravity", 8388627) != 8388627) {
                        Log.w(TAG, "Chip text must be vertically center and start aligned");
                    }
                } else {
                    throw new UnsupportedOperationException("Chip does not support multi-line text");
                }
            } else {
                throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
            }
        }
    }

    private void initOutlineProvider() {
        if (VERSION.SDK_INT >= 21) {
            setOutlineProvider(new ViewOutlineProvider() {
                public void getOutline(View view, Outline outline) {
                    if (Chip.this.chipDrawable != null) {
                        Chip.this.chipDrawable.getOutline(outline);
                    } else {
                        outline.setAlpha(0.0f);
                    }
                }
            });
        }
    }

    public Drawable getChipDrawable() {
        return this.chipDrawable;
    }

    public void setChipDrawable(ChipDrawable drawable) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != drawable) {
            unapplyChipDrawable(chipDrawable2);
            this.chipDrawable = drawable;
            applyChipDrawable(drawable);
            if (RippleUtils.USE_FRAMEWORK_RIPPLE) {
                this.ripple = new RippleDrawable(RippleUtils.convertToRippleDrawableColor(this.chipDrawable.getRippleColor()), this.chipDrawable, null);
                this.chipDrawable.setUseCompatRipple(false);
                ViewCompat.setBackground(this, this.ripple);
                return;
            }
            this.chipDrawable.setUseCompatRipple(true);
            ViewCompat.setBackground(this, this.chipDrawable);
        }
    }

    private void unapplyChipDrawable(ChipDrawable chipDrawable2) {
        if (chipDrawable2 != null) {
            chipDrawable2.setDelegate(null);
        }
    }

    private void applyChipDrawable(ChipDrawable chipDrawable2) {
        chipDrawable2.setDelegate(this);
    }

    /* access modifiers changed from: protected */
    public int[] onCreateDrawableState(int extraSpace) {
        int[] state = super.onCreateDrawableState(extraSpace + 1);
        if (isChecked()) {
            mergeDrawableStates(state, SELECTED_STATE);
        }
        return state;
    }

    /* access modifiers changed from: protected */
    public void onDraw(Canvas canvas) {
        if (!TextUtils.isEmpty(getText())) {
            ChipDrawable chipDrawable2 = this.chipDrawable;
            if (chipDrawable2 != null && !chipDrawable2.shouldDrawText()) {
                int saveCount = canvas.save();
                canvas.translate(calculateTextOffsetFromStart(this.chipDrawable), 0.0f);
                super.onDraw(canvas);
                canvas.restoreToCount(saveCount);
                return;
            }
        }
        super.onDraw(canvas);
    }

    public void setGravity(int gravity) {
        if (gravity != 8388627) {
            Log.w(TAG, "Chip text must be vertically center and start aligned");
        } else {
            super.setGravity(gravity);
        }
    }

    private float calculateTextOffsetFromStart(ChipDrawable chipDrawable2) {
        float offsetFromStart = getChipStartPadding() + chipDrawable2.calculateChipIconWidth() + getTextStartPadding();
        if (ViewCompat.getLayoutDirection(this) == 0) {
            return offsetFromStart;
        }
        return -offsetFromStart;
    }

    public void setBackgroundTintList(ColorStateList tint) {
        throw new UnsupportedOperationException("Do not set the background tint list; Chip manages its own background drawable.");
    }

    public void setBackgroundTintMode(Mode tintMode) {
        throw new UnsupportedOperationException("Do not set the background tint mode; Chip manages its own background drawable.");
    }

    public void setBackgroundColor(int color) {
        throw new UnsupportedOperationException("Do not set the background color; Chip manages its own background drawable.");
    }

    public void setBackgroundResource(int resid) {
        throw new UnsupportedOperationException("Do not set the background resource; Chip manages its own background drawable.");
    }

    public void setBackground(Drawable background) {
        if (background == this.chipDrawable || background == this.ripple) {
            super.setBackground(background);
            return;
        }
        throw new UnsupportedOperationException("Do not set the background; Chip manages its own background drawable.");
    }

    public void setBackgroundDrawable(Drawable background) {
        if (background == this.chipDrawable || background == this.ripple) {
            super.setBackgroundDrawable(background);
            return;
        }
        throw new UnsupportedOperationException("Do not set the background drawable; Chip manages its own background drawable.");
    }

    public void setCompoundDrawables(Drawable left, Drawable top, Drawable right, Drawable bottom) {
        if (left != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        } else if (right == null) {
            super.setCompoundDrawables(left, top, right, bottom);
        } else {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
    }

    public void setCompoundDrawablesWithIntrinsicBounds(int left, int top, int right, int bottom) {
        if (left != 0) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        } else if (right == 0) {
            super.setCompoundDrawablesWithIntrinsicBounds(left, top, right, bottom);
        } else {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
    }

    public void setCompoundDrawablesWithIntrinsicBounds(Drawable left, Drawable top, Drawable right, Drawable bottom) {
        if (left != null) {
            throw new UnsupportedOperationException("Please set left drawable using R.attr#chipIcon.");
        } else if (right == null) {
            super.setCompoundDrawablesWithIntrinsicBounds(left, top, right, bottom);
        } else {
            throw new UnsupportedOperationException("Please set right drawable using R.attr#closeIcon.");
        }
    }

    public void setCompoundDrawablesRelative(Drawable start, Drawable top, Drawable end, Drawable bottom) {
        if (start != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        } else if (end == null) {
            super.setCompoundDrawablesRelative(start, top, end, bottom);
        } else {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
    }

    public void setCompoundDrawablesRelativeWithIntrinsicBounds(int start, int top, int end, int bottom) {
        if (start != 0) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        } else if (end == 0) {
            super.setCompoundDrawablesRelativeWithIntrinsicBounds(start, top, end, bottom);
        } else {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
    }

    public void setCompoundDrawablesRelativeWithIntrinsicBounds(Drawable start, Drawable top, Drawable end, Drawable bottom) {
        if (start != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        } else if (end == null) {
            super.setCompoundDrawablesRelativeWithIntrinsicBounds(start, top, end, bottom);
        } else {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
    }

    public TruncateAt getEllipsize() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getEllipsize();
        }
        return null;
    }

    public void setEllipsize(TruncateAt where) {
        if (this.chipDrawable != null) {
            if (where != TruncateAt.MARQUEE) {
                super.setEllipsize(where);
                ChipDrawable chipDrawable2 = this.chipDrawable;
                if (chipDrawable2 != null) {
                    chipDrawable2.setEllipsize(where);
                }
                return;
            }
            throw new UnsupportedOperationException("Text within a chip are not allowed to scroll.");
        }
    }

    public void setSingleLine(boolean singleLine) {
        if (singleLine) {
            super.setSingleLine(singleLine);
            return;
        }
        throw new UnsupportedOperationException("Chip does not support multi-line text");
    }

    public void setLines(int lines) {
        if (lines <= 1) {
            super.setLines(lines);
            return;
        }
        throw new UnsupportedOperationException("Chip does not support multi-line text");
    }

    public void setMinLines(int minLines) {
        if (minLines <= 1) {
            super.setMinLines(minLines);
            return;
        }
        throw new UnsupportedOperationException("Chip does not support multi-line text");
    }

    public void setMaxLines(int maxLines) {
        if (maxLines <= 1) {
            super.setMaxLines(maxLines);
            return;
        }
        throw new UnsupportedOperationException("Chip does not support multi-line text");
    }

    public void setMaxWidth(int maxWidth) {
        super.setMaxWidth(maxWidth);
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setMaxWidth(maxWidth);
        }
    }

    public void onChipDrawableSizeChange() {
        updatePaddingInternal();
        requestLayout();
        if (VERSION.SDK_INT >= 21) {
            invalidateOutline();
        }
    }

    public void setChecked(boolean checked) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 == null) {
            this.deferredCheckedValue = checked;
        } else if (chipDrawable2.isCheckable()) {
            boolean wasChecked = isChecked();
            super.setChecked(checked);
            if (wasChecked != checked) {
                OnCheckedChangeListener onCheckedChangeListener = this.onCheckedChangeListenerInternal;
                if (onCheckedChangeListener != null) {
                    onCheckedChangeListener.onCheckedChanged(this, checked);
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void setOnCheckedChangeListenerInternal(OnCheckedChangeListener listener) {
        this.onCheckedChangeListenerInternal = listener;
    }

    public void setOnCloseIconClickListener(OnClickListener listener) {
        this.onCloseIconClickListener = listener;
    }

    public boolean performCloseIconClick() {
        boolean result;
        playSoundEffect(0);
        OnClickListener onClickListener = this.onCloseIconClickListener;
        if (onClickListener != null) {
            onClickListener.onClick(this);
            result = true;
        } else {
            result = false;
        }
        this.touchHelper.sendEventForVirtualView(0, 1);
        return result;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:6:0x001f, code lost:
        if (r1 != 3) goto L_0x003f;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean onTouchEvent(android.view.MotionEvent r7) {
        /*
            r6 = this;
            r0 = 0
            int r1 = r7.getActionMasked()
            android.graphics.RectF r2 = r6.getCloseIconTouchBounds()
            float r3 = r7.getX()
            float r4 = r7.getY()
            boolean r2 = r2.contains(r3, r4)
            r3 = 0
            r4 = 1
            if (r1 == 0) goto L_0x0039
            if (r1 == r4) goto L_0x002d
            r5 = 2
            if (r1 == r5) goto L_0x0022
            r5 = 3
            if (r1 == r5) goto L_0x0035
            goto L_0x003f
        L_0x0022:
            boolean r5 = r6.closeIconPressed
            if (r5 == 0) goto L_0x003f
            if (r2 != 0) goto L_0x002b
            r6.setCloseIconPressed(r3)
        L_0x002b:
            r0 = 1
            goto L_0x003f
        L_0x002d:
            boolean r5 = r6.closeIconPressed
            if (r5 == 0) goto L_0x0035
            r6.performCloseIconClick()
            r0 = 1
        L_0x0035:
            r6.setCloseIconPressed(r3)
            goto L_0x003f
        L_0x0039:
            if (r2 == 0) goto L_0x003f
            r6.setCloseIconPressed(r4)
            r0 = 1
        L_0x003f:
            if (r0 != 0) goto L_0x0047
            boolean r5 = super.onTouchEvent(r7)
            if (r5 == 0) goto L_0x0048
        L_0x0047:
            r3 = r4
        L_0x0048:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.chip.Chip.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public boolean onHoverEvent(MotionEvent event) {
        int action = event.getActionMasked();
        if (action == 7) {
            setCloseIconHovered(getCloseIconTouchBounds().contains(event.getX(), event.getY()));
        } else if (action == 10) {
            setCloseIconHovered(false);
        }
        return super.onHoverEvent(event);
    }

    private boolean handleAccessibilityExit(MotionEvent event) {
        String str = "Unable to send Accessibility Exit event";
        String str2 = TAG;
        if (event.getAction() == 10) {
            try {
                Field f = ExploreByTouchHelper.class.getDeclaredField("mHoveredVirtualViewId");
                f.setAccessible(true);
                if (((Integer) f.get(this.touchHelper)).intValue() != Integer.MIN_VALUE) {
                    Method m = ExploreByTouchHelper.class.getDeclaredMethod("updateHoveredVirtualView", new Class[]{Integer.TYPE});
                    m.setAccessible(true);
                    m.invoke(this.touchHelper, new Object[]{Integer.valueOf(Integer.MIN_VALUE)});
                    return true;
                }
            } catch (NoSuchMethodException e) {
                Log.e(str2, str, e);
            } catch (IllegalAccessException e2) {
                Log.e(str2, str, e2);
            } catch (InvocationTargetException e3) {
                Log.e(str2, str, e3);
            } catch (NoSuchFieldException e4) {
                Log.e(str2, str, e4);
            }
        }
        return false;
    }

    /* access modifiers changed from: protected */
    public boolean dispatchHoverEvent(MotionEvent event) {
        return handleAccessibilityExit(event) || this.touchHelper.dispatchHoverEvent(event) || super.dispatchHoverEvent(event);
    }

    public boolean dispatchKeyEvent(KeyEvent event) {
        return this.touchHelper.dispatchKeyEvent(event) || super.dispatchKeyEvent(event);
    }

    /* access modifiers changed from: protected */
    public void onFocusChanged(boolean focused, int direction, Rect previouslyFocusedRect) {
        if (focused) {
            setFocusedVirtualView(-1);
        } else {
            setFocusedVirtualView(Integer.MIN_VALUE);
        }
        invalidate();
        super.onFocusChanged(focused, direction, previouslyFocusedRect);
        this.touchHelper.onFocusChanged(focused, direction, previouslyFocusedRect);
    }

    /* JADX WARNING: Removed duplicated region for block: B:32:0x0068  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean onKeyDown(int r7, android.view.KeyEvent r8) {
        /*
            r6 = this;
            r0 = 0
            int r1 = r8.getKeyCode()
            r2 = 61
            r3 = 1
            if (r1 == r2) goto L_0x0041
            r2 = 66
            if (r1 == r2) goto L_0x0031
            switch(r1) {
                case 21: goto L_0x0022;
                case 22: goto L_0x0012;
                case 23: goto L_0x0031;
                default: goto L_0x0011;
            }
        L_0x0011:
            goto L_0x006c
        L_0x0012:
            boolean r1 = r8.hasNoModifiers()
            if (r1 == 0) goto L_0x006c
            boolean r1 = com.google.android.material.internal.ViewUtils.isLayoutRtl(r6)
            r1 = r1 ^ r3
            boolean r0 = r6.moveFocus(r1)
            goto L_0x006c
        L_0x0022:
            boolean r1 = r8.hasNoModifiers()
            if (r1 == 0) goto L_0x006c
            boolean r1 = com.google.android.material.internal.ViewUtils.isLayoutRtl(r6)
            boolean r0 = r6.moveFocus(r1)
            goto L_0x006c
        L_0x0031:
            int r1 = r6.focusedVirtualView
            r2 = -1
            if (r1 == r2) goto L_0x003d
            if (r1 == 0) goto L_0x0039
            goto L_0x006c
        L_0x0039:
            r6.performCloseIconClick()
            return r3
        L_0x003d:
            r6.performClick()
            return r3
        L_0x0041:
            r1 = 0
            boolean r2 = r8.hasNoModifiers()
            if (r2 == 0) goto L_0x004a
            r1 = 2
            goto L_0x0051
        L_0x004a:
            boolean r2 = r8.hasModifiers(r3)
            if (r2 == 0) goto L_0x0051
            r1 = 1
        L_0x0051:
            if (r1 == 0) goto L_0x006c
            android.view.ViewParent r2 = r6.getParent()
            r4 = r6
        L_0x0058:
            android.view.View r4 = r4.focusSearch(r1)
            if (r4 == 0) goto L_0x0066
            if (r4 == r6) goto L_0x0066
            android.view.ViewParent r5 = r4.getParent()
            if (r5 == r2) goto L_0x0058
        L_0x0066:
            if (r4 == 0) goto L_0x006c
            r4.requestFocus()
            return r3
        L_0x006c:
            if (r0 == 0) goto L_0x0072
            r6.invalidate()
            return r3
        L_0x0072:
            boolean r1 = super.onKeyDown(r7, r8)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.chip.Chip.onKeyDown(int, android.view.KeyEvent):boolean");
    }

    private boolean moveFocus(boolean positive) {
        ensureFocus();
        if (positive) {
            if (this.focusedVirtualView != -1) {
                return false;
            }
            setFocusedVirtualView(0);
            return true;
        } else if (this.focusedVirtualView != 0) {
            return false;
        } else {
            setFocusedVirtualView(-1);
            return true;
        }
    }

    private void ensureFocus() {
        if (this.focusedVirtualView == Integer.MIN_VALUE) {
            setFocusedVirtualView(-1);
        }
    }

    public void getFocusedRect(Rect r) {
        if (this.focusedVirtualView == 0) {
            r.set(getCloseIconTouchBoundsInt());
        } else {
            super.getFocusedRect(r);
        }
    }

    private void setFocusedVirtualView(int virtualView) {
        int i = this.focusedVirtualView;
        if (i != virtualView) {
            if (i == 0) {
                setCloseIconFocused(false);
            }
            this.focusedVirtualView = virtualView;
            if (virtualView == 0) {
                setCloseIconFocused(true);
            }
        }
    }

    private void setCloseIconPressed(boolean pressed) {
        if (this.closeIconPressed != pressed) {
            this.closeIconPressed = pressed;
            refreshDrawableState();
        }
    }

    private void setCloseIconHovered(boolean hovered) {
        if (this.closeIconHovered != hovered) {
            this.closeIconHovered = hovered;
            refreshDrawableState();
        }
    }

    private void setCloseIconFocused(boolean focused) {
        if (this.closeIconFocused != focused) {
            this.closeIconFocused = focused;
            refreshDrawableState();
        }
    }

    /* access modifiers changed from: protected */
    public void drawableStateChanged() {
        super.drawableStateChanged();
        boolean changed = false;
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null && chipDrawable2.isCloseIconStateful()) {
            changed = this.chipDrawable.setCloseIconState(createCloseIconDrawableState());
        }
        if (changed) {
            invalidate();
        }
    }

    private int[] createCloseIconDrawableState() {
        int count = 0;
        if (isEnabled()) {
            count = 0 + 1;
        }
        if (this.closeIconFocused) {
            count++;
        }
        if (this.closeIconHovered) {
            count++;
        }
        if (this.closeIconPressed) {
            count++;
        }
        if (isChecked()) {
            count++;
        }
        int[] stateSet = new int[count];
        int i = 0;
        if (isEnabled()) {
            stateSet[0] = 16842910;
            i = 0 + 1;
        }
        if (this.closeIconFocused) {
            stateSet[i] = 16842908;
            i++;
        }
        if (this.closeIconHovered) {
            stateSet[i] = 16843623;
            i++;
        }
        if (this.closeIconPressed) {
            stateSet[i] = 16842919;
            i++;
        }
        if (isChecked()) {
            stateSet[i] = 16842913;
            int i2 = i + 1;
        }
        return stateSet;
    }

    /* access modifiers changed from: private */
    public boolean hasCloseIcon() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return (chipDrawable2 == null || chipDrawable2.getCloseIcon() == null) ? false : true;
    }

    /* access modifiers changed from: private */
    public RectF getCloseIconTouchBounds() {
        this.rectF.setEmpty();
        if (hasCloseIcon()) {
            this.chipDrawable.getCloseIconTouchBounds(this.rectF);
        }
        return this.rectF;
    }

    /* access modifiers changed from: private */
    public Rect getCloseIconTouchBoundsInt() {
        RectF bounds = getCloseIconTouchBounds();
        this.rect.set((int) bounds.left, (int) bounds.top, (int) bounds.right, (int) bounds.bottom);
        return this.rect;
    }

    public PointerIcon onResolvePointerIcon(MotionEvent event, int pointerIndex) {
        if (!getCloseIconTouchBounds().contains(event.getX(), event.getY()) || !isEnabled()) {
            return null;
        }
        return PointerIcon.getSystemIcon(getContext(), PointerIconCompat.TYPE_HAND);
    }

    public ColorStateList getChipBackgroundColor() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipBackgroundColor();
        }
        return null;
    }

    public void setChipBackgroundColorResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipBackgroundColorResource(id);
        }
    }

    public void setChipBackgroundColor(ColorStateList chipBackgroundColor) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipBackgroundColor(chipBackgroundColor);
        }
    }

    public float getChipMinHeight() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipMinHeight();
        }
        return 0.0f;
    }

    public void setChipMinHeightResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipMinHeightResource(id);
        }
    }

    public void setChipMinHeight(float minHeight) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipMinHeight(minHeight);
        }
    }

    public float getChipCornerRadius() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipCornerRadius();
        }
        return 0.0f;
    }

    public void setChipCornerRadiusResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipCornerRadiusResource(id);
        }
    }

    public void setChipCornerRadius(float chipCornerRadius) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipCornerRadius(chipCornerRadius);
        }
    }

    public ColorStateList getChipStrokeColor() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipStrokeColor();
        }
        return null;
    }

    public void setChipStrokeColorResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStrokeColorResource(id);
        }
    }

    public void setChipStrokeColor(ColorStateList chipStrokeColor) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStrokeColor(chipStrokeColor);
        }
    }

    public float getChipStrokeWidth() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipStrokeWidth();
        }
        return 0.0f;
    }

    public void setChipStrokeWidthResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStrokeWidthResource(id);
        }
    }

    public void setChipStrokeWidth(float chipStrokeWidth) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStrokeWidth(chipStrokeWidth);
        }
    }

    public ColorStateList getRippleColor() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getRippleColor();
        }
        return null;
    }

    public void setRippleColorResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setRippleColorResource(id);
        }
    }

    public void setRippleColor(ColorStateList rippleColor) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setRippleColor(rippleColor);
        }
    }

    public CharSequence getText() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return chipDrawable2 != null ? chipDrawable2.getText() : "";
    }

    @Deprecated
    public CharSequence getChipText() {
        return getText();
    }

    public void setText(CharSequence text, BufferType type) {
        if (this.chipDrawable != null) {
            if (text == null) {
                text = "";
            }
            super.setText(this.chipDrawable.shouldDrawText() ? null : BidiFormatter.getInstance().unicodeWrap(text), type);
            ChipDrawable chipDrawable2 = this.chipDrawable;
            if (chipDrawable2 != null) {
                chipDrawable2.setText(text);
            }
        }
    }

    @Deprecated
    public void setChipTextResource(int id) {
        setText(getResources().getString(id));
    }

    @Deprecated
    public void setChipText(CharSequence chipText) {
        setText(chipText);
    }

    private TextAppearance getTextAppearance() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getTextAppearance();
        }
        return null;
    }

    private void updateTextPaintDrawState(TextAppearance textAppearance) {
        TextPaint textPaint = getPaint();
        textPaint.drawableState = this.chipDrawable.getState();
        textAppearance.updateDrawState(getContext(), textPaint, this.fontCallback);
    }

    public void setTextAppearanceResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextAppearanceResource(id);
        }
        setTextAppearance(getContext(), id);
    }

    public void setTextAppearance(TextAppearance textAppearance) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextAppearance(textAppearance);
        }
        if (getTextAppearance() != null) {
            getTextAppearance().updateMeasureState(getContext(), getPaint(), this.fontCallback);
            updateTextPaintDrawState(textAppearance);
        }
    }

    public void setTextAppearance(Context context, int resId) {
        super.setTextAppearance(context, resId);
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextAppearanceResource(resId);
        }
        if (getTextAppearance() != null) {
            getTextAppearance().updateMeasureState(context, getPaint(), this.fontCallback);
            updateTextPaintDrawState(getTextAppearance());
        }
    }

    public void setTextAppearance(int resId) {
        super.setTextAppearance(resId);
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextAppearanceResource(resId);
        }
        if (getTextAppearance() != null) {
            getTextAppearance().updateMeasureState(getContext(), getPaint(), this.fontCallback);
            updateTextPaintDrawState(getTextAppearance());
        }
    }

    public boolean isChipIconVisible() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return chipDrawable2 != null && chipDrawable2.isChipIconVisible();
    }

    @Deprecated
    public boolean isChipIconEnabled() {
        return isChipIconVisible();
    }

    public void setChipIconVisible(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconVisible(id);
        }
    }

    public void setChipIconVisible(boolean chipIconVisible) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconVisible(chipIconVisible);
        }
    }

    @Deprecated
    public void setChipIconEnabledResource(int id) {
        setChipIconVisible(id);
    }

    @Deprecated
    public void setChipIconEnabled(boolean chipIconEnabled) {
        setChipIconVisible(chipIconEnabled);
    }

    public Drawable getChipIcon() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipIcon();
        }
        return null;
    }

    public void setChipIconResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconResource(id);
        }
    }

    public void setChipIcon(Drawable chipIcon) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIcon(chipIcon);
        }
    }

    public ColorStateList getChipIconTint() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipIconTint();
        }
        return null;
    }

    public void setChipIconTintResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconTintResource(id);
        }
    }

    public void setChipIconTint(ColorStateList chipIconTint) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconTint(chipIconTint);
        }
    }

    public float getChipIconSize() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipIconSize();
        }
        return 0.0f;
    }

    public void setChipIconSizeResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconSizeResource(id);
        }
    }

    public void setChipIconSize(float chipIconSize) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipIconSize(chipIconSize);
        }
    }

    public boolean isCloseIconVisible() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return chipDrawable2 != null && chipDrawable2.isCloseIconVisible();
    }

    @Deprecated
    public boolean isCloseIconEnabled() {
        return isCloseIconVisible();
    }

    public void setCloseIconVisible(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconVisible(id);
        }
    }

    public void setCloseIconVisible(boolean closeIconVisible) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconVisible(closeIconVisible);
        }
    }

    @Deprecated
    public void setCloseIconEnabledResource(int id) {
        setCloseIconVisible(id);
    }

    @Deprecated
    public void setCloseIconEnabled(boolean closeIconEnabled) {
        setCloseIconVisible(closeIconEnabled);
    }

    public Drawable getCloseIcon() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIcon();
        }
        return null;
    }

    public void setCloseIconResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconResource(id);
        }
    }

    public void setCloseIcon(Drawable closeIcon) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIcon(closeIcon);
        }
    }

    public ColorStateList getCloseIconTint() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIconTint();
        }
        return null;
    }

    public void setCloseIconTintResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconTintResource(id);
        }
    }

    public void setCloseIconTint(ColorStateList closeIconTint) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconTint(closeIconTint);
        }
    }

    public float getCloseIconSize() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIconSize();
        }
        return 0.0f;
    }

    public void setCloseIconSizeResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconSizeResource(id);
        }
    }

    public void setCloseIconSize(float closeIconSize) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconSize(closeIconSize);
        }
    }

    public void setCloseIconContentDescription(CharSequence closeIconContentDescription) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconContentDescription(closeIconContentDescription);
        }
    }

    public CharSequence getCloseIconContentDescription() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIconContentDescription();
        }
        return null;
    }

    public boolean isCheckable() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return chipDrawable2 != null && chipDrawable2.isCheckable();
    }

    public void setCheckableResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckableResource(id);
        }
    }

    public void setCheckable(boolean checkable) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckable(checkable);
        }
    }

    public boolean isCheckedIconVisible() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        return chipDrawable2 != null && chipDrawable2.isCheckedIconVisible();
    }

    @Deprecated
    public boolean isCheckedIconEnabled() {
        return isCheckedIconVisible();
    }

    public void setCheckedIconVisible(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckedIconVisible(id);
        }
    }

    public void setCheckedIconVisible(boolean checkedIconVisible) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckedIconVisible(checkedIconVisible);
        }
    }

    @Deprecated
    public void setCheckedIconEnabledResource(int id) {
        setCheckedIconVisible(id);
    }

    @Deprecated
    public void setCheckedIconEnabled(boolean checkedIconEnabled) {
        setCheckedIconVisible(checkedIconEnabled);
    }

    public Drawable getCheckedIcon() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCheckedIcon();
        }
        return null;
    }

    public void setCheckedIconResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckedIconResource(id);
        }
    }

    public void setCheckedIcon(Drawable checkedIcon) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCheckedIcon(checkedIcon);
        }
    }

    public MotionSpec getShowMotionSpec() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getShowMotionSpec();
        }
        return null;
    }

    public void setShowMotionSpecResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setShowMotionSpecResource(id);
        }
    }

    public void setShowMotionSpec(MotionSpec showMotionSpec) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setShowMotionSpec(showMotionSpec);
        }
    }

    public MotionSpec getHideMotionSpec() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getHideMotionSpec();
        }
        return null;
    }

    public void setHideMotionSpecResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setHideMotionSpecResource(id);
        }
    }

    public void setHideMotionSpec(MotionSpec hideMotionSpec) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setHideMotionSpec(hideMotionSpec);
        }
    }

    public float getChipStartPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipStartPadding();
        }
        return 0.0f;
    }

    public void setChipStartPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStartPaddingResource(id);
        }
    }

    public void setChipStartPadding(float chipStartPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipStartPadding(chipStartPadding);
        }
    }

    public float getIconStartPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getIconStartPadding();
        }
        return 0.0f;
    }

    public void setIconStartPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setIconStartPaddingResource(id);
        }
    }

    public void setIconStartPadding(float iconStartPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setIconStartPadding(iconStartPadding);
        }
    }

    public float getIconEndPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getIconEndPadding();
        }
        return 0.0f;
    }

    public void setIconEndPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setIconEndPaddingResource(id);
        }
    }

    public void setIconEndPadding(float iconEndPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setIconEndPadding(iconEndPadding);
        }
    }

    public float getTextStartPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getTextStartPadding();
        }
        return 0.0f;
    }

    public void setTextStartPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextStartPaddingResource(id);
        }
    }

    public void setTextStartPadding(float textStartPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextStartPadding(textStartPadding);
        }
    }

    public float getTextEndPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getTextEndPadding();
        }
        return 0.0f;
    }

    public void setTextEndPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextEndPaddingResource(id);
        }
    }

    public void setTextEndPadding(float textEndPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setTextEndPadding(textEndPadding);
        }
    }

    public float getCloseIconStartPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIconStartPadding();
        }
        return 0.0f;
    }

    public void setCloseIconStartPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconStartPaddingResource(id);
        }
    }

    public void setCloseIconStartPadding(float closeIconStartPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconStartPadding(closeIconStartPadding);
        }
    }

    public float getCloseIconEndPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getCloseIconEndPadding();
        }
        return 0.0f;
    }

    public void setCloseIconEndPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconEndPaddingResource(id);
        }
    }

    public void setCloseIconEndPadding(float closeIconEndPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setCloseIconEndPadding(closeIconEndPadding);
        }
    }

    public float getChipEndPadding() {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            return chipDrawable2.getChipEndPadding();
        }
        return 0.0f;
    }

    public void setChipEndPaddingResource(int id) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipEndPaddingResource(id);
        }
    }

    public void setChipEndPadding(float chipEndPadding) {
        ChipDrawable chipDrawable2 = this.chipDrawable;
        if (chipDrawable2 != null) {
            chipDrawable2.setChipEndPadding(chipEndPadding);
        }
    }
}
