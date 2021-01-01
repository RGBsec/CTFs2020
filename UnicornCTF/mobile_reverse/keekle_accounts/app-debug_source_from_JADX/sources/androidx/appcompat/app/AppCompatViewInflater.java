package androidx.appcompat.app;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import android.util.Log;
import android.view.InflateException;
import android.view.View;
import android.view.View.OnClickListener;
import androidx.appcompat.C0003R;
import androidx.appcompat.view.ContextThemeWrapper;
import androidx.appcompat.widget.AppCompatAutoCompleteTextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.appcompat.widget.AppCompatCheckedTextView;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.AppCompatImageButton;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.appcompat.widget.AppCompatMultiAutoCompleteTextView;
import androidx.appcompat.widget.AppCompatRadioButton;
import androidx.appcompat.widget.AppCompatRatingBar;
import androidx.appcompat.widget.AppCompatSeekBar;
import androidx.appcompat.widget.AppCompatSpinner;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.AppCompatToggleButton;
import androidx.appcompat.widget.TintContextWrapper;
import androidx.collection.ArrayMap;
import androidx.core.view.ViewCompat;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

public class AppCompatViewInflater {
    private static final String LOG_TAG = "AppCompatViewInflater";
    private static final String[] sClassPrefixList = {"android.widget.", "android.view.", "android.webkit."};
    private static final Map<String, Constructor<? extends View>> sConstructorMap = new ArrayMap();
    private static final Class<?>[] sConstructorSignature = {Context.class, AttributeSet.class};
    private static final int[] sOnClickAttrs = {16843375};
    private final Object[] mConstructorArgs = new Object[2];

    private static class DeclaredOnClickListener implements OnClickListener {
        private final View mHostView;
        private final String mMethodName;
        private Context mResolvedContext;
        private Method mResolvedMethod;

        public DeclaredOnClickListener(View hostView, String methodName) {
            this.mHostView = hostView;
            this.mMethodName = methodName;
        }

        public void onClick(View v) {
            if (this.mResolvedMethod == null) {
                resolveMethod(this.mHostView.getContext(), this.mMethodName);
            }
            try {
                this.mResolvedMethod.invoke(this.mResolvedContext, new Object[]{v});
            } catch (IllegalAccessException e) {
                throw new IllegalStateException("Could not execute non-public method for android:onClick", e);
            } catch (InvocationTargetException e2) {
                throw new IllegalStateException("Could not execute method for android:onClick", e2);
            }
        }

        private void resolveMethod(Context context, String name) {
            String idText;
            while (context != null) {
                try {
                    if (!context.isRestricted()) {
                        Method method = context.getClass().getMethod(this.mMethodName, new Class[]{View.class});
                        if (method != null) {
                            this.mResolvedMethod = method;
                            this.mResolvedContext = context;
                            return;
                        }
                    }
                } catch (NoSuchMethodException e) {
                }
                if (context instanceof ContextWrapper) {
                    context = ((ContextWrapper) context).getBaseContext();
                } else {
                    context = null;
                }
            }
            int id = this.mHostView.getId();
            if (id == -1) {
                idText = "";
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(" with id '");
                sb.append(this.mHostView.getContext().getResources().getResourceEntryName(id));
                sb.append("'");
                idText = sb.toString();
            }
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Could not find method ");
            sb2.append(this.mMethodName);
            sb2.append("(View) in a parent or ancestor Context for android:onClick attribute defined on view ");
            sb2.append(this.mHostView.getClass());
            sb2.append(idText);
            throw new IllegalStateException(sb2.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public final View createView(View parent, String name, Context context, AttributeSet attrs, boolean inheritContext, boolean readAndroidTheme, boolean readAppTheme, boolean wrapContext) {
        View view;
        Context originalContext = context;
        if (inheritContext && parent != null) {
            context = parent.getContext();
        }
        if (readAndroidTheme || readAppTheme) {
            context = themifyContext(context, attrs, readAndroidTheme, readAppTheme);
        }
        if (wrapContext) {
            context = TintContextWrapper.wrap(context);
        }
        char c = 65535;
        switch (name.hashCode()) {
            case -1946472170:
                if (name.equals("RatingBar")) {
                    c = 11;
                    break;
                }
                break;
            case -1455429095:
                if (name.equals("CheckedTextView")) {
                    c = 8;
                    break;
                }
                break;
            case -1346021293:
                if (name.equals("MultiAutoCompleteTextView")) {
                    c = 10;
                    break;
                }
                break;
            case -938935918:
                if (name.equals("TextView")) {
                    c = 0;
                    break;
                }
                break;
            case -937446323:
                if (name.equals("ImageButton")) {
                    c = 5;
                    break;
                }
                break;
            case -658531749:
                if (name.equals("SeekBar")) {
                    c = 12;
                    break;
                }
                break;
            case -339785223:
                if (name.equals("Spinner")) {
                    c = 4;
                    break;
                }
                break;
            case 776382189:
                if (name.equals("RadioButton")) {
                    c = 7;
                    break;
                }
                break;
            case 799298502:
                if (name.equals("ToggleButton")) {
                    c = 13;
                    break;
                }
                break;
            case 1125864064:
                if (name.equals("ImageView")) {
                    c = 1;
                    break;
                }
                break;
            case 1413872058:
                if (name.equals("AutoCompleteTextView")) {
                    c = 9;
                    break;
                }
                break;
            case 1601505219:
                if (name.equals("CheckBox")) {
                    c = 6;
                    break;
                }
                break;
            case 1666676343:
                if (name.equals("EditText")) {
                    c = 3;
                    break;
                }
                break;
            case 2001146706:
                if (name.equals("Button")) {
                    c = 2;
                    break;
                }
                break;
        }
        switch (c) {
            case 0:
                view = createTextView(context, attrs);
                verifyNotNull(view, name);
                break;
            case 1:
                view = createImageView(context, attrs);
                verifyNotNull(view, name);
                break;
            case 2:
                view = createButton(context, attrs);
                verifyNotNull(view, name);
                break;
            case 3:
                view = createEditText(context, attrs);
                verifyNotNull(view, name);
                break;
            case 4:
                view = createSpinner(context, attrs);
                verifyNotNull(view, name);
                break;
            case 5:
                view = createImageButton(context, attrs);
                verifyNotNull(view, name);
                break;
            case 6:
                view = createCheckBox(context, attrs);
                verifyNotNull(view, name);
                break;
            case 7:
                view = createRadioButton(context, attrs);
                verifyNotNull(view, name);
                break;
            case 8:
                view = createCheckedTextView(context, attrs);
                verifyNotNull(view, name);
                break;
            case 9:
                view = createAutoCompleteTextView(context, attrs);
                verifyNotNull(view, name);
                break;
            case 10:
                view = createMultiAutoCompleteTextView(context, attrs);
                verifyNotNull(view, name);
                break;
            case 11:
                view = createRatingBar(context, attrs);
                verifyNotNull(view, name);
                break;
            case 12:
                view = createSeekBar(context, attrs);
                verifyNotNull(view, name);
                break;
            case 13:
                view = createToggleButton(context, attrs);
                verifyNotNull(view, name);
                break;
            default:
                view = createView(context, name, attrs);
                break;
        }
        if (view == null && originalContext != context) {
            view = createViewFromTag(context, name, attrs);
        }
        if (view != null) {
            checkOnClickListener(view, attrs);
        }
        return view;
    }

    /* access modifiers changed from: protected */
    public AppCompatTextView createTextView(Context context, AttributeSet attrs) {
        return new AppCompatTextView(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatImageView createImageView(Context context, AttributeSet attrs) {
        return new AppCompatImageView(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatButton createButton(Context context, AttributeSet attrs) {
        return new AppCompatButton(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatEditText createEditText(Context context, AttributeSet attrs) {
        return new AppCompatEditText(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatSpinner createSpinner(Context context, AttributeSet attrs) {
        return new AppCompatSpinner(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatImageButton createImageButton(Context context, AttributeSet attrs) {
        return new AppCompatImageButton(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatCheckBox createCheckBox(Context context, AttributeSet attrs) {
        return new AppCompatCheckBox(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatRadioButton createRadioButton(Context context, AttributeSet attrs) {
        return new AppCompatRadioButton(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatCheckedTextView createCheckedTextView(Context context, AttributeSet attrs) {
        return new AppCompatCheckedTextView(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatAutoCompleteTextView createAutoCompleteTextView(Context context, AttributeSet attrs) {
        return new AppCompatAutoCompleteTextView(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatMultiAutoCompleteTextView createMultiAutoCompleteTextView(Context context, AttributeSet attrs) {
        return new AppCompatMultiAutoCompleteTextView(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatRatingBar createRatingBar(Context context, AttributeSet attrs) {
        return new AppCompatRatingBar(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatSeekBar createSeekBar(Context context, AttributeSet attrs) {
        return new AppCompatSeekBar(context, attrs);
    }

    /* access modifiers changed from: protected */
    public AppCompatToggleButton createToggleButton(Context context, AttributeSet attrs) {
        return new AppCompatToggleButton(context, attrs);
    }

    private void verifyNotNull(View view, String name) {
        if (view == null) {
            StringBuilder sb = new StringBuilder();
            sb.append(getClass().getName());
            sb.append(" asked to inflate view for <");
            sb.append(name);
            sb.append(">, but returned null");
            throw new IllegalStateException(sb.toString());
        }
    }

    /* access modifiers changed from: protected */
    public View createView(Context context, String name, AttributeSet attrs) {
        return null;
    }

    private View createViewFromTag(Context context, String name, AttributeSet attrs) {
        if (name.equals("view")) {
            name = attrs.getAttributeValue(null, "class");
        }
        try {
            this.mConstructorArgs[0] = context;
            this.mConstructorArgs[1] = attrs;
            if (-1 == name.indexOf(46)) {
                for (String createViewByPrefix : sClassPrefixList) {
                    View view = createViewByPrefix(context, name, createViewByPrefix);
                    if (view != null) {
                        return view;
                    }
                }
                Object[] objArr = this.mConstructorArgs;
                objArr[0] = null;
                objArr[1] = null;
                return null;
            }
            View createViewByPrefix2 = createViewByPrefix(context, name, null);
            Object[] objArr2 = this.mConstructorArgs;
            objArr2[0] = null;
            objArr2[1] = null;
            return createViewByPrefix2;
        } catch (Exception e) {
            return null;
        } finally {
            Object[] objArr3 = this.mConstructorArgs;
            objArr3[0] = null;
            objArr3[1] = null;
        }
    }

    private void checkOnClickListener(View view, AttributeSet attrs) {
        Context context = view.getContext();
        if ((context instanceof ContextWrapper) && (VERSION.SDK_INT < 15 || ViewCompat.hasOnClickListeners(view))) {
            TypedArray a = context.obtainStyledAttributes(attrs, sOnClickAttrs);
            String handlerName = a.getString(0);
            if (handlerName != null) {
                view.setOnClickListener(new DeclaredOnClickListener(view, handlerName));
            }
            a.recycle();
        }
    }

    private View createViewByPrefix(Context context, String name, String prefix) throws ClassNotFoundException, InflateException {
        String str;
        Constructor constructor = (Constructor) sConstructorMap.get(name);
        if (constructor == null) {
            if (prefix != null) {
                try {
                    StringBuilder sb = new StringBuilder();
                    sb.append(prefix);
                    sb.append(name);
                    str = sb.toString();
                } catch (Exception e) {
                    return null;
                }
            } else {
                str = name;
            }
            constructor = Class.forName(str, false, context.getClassLoader()).asSubclass(View.class).getConstructor(sConstructorSignature);
            sConstructorMap.put(name, constructor);
        }
        constructor.setAccessible(true);
        return (View) constructor.newInstance(this.mConstructorArgs);
    }

    private static Context themifyContext(Context context, AttributeSet attrs, boolean useAndroidTheme, boolean useAppTheme) {
        TypedArray a = context.obtainStyledAttributes(attrs, C0003R.styleable.View, 0, 0);
        int themeId = 0;
        if (useAndroidTheme) {
            themeId = a.getResourceId(C0003R.styleable.View_android_theme, 0);
        }
        if (useAppTheme && themeId == 0) {
            themeId = a.getResourceId(C0003R.styleable.View_theme, 0);
            if (themeId != 0) {
                Log.i(LOG_TAG, "app:theme is now deprecated. Please move to using android:theme instead.");
            }
        }
        a.recycle();
        if (themeId == 0) {
            return context;
        }
        if (!(context instanceof ContextThemeWrapper) || ((ContextThemeWrapper) context).getThemeResId() != themeId) {
            return new ContextThemeWrapper(context, themeId);
        }
        return context;
    }
}
