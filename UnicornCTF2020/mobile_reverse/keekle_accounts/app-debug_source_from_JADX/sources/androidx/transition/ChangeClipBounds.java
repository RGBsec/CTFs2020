package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.ViewCompat;
import java.util.Map;

public class ChangeClipBounds extends Transition {
    private static final String PROPNAME_BOUNDS = "android:clipBounds:bounds";
    private static final String PROPNAME_CLIP = "android:clipBounds:clip";
    private static final String[] sTransitionProperties = {PROPNAME_CLIP};

    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    public ChangeClipBounds() {
    }

    public ChangeClipBounds(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    private void captureValues(TransitionValues values) {
        View view = values.view;
        if (view.getVisibility() != 8) {
            Rect clip = ViewCompat.getClipBounds(view);
            values.values.put(PROPNAME_CLIP, clip);
            if (clip == null) {
                values.values.put(PROPNAME_BOUNDS, new Rect(0, 0, view.getWidth(), view.getHeight()));
            }
        }
    }

    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public Animator createAnimator(ViewGroup sceneRoot, TransitionValues startValues, TransitionValues endValues) {
        if (!(startValues == null || endValues == null)) {
            Map<String, Object> map = startValues.values;
            String str = PROPNAME_CLIP;
            if (map.containsKey(str) && endValues.values.containsKey(str)) {
                Rect start = (Rect) startValues.values.get(str);
                Rect end = (Rect) endValues.values.get(str);
                boolean endIsNull = end == null;
                if (start == null && end == null) {
                    return null;
                }
                String str2 = PROPNAME_BOUNDS;
                if (start == null) {
                    start = (Rect) startValues.values.get(str2);
                } else if (end == null) {
                    end = (Rect) endValues.values.get(str2);
                }
                if (start.equals(end)) {
                    return null;
                }
                ViewCompat.setClipBounds(endValues.view, start);
                ObjectAnimator animator = ObjectAnimator.ofObject(endValues.view, ViewUtils.CLIP_BOUNDS, new RectEvaluator(new Rect()), new Rect[]{start, end});
                if (endIsNull) {
                    final View endView = endValues.view;
                    animator.addListener(new AnimatorListenerAdapter() {
                        public void onAnimationEnd(Animator animation) {
                            ViewCompat.setClipBounds(endView, null);
                        }
                    });
                }
                return animator;
            }
        }
        return null;
    }
}
