package com.google.android.material.animation;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.Log;
import androidx.collection.SimpleArrayMap;
import java.util.ArrayList;
import java.util.List;

public class MotionSpec {
    private static final String TAG = "MotionSpec";
    private final SimpleArrayMap<String, MotionTiming> timings = new SimpleArrayMap<>();

    public boolean hasTiming(String name) {
        return this.timings.get(name) != null;
    }

    public MotionTiming getTiming(String name) {
        if (hasTiming(name)) {
            return (MotionTiming) this.timings.get(name);
        }
        throw new IllegalArgumentException();
    }

    public void setTiming(String name, MotionTiming timing) {
        this.timings.put(name, timing);
    }

    public long getTotalDuration() {
        long duration = 0;
        int count = this.timings.size();
        for (int i = 0; i < count; i++) {
            MotionTiming timing = (MotionTiming) this.timings.valueAt(i);
            duration = Math.max(duration, timing.getDelay() + timing.getDuration());
        }
        return duration;
    }

    public static MotionSpec createFromAttribute(Context context, TypedArray attributes, int index) {
        if (attributes.hasValue(index)) {
            int resourceId = attributes.getResourceId(index, 0);
            if (resourceId != 0) {
                return createFromResource(context, resourceId);
            }
        }
        return null;
    }

    public static MotionSpec createFromResource(Context context, int id) {
        try {
            Animator animator = AnimatorInflater.loadAnimator(context, id);
            if (animator instanceof AnimatorSet) {
                return createSpecFromAnimators(((AnimatorSet) animator).getChildAnimations());
            }
            if (animator == null) {
                return null;
            }
            List<Animator> animators = new ArrayList<>();
            animators.add(animator);
            return createSpecFromAnimators(animators);
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            sb.append("Can't load animation resource ID #0x");
            sb.append(Integer.toHexString(id));
            Log.w(TAG, sb.toString(), e);
            return null;
        }
    }

    private static MotionSpec createSpecFromAnimators(List<Animator> animators) {
        MotionSpec spec = new MotionSpec();
        int count = animators.size();
        for (int i = 0; i < count; i++) {
            addTimingFromAnimator(spec, (Animator) animators.get(i));
        }
        return spec;
    }

    private static void addTimingFromAnimator(MotionSpec spec, Animator animator) {
        if (animator instanceof ObjectAnimator) {
            ObjectAnimator anim = (ObjectAnimator) animator;
            spec.setTiming(anim.getPropertyName(), MotionTiming.createFromAnimator(anim));
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Animator must be an ObjectAnimator: ");
        sb.append(animator);
        throw new IllegalArgumentException(sb.toString());
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return this.timings.equals(((MotionSpec) o).timings);
    }

    public int hashCode() {
        return this.timings.hashCode();
    }

    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append(10);
        out.append(getClass().getName());
        out.append('{');
        out.append(Integer.toHexString(System.identityHashCode(this)));
        out.append(" timings: ");
        out.append(this.timings);
        out.append("}\n");
        return out.toString();
    }
}
