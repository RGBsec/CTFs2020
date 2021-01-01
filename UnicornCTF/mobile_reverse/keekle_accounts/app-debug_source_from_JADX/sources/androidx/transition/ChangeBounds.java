package androidx.transition;

import android.content.Context;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.Property;
import android.view.View;
import androidx.core.content.res.TypedArrayUtils;
import androidx.core.view.ViewCompat;

public class ChangeBounds extends Transition {
    private static final Property<View, PointF> BOTTOM_RIGHT_ONLY_PROPERTY;
    private static final Property<ViewBounds, PointF> BOTTOM_RIGHT_PROPERTY;
    private static final Property<Drawable, PointF> DRAWABLE_ORIGIN_PROPERTY = new Property<Drawable, PointF>(PointF.class, "boundsOrigin") {
        private Rect mBounds = new Rect();

        public void set(Drawable object, PointF value) {
            object.copyBounds(this.mBounds);
            this.mBounds.offsetTo(Math.round(value.x), Math.round(value.y));
            object.setBounds(this.mBounds);
        }

        public PointF get(Drawable object) {
            object.copyBounds(this.mBounds);
            return new PointF((float) this.mBounds.left, (float) this.mBounds.top);
        }
    };
    private static final Property<View, PointF> POSITION_PROPERTY = new Property<View, PointF>(PointF.class, "position") {
        public void set(View view, PointF topLeft) {
            int left = Math.round(topLeft.x);
            int top = Math.round(topLeft.y);
            ViewUtils.setLeftTopRightBottom(view, left, top, view.getWidth() + left, view.getHeight() + top);
        }

        public PointF get(View view) {
            return null;
        }
    };
    private static final String PROPNAME_BOUNDS = "android:changeBounds:bounds";
    private static final String PROPNAME_CLIP = "android:changeBounds:clip";
    private static final String PROPNAME_PARENT = "android:changeBounds:parent";
    private static final String PROPNAME_WINDOW_X = "android:changeBounds:windowX";
    private static final String PROPNAME_WINDOW_Y = "android:changeBounds:windowY";
    private static final Property<View, PointF> TOP_LEFT_ONLY_PROPERTY;
    private static final Property<ViewBounds, PointF> TOP_LEFT_PROPERTY;
    private static RectEvaluator sRectEvaluator = new RectEvaluator();
    private static final String[] sTransitionProperties = {PROPNAME_BOUNDS, PROPNAME_CLIP, PROPNAME_PARENT, PROPNAME_WINDOW_X, PROPNAME_WINDOW_Y};
    private boolean mReparent = false;
    private boolean mResizeClip = false;
    private int[] mTempLocation = new int[2];

    private static class ViewBounds {
        private int mBottom;
        private int mBottomRightCalls;
        private int mLeft;
        private int mRight;
        private int mTop;
        private int mTopLeftCalls;
        private View mView;

        ViewBounds(View view) {
            this.mView = view;
        }

        /* access modifiers changed from: 0000 */
        public void setTopLeft(PointF topLeft) {
            this.mLeft = Math.round(topLeft.x);
            this.mTop = Math.round(topLeft.y);
            int i = this.mTopLeftCalls + 1;
            this.mTopLeftCalls = i;
            if (i == this.mBottomRightCalls) {
                setLeftTopRightBottom();
            }
        }

        /* access modifiers changed from: 0000 */
        public void setBottomRight(PointF bottomRight) {
            this.mRight = Math.round(bottomRight.x);
            this.mBottom = Math.round(bottomRight.y);
            int i = this.mBottomRightCalls + 1;
            this.mBottomRightCalls = i;
            if (this.mTopLeftCalls == i) {
                setLeftTopRightBottom();
            }
        }

        private void setLeftTopRightBottom() {
            ViewUtils.setLeftTopRightBottom(this.mView, this.mLeft, this.mTop, this.mRight, this.mBottom);
            this.mTopLeftCalls = 0;
            this.mBottomRightCalls = 0;
        }
    }

    static {
        String str = "topLeft";
        TOP_LEFT_PROPERTY = new Property<ViewBounds, PointF>(PointF.class, str) {
            public void set(ViewBounds viewBounds, PointF topLeft) {
                viewBounds.setTopLeft(topLeft);
            }

            public PointF get(ViewBounds viewBounds) {
                return null;
            }
        };
        String str2 = "bottomRight";
        BOTTOM_RIGHT_PROPERTY = new Property<ViewBounds, PointF>(PointF.class, str2) {
            public void set(ViewBounds viewBounds, PointF bottomRight) {
                viewBounds.setBottomRight(bottomRight);
            }

            public PointF get(ViewBounds viewBounds) {
                return null;
            }
        };
        BOTTOM_RIGHT_ONLY_PROPERTY = new Property<View, PointF>(PointF.class, str2) {
            public void set(View view, PointF bottomRight) {
                ViewUtils.setLeftTopRightBottom(view, view.getLeft(), view.getTop(), Math.round(bottomRight.x), Math.round(bottomRight.y));
            }

            public PointF get(View view) {
                return null;
            }
        };
        TOP_LEFT_ONLY_PROPERTY = new Property<View, PointF>(PointF.class, str) {
            public void set(View view, PointF topLeft) {
                ViewUtils.setLeftTopRightBottom(view, Math.round(topLeft.x), Math.round(topLeft.y), view.getRight(), view.getBottom());
            }

            public PointF get(View view) {
                return null;
            }
        };
    }

    public ChangeBounds() {
    }

    public ChangeBounds(Context context, AttributeSet attrs) {
        super(context, attrs);
        TypedArray a = context.obtainStyledAttributes(attrs, Styleable.CHANGE_BOUNDS);
        boolean resizeClip = TypedArrayUtils.getNamedBoolean(a, (XmlResourceParser) attrs, "resizeClip", 0, false);
        a.recycle();
        setResizeClip(resizeClip);
    }

    public String[] getTransitionProperties() {
        return sTransitionProperties;
    }

    public void setResizeClip(boolean resizeClip) {
        this.mResizeClip = resizeClip;
    }

    public boolean getResizeClip() {
        return this.mResizeClip;
    }

    private void captureValues(TransitionValues values) {
        View view = values.view;
        if (ViewCompat.isLaidOut(view) || view.getWidth() != 0 || view.getHeight() != 0) {
            values.values.put(PROPNAME_BOUNDS, new Rect(view.getLeft(), view.getTop(), view.getRight(), view.getBottom()));
            values.values.put(PROPNAME_PARENT, values.view.getParent());
            if (this.mReparent) {
                values.view.getLocationInWindow(this.mTempLocation);
                values.values.put(PROPNAME_WINDOW_X, Integer.valueOf(this.mTempLocation[0]));
                values.values.put(PROPNAME_WINDOW_Y, Integer.valueOf(this.mTempLocation[1]));
            }
            if (this.mResizeClip) {
                values.values.put(PROPNAME_CLIP, ViewCompat.getClipBounds(view));
            }
        }
    }

    public void captureStartValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    public void captureEndValues(TransitionValues transitionValues) {
        captureValues(transitionValues);
    }

    private boolean parentMatches(View startParent, View endParent) {
        if (!this.mReparent) {
            return true;
        }
        boolean z = true;
        TransitionValues endValues = getMatchedTransitionValues(startParent, true);
        if (endValues == null) {
            if (startParent != endParent) {
                z = false;
            }
            return z;
        }
        if (endParent != endValues.view) {
            z = false;
        }
        return z;
    }

    /* JADX WARNING: type inference failed for: r0v27, types: [android.animation.Animator] */
    /* JADX WARNING: type inference failed for: r0v28, types: [android.animation.Animator] */
    /* JADX WARNING: type inference failed for: r0v33, types: [android.animation.ObjectAnimator] */
    /* JADX WARNING: type inference failed for: r0v36, types: [android.animation.ObjectAnimator] */
    /* JADX WARNING: type inference failed for: r14v11 */
    /* JADX WARNING: type inference failed for: r0v38 */
    /* JADX WARNING: type inference failed for: r0v41, types: [android.animation.ObjectAnimator] */
    /* JADX WARNING: type inference failed for: r0v43 */
    /* JADX WARNING: type inference failed for: r0v44 */
    /* JADX WARNING: type inference failed for: r0v45 */
    /* JADX WARNING: type inference failed for: r0v46 */
    /* JADX WARNING: Multi-variable type inference failed */
    /* JADX WARNING: Unknown variable types count: 6 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public android.animation.Animator createAnimator(android.view.ViewGroup r39, androidx.transition.TransitionValues r40, androidx.transition.TransitionValues r41) {
        /*
            r38 = this;
            r8 = r38
            r9 = r40
            r10 = r41
            if (r9 == 0) goto L_0x03c6
            if (r10 != 0) goto L_0x0011
            r15 = r39
            r12 = r10
            r0 = 0
            r10 = r8
            goto L_0x03cb
        L_0x0011:
            java.util.Map<java.lang.String, java.lang.Object> r11 = r9.values
            java.util.Map<java.lang.String, java.lang.Object> r12 = r10.values
            java.lang.String r1 = "android:changeBounds:parent"
            java.lang.Object r2 = r11.get(r1)
            r13 = r2
            android.view.ViewGroup r13 = (android.view.ViewGroup) r13
            java.lang.Object r1 = r12.get(r1)
            r14 = r1
            android.view.ViewGroup r14 = (android.view.ViewGroup) r14
            if (r13 == 0) goto L_0x03b8
            if (r14 != 0) goto L_0x0037
            r15 = r39
            r18 = r11
            r19 = r12
            r20 = r13
            r21 = r14
            r12 = r10
            r10 = r8
            goto L_0x03c4
        L_0x0037:
            android.view.View r15 = r10.view
            boolean r1 = r8.parentMatches(r13, r14)
            if (r1 == 0) goto L_0x02ef
            java.util.Map<java.lang.String, java.lang.Object> r1 = r9.values
            java.lang.String r3 = "android:changeBounds:bounds"
            java.lang.Object r1 = r1.get(r3)
            r6 = r1
            android.graphics.Rect r6 = (android.graphics.Rect) r6
            java.util.Map<java.lang.String, java.lang.Object> r1 = r10.values
            java.lang.Object r1 = r1.get(r3)
            r5 = r1
            android.graphics.Rect r5 = (android.graphics.Rect) r5
            int r4 = r6.left
            int r1 = r5.left
            int r3 = r6.top
            int r7 = r5.top
            int r2 = r6.right
            r18 = r11
            int r11 = r5.right
            r19 = r12
            int r12 = r6.bottom
            r20 = r13
            int r13 = r5.bottom
            r21 = r14
            int r14 = r2 - r4
            r22 = r6
            int r6 = r12 - r3
            r23 = r5
            int r5 = r11 - r1
            int r0 = r13 - r7
            r25 = r15
            java.util.Map<java.lang.String, java.lang.Object> r15 = r9.values
            java.lang.String r9 = "android:changeBounds:clip"
            java.lang.Object r15 = r15.get(r9)
            android.graphics.Rect r15 = (android.graphics.Rect) r15
            java.util.Map<java.lang.String, java.lang.Object> r8 = r10.values
            java.lang.Object r8 = r8.get(r9)
            android.graphics.Rect r8 = (android.graphics.Rect) r8
            r9 = 0
            if (r14 == 0) goto L_0x0090
            if (r6 != 0) goto L_0x0094
        L_0x0090:
            if (r5 == 0) goto L_0x00a0
            if (r0 == 0) goto L_0x00a0
        L_0x0094:
            if (r4 != r1) goto L_0x0098
            if (r3 == r7) goto L_0x009a
        L_0x0098:
            int r9 = r9 + 1
        L_0x009a:
            if (r2 != r11) goto L_0x009e
            if (r12 == r13) goto L_0x00a0
        L_0x009e:
            int r9 = r9 + 1
        L_0x00a0:
            if (r15 == 0) goto L_0x00a8
            boolean r26 = r15.equals(r8)
            if (r26 == 0) goto L_0x00ac
        L_0x00a8:
            if (r15 != 0) goto L_0x00ae
            if (r8 == 0) goto L_0x00ae
        L_0x00ac:
            int r9 = r9 + 1
        L_0x00ae:
            if (r9 <= 0) goto L_0x02ca
            r10 = r38
            r26 = r15
            boolean r15 = r10.mResizeClip
            r27 = r8
            r8 = 2
            if (r15 != 0) goto L_0x01dc
            r15 = r25
            androidx.transition.ViewUtils.setLeftTopRightBottom(r15, r4, r3, r2, r12)
            if (r9 != r8) goto L_0x016b
            if (r14 != r5) goto L_0x00fc
            if (r6 != r0) goto L_0x00fc
            androidx.transition.PathMotion r8 = r38.getPathMotion()
            r25 = r9
            float r9 = (float) r4
            r28 = r0
            float r0 = (float) r3
            r29 = r6
            float r6 = (float) r1
            r30 = r5
            float r5 = (float) r7
            android.graphics.Path r0 = r8.getPath(r9, r0, r6, r5)
            android.util.Property<android.view.View, android.graphics.PointF> r5 = POSITION_PROPERTY
            android.animation.ObjectAnimator r0 = androidx.transition.ObjectAnimatorUtils.ofPointF(r15, r5, r0)
            r33 = r1
            r17 = r2
            r16 = r7
            r37 = r11
            r34 = r14
            r8 = r15
            r15 = r26
            r32 = r28
            r36 = r29
            r35 = r30
            r11 = 1
            r30 = r3
            r28 = r4
            r29 = r12
            goto L_0x02b0
        L_0x00fc:
            r28 = r0
            r30 = r5
            r29 = r6
            r25 = r9
            androidx.transition.ChangeBounds$ViewBounds r0 = new androidx.transition.ChangeBounds$ViewBounds
            r0.<init>(r15)
            androidx.transition.PathMotion r5 = r38.getPathMotion()
            float r6 = (float) r4
            float r9 = (float) r3
            float r8 = (float) r1
            r31 = r14
            float r14 = (float) r7
            android.graphics.Path r5 = r5.getPath(r6, r9, r8, r14)
            android.util.Property<androidx.transition.ChangeBounds$ViewBounds, android.graphics.PointF> r6 = TOP_LEFT_PROPERTY
            android.animation.ObjectAnimator r6 = androidx.transition.ObjectAnimatorUtils.ofPointF(r0, r6, r5)
            androidx.transition.PathMotion r8 = r38.getPathMotion()
            float r9 = (float) r2
            float r14 = (float) r12
            r32 = r5
            float r5 = (float) r11
            r33 = r15
            float r15 = (float) r13
            android.graphics.Path r5 = r8.getPath(r9, r14, r5, r15)
            android.util.Property<androidx.transition.ChangeBounds$ViewBounds, android.graphics.PointF> r8 = BOTTOM_RIGHT_PROPERTY
            android.animation.ObjectAnimator r8 = androidx.transition.ObjectAnimatorUtils.ofPointF(r0, r8, r5)
            android.animation.AnimatorSet r9 = new android.animation.AnimatorSet
            r9.<init>()
            r14 = 2
            android.animation.Animator[] r14 = new android.animation.Animator[r14]
            r15 = 0
            r14[r15] = r6
            r15 = 1
            r14[r15] = r8
            r9.playTogether(r14)
            r14 = r9
            androidx.transition.ChangeBounds$7 r15 = new androidx.transition.ChangeBounds$7
            r15.<init>(r0)
            r9.addListener(r15)
            r17 = r2
            r16 = r7
            r37 = r11
            r0 = r14
            r15 = r26
            r32 = r28
            r36 = r29
            r35 = r30
            r34 = r31
            r8 = r33
            r11 = 1
            r33 = r1
            r30 = r3
            r28 = r4
            r29 = r12
            goto L_0x02b0
        L_0x016b:
            r28 = r0
            r30 = r5
            r29 = r6
            r25 = r9
            r31 = r14
            r33 = r15
            if (r4 != r1) goto L_0x01ad
            if (r3 == r7) goto L_0x017e
            r8 = r33
            goto L_0x01af
        L_0x017e:
            androidx.transition.PathMotion r0 = r38.getPathMotion()
            float r5 = (float) r2
            float r6 = (float) r12
            float r8 = (float) r11
            float r9 = (float) r13
            android.graphics.Path r0 = r0.getPath(r5, r6, r8, r9)
            android.util.Property<android.view.View, android.graphics.PointF> r5 = BOTTOM_RIGHT_ONLY_PROPERTY
            r8 = r33
            android.animation.ObjectAnimator r0 = androidx.transition.ObjectAnimatorUtils.ofPointF(r8, r5, r0)
            r33 = r1
            r17 = r2
            r16 = r7
            r37 = r11
            r15 = r26
            r32 = r28
            r36 = r29
            r35 = r30
            r34 = r31
            r11 = 1
            r30 = r3
            r28 = r4
            r29 = r12
            goto L_0x02b0
        L_0x01ad:
            r8 = r33
        L_0x01af:
            androidx.transition.PathMotion r0 = r38.getPathMotion()
            float r5 = (float) r4
            float r6 = (float) r3
            float r9 = (float) r1
            float r14 = (float) r7
            android.graphics.Path r0 = r0.getPath(r5, r6, r9, r14)
            android.util.Property<android.view.View, android.graphics.PointF> r5 = TOP_LEFT_ONLY_PROPERTY
            android.animation.ObjectAnimator r0 = androidx.transition.ObjectAnimatorUtils.ofPointF(r8, r5, r0)
            r33 = r1
            r17 = r2
            r16 = r7
            r37 = r11
            r15 = r26
            r32 = r28
            r36 = r29
            r35 = r30
            r34 = r31
            r11 = 1
            r30 = r3
            r28 = r4
            r29 = r12
            goto L_0x02b0
        L_0x01dc:
            r28 = r0
            r30 = r5
            r29 = r6
            r31 = r14
            r8 = r25
            r25 = r9
            r9 = r31
            int r14 = java.lang.Math.max(r9, r5)
            int r15 = java.lang.Math.max(r6, r0)
            r28 = r2
            int r2 = r4 + r14
            r29 = r12
            int r12 = r3 + r15
            androidx.transition.ViewUtils.setLeftTopRightBottom(r8, r4, r3, r2, r12)
            r2 = 0
            if (r4 != r1) goto L_0x020c
            if (r3 == r7) goto L_0x0204
            goto L_0x020c
        L_0x0204:
            r33 = r1
            r12 = r2
            r32 = r3
            r31 = r4
            goto L_0x0227
        L_0x020c:
            androidx.transition.PathMotion r12 = r38.getPathMotion()
            r30 = r2
            float r2 = (float) r4
            r31 = r4
            float r4 = (float) r3
            r32 = r3
            float r3 = (float) r1
            r33 = r1
            float r1 = (float) r7
            android.graphics.Path r1 = r12.getPath(r2, r4, r3, r1)
            android.util.Property<android.view.View, android.graphics.PointF> r2 = POSITION_PROPERTY
            android.animation.ObjectAnimator r2 = androidx.transition.ObjectAnimatorUtils.ofPointF(r8, r2, r1)
            r12 = r2
        L_0x0227:
            r30 = r32
            r3 = r27
            if (r26 != 0) goto L_0x0235
            android.graphics.Rect r1 = new android.graphics.Rect
            r2 = 0
            r1.<init>(r2, r2, r9, r6)
            r4 = r1
            goto L_0x0238
        L_0x0235:
            r2 = 0
            r4 = r26
        L_0x0238:
            if (r27 != 0) goto L_0x0241
            android.graphics.Rect r1 = new android.graphics.Rect
            r1.<init>(r2, r2, r5, r0)
            r2 = r1
            goto L_0x0243
        L_0x0241:
            r2 = r27
        L_0x0243:
            r1 = 0
            boolean r26 = r4.equals(r2)
            if (r26 != 0) goto L_0x0291
            androidx.core.view.ViewCompat.setClipBounds(r8, r4)
            r32 = r0
            androidx.transition.RectEvaluator r0 = sRectEvaluator
            r26 = r1
            r1 = 2
            java.lang.Object[] r1 = new java.lang.Object[r1]
            r17 = 0
            r1[r17] = r4
            r16 = 1
            r1[r16] = r2
            r17 = r2
            java.lang.String r2 = "clipBounds"
            android.animation.ObjectAnimator r2 = android.animation.ObjectAnimator.ofObject(r8, r2, r0, r1)
            androidx.transition.ChangeBounds$8 r1 = new androidx.transition.ChangeBounds$8
            r0 = r1
            r34 = r9
            r9 = r1
            r1 = r38
            r24 = r14
            r27 = r17
            r17 = r28
            r14 = r2
            r2 = r8
            r28 = r31
            r31 = r4
            r4 = r33
            r35 = r5
            r5 = r7
            r36 = r6
            r6 = r11
            r37 = r11
            r11 = r16
            r16 = r7
            r7 = r13
            r0.<init>(r2, r3, r4, r5, r6, r7)
            r14.addListener(r9)
            r1 = r14
            goto L_0x02aa
        L_0x0291:
            r32 = r0
            r26 = r1
            r27 = r2
            r35 = r5
            r36 = r6
            r16 = r7
            r34 = r9
            r37 = r11
            r24 = r14
            r17 = r28
            r28 = r31
            r11 = 1
            r31 = r4
        L_0x02aa:
            android.animation.Animator r0 = androidx.transition.TransitionUtils.mergeAnimators(r12, r1)
            r15 = r31
        L_0x02b0:
            android.view.ViewParent r1 = r8.getParent()
            boolean r1 = r1 instanceof android.view.ViewGroup
            if (r1 == 0) goto L_0x02c9
            android.view.ViewParent r1 = r8.getParent()
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
            androidx.transition.ViewGroupUtils.suppressLayout(r1, r11)
            androidx.transition.ChangeBounds$9 r2 = new androidx.transition.ChangeBounds$9
            r2.<init>(r1)
            r10.addListener(r2)
        L_0x02c9:
            return r0
        L_0x02ca:
            r10 = r38
            r32 = r0
            r33 = r1
            r17 = r2
            r30 = r3
            r28 = r4
            r35 = r5
            r36 = r6
            r16 = r7
            r27 = r8
            r37 = r11
            r29 = r12
            r34 = r14
            r26 = r15
            r8 = r25
            r25 = r9
            r6 = r40
            r12 = r41
            goto L_0x0337
        L_0x02ef:
            r10 = r8
            r18 = r11
            r19 = r12
            r20 = r13
            r21 = r14
            r8 = r15
            r11 = 1
            r6 = r40
            java.util.Map<java.lang.String, java.lang.Object> r0 = r6.values
            java.lang.String r1 = "android:changeBounds:windowX"
            java.lang.Object r0 = r0.get(r1)
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r7 = r0.intValue()
            java.util.Map<java.lang.String, java.lang.Object> r0 = r6.values
            java.lang.String r2 = "android:changeBounds:windowY"
            java.lang.Object r0 = r0.get(r2)
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r9 = r0.intValue()
            r12 = r41
            java.util.Map<java.lang.String, java.lang.Object> r0 = r12.values
            java.lang.Object r0 = r0.get(r1)
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r13 = r0.intValue()
            java.util.Map<java.lang.String, java.lang.Object> r0 = r12.values
            java.lang.Object r0 = r0.get(r2)
            java.lang.Integer r0 = (java.lang.Integer) r0
            int r14 = r0.intValue()
            if (r7 != r13) goto L_0x0339
            if (r9 == r14) goto L_0x0337
            goto L_0x0339
        L_0x0337:
            r0 = 0
            return r0
        L_0x0339:
            int[] r0 = r10.mTempLocation
            r15 = r39
            r15.getLocationInWindow(r0)
            int r0 = r8.getWidth()
            int r1 = r8.getHeight()
            android.graphics.Bitmap$Config r2 = android.graphics.Bitmap.Config.ARGB_8888
            android.graphics.Bitmap r5 = android.graphics.Bitmap.createBitmap(r0, r1, r2)
            android.graphics.Canvas r0 = new android.graphics.Canvas
            r0.<init>(r5)
            r4 = r0
            r8.draw(r4)
            android.graphics.drawable.BitmapDrawable r0 = new android.graphics.drawable.BitmapDrawable
            r0.<init>(r5)
            r3 = r0
            float r16 = androidx.transition.ViewUtils.getTransitionAlpha(r8)
            r0 = 0
            androidx.transition.ViewUtils.setTransitionAlpha(r8, r0)
            androidx.transition.ViewOverlayImpl r0 = androidx.transition.ViewUtils.getOverlay(r39)
            r0.add(r3)
            androidx.transition.PathMotion r0 = r38.getPathMotion()
            int[] r1 = r10.mTempLocation
            r2 = 0
            r17 = r1[r2]
            int r2 = r7 - r17
            float r2 = (float) r2
            r17 = r1[r11]
            int r11 = r9 - r17
            float r11 = (float) r11
            r17 = 0
            r22 = r1[r17]
            r24 = r4
            int r4 = r13 - r22
            float r4 = (float) r4
            r22 = r5
            r5 = 1
            r1 = r1[r5]
            int r1 = r14 - r1
            float r1 = (float) r1
            android.graphics.Path r11 = r0.getPath(r2, r11, r4, r1)
            android.util.Property<android.graphics.drawable.Drawable, android.graphics.PointF> r0 = DRAWABLE_ORIGIN_PROPERTY
            android.animation.PropertyValuesHolder r23 = androidx.transition.PropertyValuesHolderUtils.ofPointF(r0, r11)
            android.animation.PropertyValuesHolder[] r0 = new android.animation.PropertyValuesHolder[r5]
            r1 = 0
            r0[r1] = r23
            android.animation.ObjectAnimator r5 = android.animation.ObjectAnimator.ofPropertyValuesHolder(r3, r0)
            androidx.transition.ChangeBounds$10 r4 = new androidx.transition.ChangeBounds$10
            r0 = r4
            r1 = r38
            r2 = r39
            r17 = r3
            r6 = r4
            r4 = r8
            r25 = r7
            r7 = r5
            r5 = r16
            r0.<init>(r2, r3, r4, r5)
            r7.addListener(r6)
            return r7
        L_0x03b8:
            r15 = r39
            r18 = r11
            r19 = r12
            r20 = r13
            r21 = r14
            r12 = r10
            r10 = r8
        L_0x03c4:
            r0 = 0
            return r0
        L_0x03c6:
            r15 = r39
            r12 = r10
            r0 = 0
            r10 = r8
        L_0x03cb:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.transition.ChangeBounds.createAnimator(android.view.ViewGroup, androidx.transition.TransitionValues, androidx.transition.TransitionValues):android.animation.Animator");
    }
}
