package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.PropertyValuesHolder;
import android.animation.TimeInterpolator;
import android.view.View;

class TranslationAnimationCreator {

    private static class TransitionPositionListener extends AnimatorListenerAdapter {
        private final View mMovingView;
        private float mPausedX;
        private float mPausedY;
        private final int mStartX;
        private final int mStartY;
        private final float mTerminalX;
        private final float mTerminalY;
        private int[] mTransitionPosition;
        private final View mViewInHierarchy;

        TransitionPositionListener(View movingView, View viewInHierarchy, int startX, int startY, float terminalX, float terminalY) {
            this.mMovingView = movingView;
            this.mViewInHierarchy = viewInHierarchy;
            this.mStartX = startX - Math.round(movingView.getTranslationX());
            this.mStartY = startY - Math.round(this.mMovingView.getTranslationY());
            this.mTerminalX = terminalX;
            this.mTerminalY = terminalY;
            int[] iArr = (int[]) this.mViewInHierarchy.getTag(C0065R.C0067id.transition_position);
            this.mTransitionPosition = iArr;
            if (iArr != null) {
                this.mViewInHierarchy.setTag(C0065R.C0067id.transition_position, null);
            }
        }

        public void onAnimationCancel(Animator animation) {
            if (this.mTransitionPosition == null) {
                this.mTransitionPosition = new int[2];
            }
            this.mTransitionPosition[0] = Math.round(((float) this.mStartX) + this.mMovingView.getTranslationX());
            this.mTransitionPosition[1] = Math.round(((float) this.mStartY) + this.mMovingView.getTranslationY());
            this.mViewInHierarchy.setTag(C0065R.C0067id.transition_position, this.mTransitionPosition);
        }

        public void onAnimationEnd(Animator animator) {
            this.mMovingView.setTranslationX(this.mTerminalX);
            this.mMovingView.setTranslationY(this.mTerminalY);
        }

        public void onAnimationPause(Animator animator) {
            this.mPausedX = this.mMovingView.getTranslationX();
            this.mPausedY = this.mMovingView.getTranslationY();
            this.mMovingView.setTranslationX(this.mTerminalX);
            this.mMovingView.setTranslationY(this.mTerminalY);
        }

        public void onAnimationResume(Animator animator) {
            this.mMovingView.setTranslationX(this.mPausedX);
            this.mMovingView.setTranslationY(this.mPausedY);
        }
    }

    static Animator createAnimation(View view, TransitionValues values, int viewPosX, int viewPosY, float startX, float startY, float endX, float endY, TimeInterpolator interpolator) {
        float startY2;
        float startX2;
        View view2 = view;
        TransitionValues transitionValues = values;
        float terminalX = view.getTranslationX();
        float terminalY = view.getTranslationY();
        int[] startPosition = (int[]) transitionValues.view.getTag(C0065R.C0067id.transition_position);
        if (startPosition != null) {
            startX2 = ((float) (startPosition[0] - viewPosX)) + terminalX;
            startY2 = ((float) (startPosition[1] - viewPosY)) + terminalY;
        } else {
            startX2 = startX;
            startY2 = startY;
        }
        int startPosX = viewPosX + Math.round(startX2 - terminalX);
        int startPosY = viewPosY + Math.round(startY2 - terminalY);
        view2.setTranslationX(startX2);
        view2.setTranslationY(startY2);
        if (startX2 == endX && startY2 == endY) {
            return null;
        }
        ObjectAnimator anim = ObjectAnimator.ofPropertyValuesHolder(view2, new PropertyValuesHolder[]{PropertyValuesHolder.ofFloat(View.TRANSLATION_X, new float[]{startX2, endX}), PropertyValuesHolder.ofFloat(View.TRANSLATION_Y, new float[]{startY2, endY})});
        TransitionPositionListener listener = new TransitionPositionListener(view, transitionValues.view, startPosX, startPosY, terminalX, terminalY);
        anim.addListener(listener);
        AnimatorUtils.addPauseListener(anim, listener);
        anim.setInterpolator(interpolator);
        return anim;
    }

    private TranslationAnimationCreator() {
    }
}
