package androidx.constraintlayout.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout.LayoutParams;

public class Guideline extends View {
    public Guideline(Context context) {
        super(context);
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs) {
        super(context, attrs);
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        super.setVisibility(8);
    }

    public Guideline(Context context, AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr);
        super.setVisibility(8);
    }

    public void setVisibility(int visibility) {
    }

    public void draw(Canvas canvas) {
    }

    /* access modifiers changed from: protected */
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        setMeasuredDimension(0, 0);
    }

    public void setGuidelineBegin(int margin) {
        LayoutParams params = (LayoutParams) getLayoutParams();
        params.guideBegin = margin;
        setLayoutParams(params);
    }

    public void setGuidelineEnd(int margin) {
        LayoutParams params = (LayoutParams) getLayoutParams();
        params.guideEnd = margin;
        setLayoutParams(params);
    }

    public void setGuidelinePercent(float ratio) {
        LayoutParams params = (LayoutParams) getLayoutParams();
        params.guidePercent = ratio;
        setLayoutParams(params);
    }
}
