package androidx.constraintlayout.solver.widgets;

public class Rectangle {
    public int height;
    public int width;

    /* renamed from: x */
    public int f27x;

    /* renamed from: y */
    public int f28y;

    public void setBounds(int x, int y, int width2, int height2) {
        this.f27x = x;
        this.f28y = y;
        this.width = width2;
        this.height = height2;
    }

    /* access modifiers changed from: 0000 */
    public void grow(int w, int h) {
        this.f27x -= w;
        this.f28y -= h;
        this.width += w * 2;
        this.height += h * 2;
    }

    /* access modifiers changed from: 0000 */
    public boolean intersects(Rectangle bounds) {
        int i = this.f27x;
        int i2 = bounds.f27x;
        if (i >= i2 && i < i2 + bounds.width) {
            int i3 = this.f28y;
            int i4 = bounds.f28y;
            if (i3 >= i4 && i3 < i4 + bounds.height) {
                return true;
            }
        }
        return false;
    }

    public boolean contains(int x, int y) {
        int i = this.f27x;
        if (x >= i && x < i + this.width) {
            int i2 = this.f28y;
            if (y >= i2 && y < i2 + this.height) {
                return true;
            }
        }
        return false;
    }

    public int getCenterX() {
        return (this.f27x + this.width) / 2;
    }

    public int getCenterY() {
        return (this.f28y + this.height) / 2;
    }
}
