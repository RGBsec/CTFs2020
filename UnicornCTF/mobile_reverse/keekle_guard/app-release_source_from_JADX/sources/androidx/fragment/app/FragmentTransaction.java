package androidx.fragment.app;

import android.view.View;
import androidx.core.view.ViewCompat;
import androidx.lifecycle.Lifecycle.State;
import java.lang.reflect.Modifier;
import java.util.ArrayList;

public abstract class FragmentTransaction {
    static final int OP_ADD = 1;
    static final int OP_ATTACH = 7;
    static final int OP_DETACH = 6;
    static final int OP_HIDE = 4;
    static final int OP_NULL = 0;
    static final int OP_REMOVE = 3;
    static final int OP_REPLACE = 2;
    static final int OP_SET_MAX_LIFECYCLE = 10;
    static final int OP_SET_PRIMARY_NAV = 8;
    static final int OP_SHOW = 5;
    static final int OP_UNSET_PRIMARY_NAV = 9;
    public static final int TRANSIT_ENTER_MASK = 4096;
    public static final int TRANSIT_EXIT_MASK = 8192;
    public static final int TRANSIT_FRAGMENT_CLOSE = 8194;
    public static final int TRANSIT_FRAGMENT_FADE = 4099;
    public static final int TRANSIT_FRAGMENT_OPEN = 4097;
    public static final int TRANSIT_NONE = 0;
    public static final int TRANSIT_UNSET = -1;
    boolean mAddToBackStack;
    boolean mAllowAddToBackStack = true;
    int mBreadCrumbShortTitleRes;
    CharSequence mBreadCrumbShortTitleText;
    int mBreadCrumbTitleRes;
    CharSequence mBreadCrumbTitleText;
    ArrayList<Runnable> mCommitRunnables;
    int mEnterAnim;
    int mExitAnim;
    String mName;
    ArrayList<C0199Op> mOps = new ArrayList<>();
    int mPopEnterAnim;
    int mPopExitAnim;
    boolean mReorderingAllowed = false;
    ArrayList<String> mSharedElementSourceNames;
    ArrayList<String> mSharedElementTargetNames;
    int mTransition;
    int mTransitionStyle;

    /* renamed from: androidx.fragment.app.FragmentTransaction$Op */
    static final class C0199Op {
        int mCmd;
        State mCurrentMaxState;
        int mEnterAnim;
        int mExitAnim;
        Fragment mFragment;
        State mOldMaxState;
        int mPopEnterAnim;
        int mPopExitAnim;

        C0199Op() {
        }

        C0199Op(int i, Fragment fragment) {
            this.mCmd = i;
            this.mFragment = fragment;
            this.mOldMaxState = State.RESUMED;
            this.mCurrentMaxState = State.RESUMED;
        }

        C0199Op(int i, Fragment fragment, State state) {
            this.mCmd = i;
            this.mFragment = fragment;
            this.mOldMaxState = fragment.mMaxState;
            this.mCurrentMaxState = state;
        }
    }

    public abstract int commit();

    public abstract int commitAllowingStateLoss();

    public abstract void commitNow();

    public abstract void commitNowAllowingStateLoss();

    /* access modifiers changed from: 0000 */
    public void addOp(C0199Op op) {
        this.mOps.add(op);
        op.mEnterAnim = this.mEnterAnim;
        op.mExitAnim = this.mExitAnim;
        op.mPopEnterAnim = this.mPopEnterAnim;
        op.mPopExitAnim = this.mPopExitAnim;
    }

    public FragmentTransaction add(Fragment fragment, String str) {
        doAddOp(0, fragment, str, 1);
        return this;
    }

    public FragmentTransaction add(int i, Fragment fragment) {
        doAddOp(i, fragment, null, 1);
        return this;
    }

    public FragmentTransaction add(int i, Fragment fragment, String str) {
        doAddOp(i, fragment, str, 1);
        return this;
    }

    /* access modifiers changed from: 0000 */
    public void doAddOp(int i, Fragment fragment, String str, int i2) {
        Class cls = fragment.getClass();
        int modifiers = cls.getModifiers();
        if (cls.isAnonymousClass() || !Modifier.isPublic(modifiers) || (cls.isMemberClass() && !Modifier.isStatic(modifiers))) {
            StringBuilder sb = new StringBuilder();
            sb.append("Fragment ");
            sb.append(cls.getCanonicalName());
            sb.append(" must be a public static class to be  properly recreated from instance state.");
            throw new IllegalStateException(sb.toString());
        }
        String str2 = " now ";
        String str3 = ": was ";
        if (str != null) {
            if (fragment.mTag == null || str.equals(fragment.mTag)) {
                fragment.mTag = str;
            } else {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Can't change tag of fragment ");
                sb2.append(fragment);
                sb2.append(str3);
                sb2.append(fragment.mTag);
                sb2.append(str2);
                sb2.append(str);
                throw new IllegalStateException(sb2.toString());
            }
        }
        if (i != 0) {
            if (i == -1) {
                StringBuilder sb3 = new StringBuilder();
                sb3.append("Can't add fragment ");
                sb3.append(fragment);
                sb3.append(" with tag ");
                sb3.append(str);
                sb3.append(" to container view with no id");
                throw new IllegalArgumentException(sb3.toString());
            } else if (fragment.mFragmentId == 0 || fragment.mFragmentId == i) {
                fragment.mFragmentId = i;
                fragment.mContainerId = i;
            } else {
                StringBuilder sb4 = new StringBuilder();
                sb4.append("Can't change container ID of fragment ");
                sb4.append(fragment);
                sb4.append(str3);
                sb4.append(fragment.mFragmentId);
                sb4.append(str2);
                sb4.append(i);
                throw new IllegalStateException(sb4.toString());
            }
        }
        addOp(new C0199Op(i2, fragment));
    }

    public FragmentTransaction replace(int i, Fragment fragment) {
        return replace(i, fragment, null);
    }

    public FragmentTransaction replace(int i, Fragment fragment, String str) {
        if (i != 0) {
            doAddOp(i, fragment, str, 2);
            return this;
        }
        throw new IllegalArgumentException("Must use non-zero containerViewId");
    }

    public FragmentTransaction remove(Fragment fragment) {
        addOp(new C0199Op(3, fragment));
        return this;
    }

    public FragmentTransaction hide(Fragment fragment) {
        addOp(new C0199Op(4, fragment));
        return this;
    }

    public FragmentTransaction show(Fragment fragment) {
        addOp(new C0199Op(5, fragment));
        return this;
    }

    public FragmentTransaction detach(Fragment fragment) {
        addOp(new C0199Op(6, fragment));
        return this;
    }

    public FragmentTransaction attach(Fragment fragment) {
        addOp(new C0199Op(7, fragment));
        return this;
    }

    public FragmentTransaction setPrimaryNavigationFragment(Fragment fragment) {
        addOp(new C0199Op(8, fragment));
        return this;
    }

    public FragmentTransaction setMaxLifecycle(Fragment fragment, State state) {
        addOp(new C0199Op(10, fragment, state));
        return this;
    }

    public boolean isEmpty() {
        return this.mOps.isEmpty();
    }

    public FragmentTransaction setCustomAnimations(int i, int i2) {
        return setCustomAnimations(i, i2, 0, 0);
    }

    public FragmentTransaction setCustomAnimations(int i, int i2, int i3, int i4) {
        this.mEnterAnim = i;
        this.mExitAnim = i2;
        this.mPopEnterAnim = i3;
        this.mPopExitAnim = i4;
        return this;
    }

    public FragmentTransaction addSharedElement(View view, String str) {
        if (FragmentTransition.supportsTransition()) {
            String transitionName = ViewCompat.getTransitionName(view);
            if (transitionName != null) {
                if (this.mSharedElementSourceNames == null) {
                    this.mSharedElementSourceNames = new ArrayList<>();
                    this.mSharedElementTargetNames = new ArrayList<>();
                } else {
                    String str2 = "' has already been added to the transaction.";
                    if (this.mSharedElementTargetNames.contains(str)) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("A shared element with the target name '");
                        sb.append(str);
                        sb.append(str2);
                        throw new IllegalArgumentException(sb.toString());
                    } else if (this.mSharedElementSourceNames.contains(transitionName)) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("A shared element with the source name '");
                        sb2.append(transitionName);
                        sb2.append(str2);
                        throw new IllegalArgumentException(sb2.toString());
                    }
                }
                this.mSharedElementSourceNames.add(transitionName);
                this.mSharedElementTargetNames.add(str);
            } else {
                throw new IllegalArgumentException("Unique transitionNames are required for all sharedElements");
            }
        }
        return this;
    }

    public FragmentTransaction setTransition(int i) {
        this.mTransition = i;
        return this;
    }

    public FragmentTransaction setTransitionStyle(int i) {
        this.mTransitionStyle = i;
        return this;
    }

    public FragmentTransaction addToBackStack(String str) {
        if (this.mAllowAddToBackStack) {
            this.mAddToBackStack = true;
            this.mName = str;
            return this;
        }
        throw new IllegalStateException("This FragmentTransaction is not allowed to be added to the back stack.");
    }

    public boolean isAddToBackStackAllowed() {
        return this.mAllowAddToBackStack;
    }

    public FragmentTransaction disallowAddToBackStack() {
        if (!this.mAddToBackStack) {
            this.mAllowAddToBackStack = false;
            return this;
        }
        throw new IllegalStateException("This transaction is already being added to the back stack");
    }

    public FragmentTransaction setBreadCrumbTitle(int i) {
        this.mBreadCrumbTitleRes = i;
        this.mBreadCrumbTitleText = null;
        return this;
    }

    public FragmentTransaction setBreadCrumbTitle(CharSequence charSequence) {
        this.mBreadCrumbTitleRes = 0;
        this.mBreadCrumbTitleText = charSequence;
        return this;
    }

    public FragmentTransaction setBreadCrumbShortTitle(int i) {
        this.mBreadCrumbShortTitleRes = i;
        this.mBreadCrumbShortTitleText = null;
        return this;
    }

    public FragmentTransaction setBreadCrumbShortTitle(CharSequence charSequence) {
        this.mBreadCrumbShortTitleRes = 0;
        this.mBreadCrumbShortTitleText = charSequence;
        return this;
    }

    public FragmentTransaction setReorderingAllowed(boolean z) {
        this.mReorderingAllowed = z;
        return this;
    }

    @Deprecated
    public FragmentTransaction setAllowOptimization(boolean z) {
        return setReorderingAllowed(z);
    }

    public FragmentTransaction runOnCommit(Runnable runnable) {
        disallowAddToBackStack();
        if (this.mCommitRunnables == null) {
            this.mCommitRunnables = new ArrayList<>();
        }
        this.mCommitRunnables.add(runnable);
        return this;
    }
}
