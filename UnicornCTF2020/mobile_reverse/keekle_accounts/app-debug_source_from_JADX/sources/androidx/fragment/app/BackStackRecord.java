package androidx.fragment.app;

import android.util.Log;
import androidx.core.util.LogWriter;
import androidx.fragment.app.FragmentManager.BackStackEntry;
import androidx.lifecycle.Lifecycle.State;
import java.io.PrintWriter;
import java.util.ArrayList;

final class BackStackRecord extends FragmentTransaction implements BackStackEntry, OpGenerator {
    static final String TAG = "FragmentManager";
    boolean mCommitted;
    int mIndex = -1;
    final FragmentManagerImpl mManager;

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("BackStackEntry{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        if (this.mIndex >= 0) {
            sb.append(" #");
            sb.append(this.mIndex);
        }
        if (this.mName != null) {
            sb.append(" ");
            sb.append(this.mName);
        }
        sb.append("}");
        return sb.toString();
    }

    public void dump(String prefix, PrintWriter writer) {
        dump(prefix, writer, true);
    }

    public void dump(String prefix, PrintWriter writer, boolean full) {
        String cmdStr;
        if (full) {
            writer.print(prefix);
            writer.print("mName=");
            writer.print(this.mName);
            writer.print(" mIndex=");
            writer.print(this.mIndex);
            writer.print(" mCommitted=");
            writer.println(this.mCommitted);
            if (this.mTransition != 0) {
                writer.print(prefix);
                writer.print("mTransition=#");
                writer.print(Integer.toHexString(this.mTransition));
                writer.print(" mTransitionStyle=#");
                writer.println(Integer.toHexString(this.mTransitionStyle));
            }
            if (!(this.mEnterAnim == 0 && this.mExitAnim == 0)) {
                writer.print(prefix);
                writer.print("mEnterAnim=#");
                writer.print(Integer.toHexString(this.mEnterAnim));
                writer.print(" mExitAnim=#");
                writer.println(Integer.toHexString(this.mExitAnim));
            }
            if (!(this.mPopEnterAnim == 0 && this.mPopExitAnim == 0)) {
                writer.print(prefix);
                writer.print("mPopEnterAnim=#");
                writer.print(Integer.toHexString(this.mPopEnterAnim));
                writer.print(" mPopExitAnim=#");
                writer.println(Integer.toHexString(this.mPopExitAnim));
            }
            if (!(this.mBreadCrumbTitleRes == 0 && this.mBreadCrumbTitleText == null)) {
                writer.print(prefix);
                writer.print("mBreadCrumbTitleRes=#");
                writer.print(Integer.toHexString(this.mBreadCrumbTitleRes));
                writer.print(" mBreadCrumbTitleText=");
                writer.println(this.mBreadCrumbTitleText);
            }
            if (!(this.mBreadCrumbShortTitleRes == 0 && this.mBreadCrumbShortTitleText == null)) {
                writer.print(prefix);
                writer.print("mBreadCrumbShortTitleRes=#");
                writer.print(Integer.toHexString(this.mBreadCrumbShortTitleRes));
                writer.print(" mBreadCrumbShortTitleText=");
                writer.println(this.mBreadCrumbShortTitleText);
            }
        }
        if (!this.mOps.isEmpty()) {
            writer.print(prefix);
            writer.println("Operations:");
            int numOps = this.mOps.size();
            for (int opNum = 0; opNum < numOps; opNum++) {
                C0275Op op = (C0275Op) this.mOps.get(opNum);
                switch (op.mCmd) {
                    case 0:
                        cmdStr = "NULL";
                        break;
                    case 1:
                        cmdStr = "ADD";
                        break;
                    case 2:
                        cmdStr = "REPLACE";
                        break;
                    case 3:
                        cmdStr = "REMOVE";
                        break;
                    case 4:
                        cmdStr = "HIDE";
                        break;
                    case 5:
                        cmdStr = "SHOW";
                        break;
                    case 6:
                        cmdStr = "DETACH";
                        break;
                    case 7:
                        cmdStr = "ATTACH";
                        break;
                    case 8:
                        cmdStr = "SET_PRIMARY_NAV";
                        break;
                    case 9:
                        cmdStr = "UNSET_PRIMARY_NAV";
                        break;
                    case 10:
                        cmdStr = "OP_SET_MAX_LIFECYCLE";
                        break;
                    default:
                        StringBuilder sb = new StringBuilder();
                        sb.append("cmd=");
                        sb.append(op.mCmd);
                        cmdStr = sb.toString();
                        break;
                }
                writer.print(prefix);
                writer.print("  Op #");
                writer.print(opNum);
                writer.print(": ");
                writer.print(cmdStr);
                writer.print(" ");
                writer.println(op.mFragment);
                if (full) {
                    if (!(op.mEnterAnim == 0 && op.mExitAnim == 0)) {
                        writer.print(prefix);
                        writer.print("enterAnim=#");
                        writer.print(Integer.toHexString(op.mEnterAnim));
                        writer.print(" exitAnim=#");
                        writer.println(Integer.toHexString(op.mExitAnim));
                    }
                    if (op.mPopEnterAnim != 0 || op.mPopExitAnim != 0) {
                        writer.print(prefix);
                        writer.print("popEnterAnim=#");
                        writer.print(Integer.toHexString(op.mPopEnterAnim));
                        writer.print(" popExitAnim=#");
                        writer.println(Integer.toHexString(op.mPopExitAnim));
                    }
                }
            }
        }
    }

    public BackStackRecord(FragmentManagerImpl manager) {
        this.mManager = manager;
    }

    public int getId() {
        return this.mIndex;
    }

    public int getBreadCrumbTitleRes() {
        return this.mBreadCrumbTitleRes;
    }

    public int getBreadCrumbShortTitleRes() {
        return this.mBreadCrumbShortTitleRes;
    }

    public CharSequence getBreadCrumbTitle() {
        if (this.mBreadCrumbTitleRes != 0) {
            return this.mManager.mHost.getContext().getText(this.mBreadCrumbTitleRes);
        }
        return this.mBreadCrumbTitleText;
    }

    public CharSequence getBreadCrumbShortTitle() {
        if (this.mBreadCrumbShortTitleRes != 0) {
            return this.mManager.mHost.getContext().getText(this.mBreadCrumbShortTitleRes);
        }
        return this.mBreadCrumbShortTitleText;
    }

    /* access modifiers changed from: 0000 */
    public void doAddOp(int containerViewId, Fragment fragment, String tag, int opcmd) {
        super.doAddOp(containerViewId, fragment, tag, opcmd);
        fragment.mFragmentManager = this.mManager;
    }

    public FragmentTransaction remove(Fragment fragment) {
        if (fragment.mFragmentManager == null || fragment.mFragmentManager == this.mManager) {
            return super.remove(fragment);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Cannot remove Fragment attached to a different FragmentManager. Fragment ");
        sb.append(fragment.toString());
        sb.append(" is already attached to a FragmentManager.");
        throw new IllegalStateException(sb.toString());
    }

    public FragmentTransaction hide(Fragment fragment) {
        if (fragment.mFragmentManager == null || fragment.mFragmentManager == this.mManager) {
            return super.hide(fragment);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Cannot hide Fragment attached to a different FragmentManager. Fragment ");
        sb.append(fragment.toString());
        sb.append(" is already attached to a FragmentManager.");
        throw new IllegalStateException(sb.toString());
    }

    public FragmentTransaction show(Fragment fragment) {
        if (fragment.mFragmentManager == null || fragment.mFragmentManager == this.mManager) {
            return super.show(fragment);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Cannot show Fragment attached to a different FragmentManager. Fragment ");
        sb.append(fragment.toString());
        sb.append(" is already attached to a FragmentManager.");
        throw new IllegalStateException(sb.toString());
    }

    public FragmentTransaction detach(Fragment fragment) {
        if (fragment.mFragmentManager == null || fragment.mFragmentManager == this.mManager) {
            return super.detach(fragment);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Cannot detach Fragment attached to a different FragmentManager. Fragment ");
        sb.append(fragment.toString());
        sb.append(" is already attached to a FragmentManager.");
        throw new IllegalStateException(sb.toString());
    }

    public FragmentTransaction setPrimaryNavigationFragment(Fragment fragment) {
        if (fragment == null || fragment.mFragmentManager == null || fragment.mFragmentManager == this.mManager) {
            return super.setPrimaryNavigationFragment(fragment);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Cannot setPrimaryNavigation for Fragment attached to a different FragmentManager. Fragment ");
        sb.append(fragment.toString());
        sb.append(" is already attached to a FragmentManager.");
        throw new IllegalStateException(sb.toString());
    }

    public FragmentTransaction setMaxLifecycle(Fragment fragment, State state) {
        if (fragment.mFragmentManager != this.mManager) {
            StringBuilder sb = new StringBuilder();
            sb.append("Cannot setMaxLifecycle for Fragment not attached to FragmentManager ");
            sb.append(this.mManager);
            throw new IllegalArgumentException(sb.toString());
        } else if (state.isAtLeast(State.CREATED)) {
            return super.setMaxLifecycle(fragment, state);
        } else {
            StringBuilder sb2 = new StringBuilder();
            sb2.append("Cannot set maximum Lifecycle below ");
            sb2.append(State.CREATED);
            throw new IllegalArgumentException(sb2.toString());
        }
    }

    /* access modifiers changed from: 0000 */
    public void bumpBackStackNesting(int amt) {
        if (this.mAddToBackStack) {
            boolean z = FragmentManagerImpl.DEBUG;
            String str = TAG;
            if (z) {
                StringBuilder sb = new StringBuilder();
                sb.append("Bump nesting in ");
                sb.append(this);
                sb.append(" by ");
                sb.append(amt);
                Log.v(str, sb.toString());
            }
            int numOps = this.mOps.size();
            for (int opNum = 0; opNum < numOps; opNum++) {
                C0275Op op = (C0275Op) this.mOps.get(opNum);
                if (op.mFragment != null) {
                    op.mFragment.mBackStackNesting += amt;
                    if (FragmentManagerImpl.DEBUG) {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append("Bump nesting of ");
                        sb2.append(op.mFragment);
                        sb2.append(" to ");
                        sb2.append(op.mFragment.mBackStackNesting);
                        Log.v(str, sb2.toString());
                    }
                }
            }
        }
    }

    public void runOnCommitRunnables() {
        if (this.mCommitRunnables != null) {
            for (int i = 0; i < this.mCommitRunnables.size(); i++) {
                ((Runnable) this.mCommitRunnables.get(i)).run();
            }
            this.mCommitRunnables = null;
        }
    }

    public int commit() {
        return commitInternal(false);
    }

    public int commitAllowingStateLoss() {
        return commitInternal(true);
    }

    public void commitNow() {
        disallowAddToBackStack();
        this.mManager.execSingleAction(this, false);
    }

    public void commitNowAllowingStateLoss() {
        disallowAddToBackStack();
        this.mManager.execSingleAction(this, true);
    }

    /* access modifiers changed from: 0000 */
    public int commitInternal(boolean allowStateLoss) {
        if (!this.mCommitted) {
            if (FragmentManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("Commit: ");
                sb.append(this);
                String sb2 = sb.toString();
                String str = TAG;
                Log.v(str, sb2);
                PrintWriter pw = new PrintWriter(new LogWriter(str));
                dump("  ", pw);
                pw.close();
            }
            this.mCommitted = true;
            if (this.mAddToBackStack) {
                this.mIndex = this.mManager.allocBackStackIndex(this);
            } else {
                this.mIndex = -1;
            }
            this.mManager.enqueueAction(this, allowStateLoss);
            return this.mIndex;
        }
        throw new IllegalStateException("commit already called");
    }

    public boolean generateOps(ArrayList<BackStackRecord> records, ArrayList<Boolean> isRecordPop) {
        if (FragmentManagerImpl.DEBUG) {
            StringBuilder sb = new StringBuilder();
            sb.append("Run: ");
            sb.append(this);
            Log.v(TAG, sb.toString());
        }
        records.add(this);
        isRecordPop.add(Boolean.valueOf(false));
        if (this.mAddToBackStack) {
            this.mManager.addBackStackState(this);
        }
        return true;
    }

    /* access modifiers changed from: 0000 */
    public boolean interactsWith(int containerId) {
        int numOps = this.mOps.size();
        int opNum = 0;
        while (true) {
            int fragContainer = 0;
            if (opNum >= numOps) {
                return false;
            }
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            if (op.mFragment != null) {
                fragContainer = op.mFragment.mContainerId;
            }
            if (fragContainer != 0 && fragContainer == containerId) {
                return true;
            }
            opNum++;
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean interactsWith(ArrayList<BackStackRecord> records, int startIndex, int endIndex) {
        if (endIndex == startIndex) {
            return false;
        }
        int numOps = this.mOps.size();
        int lastContainer = -1;
        for (int opNum = 0; opNum < numOps; opNum++) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            int container = op.mFragment != null ? op.mFragment.mContainerId : 0;
            if (!(container == 0 || container == lastContainer)) {
                lastContainer = container;
                for (int i = startIndex; i < endIndex; i++) {
                    BackStackRecord record = (BackStackRecord) records.get(i);
                    int numThoseOps = record.mOps.size();
                    for (int thoseOpIndex = 0; thoseOpIndex < numThoseOps; thoseOpIndex++) {
                        C0275Op thatOp = (C0275Op) record.mOps.get(thoseOpIndex);
                        if ((thatOp.mFragment != null ? thatOp.mFragment.mContainerId : 0) == container) {
                            return true;
                        }
                    }
                }
                continue;
            }
        }
        return false;
    }

    /* access modifiers changed from: 0000 */
    public void executeOps() {
        int numOps = this.mOps.size();
        for (int opNum = 0; opNum < numOps; opNum++) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            Fragment f = op.mFragment;
            if (f != null) {
                f.setNextTransition(this.mTransition, this.mTransitionStyle);
            }
            switch (op.mCmd) {
                case 1:
                    f.setNextAnim(op.mEnterAnim);
                    this.mManager.addFragment(f, false);
                    break;
                case 3:
                    f.setNextAnim(op.mExitAnim);
                    this.mManager.removeFragment(f);
                    break;
                case 4:
                    f.setNextAnim(op.mExitAnim);
                    this.mManager.hideFragment(f);
                    break;
                case 5:
                    f.setNextAnim(op.mEnterAnim);
                    this.mManager.showFragment(f);
                    break;
                case 6:
                    f.setNextAnim(op.mExitAnim);
                    this.mManager.detachFragment(f);
                    break;
                case 7:
                    f.setNextAnim(op.mEnterAnim);
                    this.mManager.attachFragment(f);
                    break;
                case 8:
                    this.mManager.setPrimaryNavigationFragment(f);
                    break;
                case 9:
                    this.mManager.setPrimaryNavigationFragment(null);
                    break;
                case 10:
                    this.mManager.setMaxLifecycle(f, op.mCurrentMaxState);
                    break;
                default:
                    StringBuilder sb = new StringBuilder();
                    sb.append("Unknown cmd: ");
                    sb.append(op.mCmd);
                    throw new IllegalArgumentException(sb.toString());
            }
            if (!(this.mReorderingAllowed || op.mCmd == 1 || f == null)) {
                this.mManager.moveFragmentToExpectedState(f);
            }
        }
        if (this.mReorderingAllowed == 0) {
            FragmentManagerImpl fragmentManagerImpl = this.mManager;
            fragmentManagerImpl.moveToState(fragmentManagerImpl.mCurState, true);
        }
    }

    /* access modifiers changed from: 0000 */
    public void executePopOps(boolean moveToState) {
        for (int opNum = this.mOps.size() - 1; opNum >= 0; opNum--) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            Fragment f = op.mFragment;
            if (f != null) {
                f.setNextTransition(FragmentManagerImpl.reverseTransit(this.mTransition), this.mTransitionStyle);
            }
            switch (op.mCmd) {
                case 1:
                    f.setNextAnim(op.mPopExitAnim);
                    this.mManager.removeFragment(f);
                    break;
                case 3:
                    f.setNextAnim(op.mPopEnterAnim);
                    this.mManager.addFragment(f, false);
                    break;
                case 4:
                    f.setNextAnim(op.mPopEnterAnim);
                    this.mManager.showFragment(f);
                    break;
                case 5:
                    f.setNextAnim(op.mPopExitAnim);
                    this.mManager.hideFragment(f);
                    break;
                case 6:
                    f.setNextAnim(op.mPopEnterAnim);
                    this.mManager.attachFragment(f);
                    break;
                case 7:
                    f.setNextAnim(op.mPopExitAnim);
                    this.mManager.detachFragment(f);
                    break;
                case 8:
                    this.mManager.setPrimaryNavigationFragment(null);
                    break;
                case 9:
                    this.mManager.setPrimaryNavigationFragment(f);
                    break;
                case 10:
                    this.mManager.setMaxLifecycle(f, op.mOldMaxState);
                    break;
                default:
                    StringBuilder sb = new StringBuilder();
                    sb.append("Unknown cmd: ");
                    sb.append(op.mCmd);
                    throw new IllegalArgumentException(sb.toString());
            }
            if (!(this.mReorderingAllowed || op.mCmd == 3 || f == null)) {
                this.mManager.moveFragmentToExpectedState(f);
            }
        }
        if (this.mReorderingAllowed == 0 && moveToState) {
            FragmentManagerImpl fragmentManagerImpl = this.mManager;
            fragmentManagerImpl.moveToState(fragmentManagerImpl.mCurState, true);
        }
    }

    /* access modifiers changed from: 0000 */
    public Fragment expandOps(ArrayList<Fragment> added, Fragment oldPrimaryNav) {
        int opNum = 0;
        while (opNum < this.mOps.size()) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            int i = op.mCmd;
            if (i != 1) {
                if (i == 2) {
                    Fragment f = op.mFragment;
                    int containerId = f.mContainerId;
                    boolean alreadyAdded = false;
                    for (int i2 = added.size() - 1; i2 >= 0; i2--) {
                        Fragment old = (Fragment) added.get(i2);
                        if (old.mContainerId == containerId) {
                            if (old == f) {
                                alreadyAdded = true;
                            } else {
                                if (old == oldPrimaryNav) {
                                    this.mOps.add(opNum, new C0275Op(9, old));
                                    opNum++;
                                    oldPrimaryNav = null;
                                }
                                C0275Op removeOp = new C0275Op(3, old);
                                removeOp.mEnterAnim = op.mEnterAnim;
                                removeOp.mPopEnterAnim = op.mPopEnterAnim;
                                removeOp.mExitAnim = op.mExitAnim;
                                removeOp.mPopExitAnim = op.mPopExitAnim;
                                this.mOps.add(opNum, removeOp);
                                added.remove(old);
                                opNum++;
                            }
                        }
                    }
                    if (alreadyAdded) {
                        this.mOps.remove(opNum);
                        opNum--;
                    } else {
                        op.mCmd = 1;
                        added.add(f);
                    }
                } else if (i == 3 || i == 6) {
                    added.remove(op.mFragment);
                    if (op.mFragment == oldPrimaryNav) {
                        this.mOps.add(opNum, new C0275Op(9, op.mFragment));
                        opNum++;
                        oldPrimaryNav = null;
                    }
                } else if (i != 7) {
                    if (i == 8) {
                        this.mOps.add(opNum, new C0275Op(9, oldPrimaryNav));
                        opNum++;
                        oldPrimaryNav = op.mFragment;
                    }
                }
                opNum++;
            }
            added.add(op.mFragment);
            opNum++;
        }
        return oldPrimaryNav;
    }

    /* access modifiers changed from: 0000 */
    public Fragment trackAddedFragmentsInPop(ArrayList<Fragment> added, Fragment oldPrimaryNav) {
        for (int opNum = this.mOps.size() - 1; opNum >= 0; opNum--) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            int i = op.mCmd;
            if (i != 1) {
                if (i != 3) {
                    switch (i) {
                        case 6:
                            break;
                        case 7:
                            break;
                        case 8:
                            oldPrimaryNav = null;
                            break;
                        case 9:
                            oldPrimaryNav = op.mFragment;
                            break;
                        case 10:
                            op.mCurrentMaxState = op.mOldMaxState;
                            break;
                    }
                }
                added.add(op.mFragment);
            }
            added.remove(op.mFragment);
        }
        return oldPrimaryNav;
    }

    /* access modifiers changed from: 0000 */
    public boolean isPostponed() {
        for (int opNum = 0; opNum < this.mOps.size(); opNum++) {
            if (isFragmentPostponed((C0275Op) this.mOps.get(opNum))) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: 0000 */
    public void setOnStartPostponedListener(OnStartEnterTransitionListener listener) {
        for (int opNum = 0; opNum < this.mOps.size(); opNum++) {
            C0275Op op = (C0275Op) this.mOps.get(opNum);
            if (isFragmentPostponed(op)) {
                op.mFragment.setOnStartEnterTransitionListener(listener);
            }
        }
    }

    private static boolean isFragmentPostponed(C0275Op op) {
        Fragment fragment = op.mFragment;
        return fragment != null && fragment.mAdded && fragment.mView != null && !fragment.mDetached && !fragment.mHidden && fragment.isPostponed();
    }

    public String getName() {
        return this.mName;
    }

    public boolean isEmpty() {
        return this.mOps.isEmpty();
    }
}
