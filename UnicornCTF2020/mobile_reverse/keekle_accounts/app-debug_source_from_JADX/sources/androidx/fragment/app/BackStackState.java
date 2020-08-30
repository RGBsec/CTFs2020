package androidx.fragment.app;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.text.TextUtils;
import android.util.Log;
import androidx.lifecycle.Lifecycle.State;
import java.util.ArrayList;

final class BackStackState implements Parcelable {
    public static final Creator<BackStackState> CREATOR = new Creator<BackStackState>() {
        public BackStackState createFromParcel(Parcel in) {
            return new BackStackState(in);
        }

        public BackStackState[] newArray(int size) {
            return new BackStackState[size];
        }
    };
    final int mBreadCrumbShortTitleRes;
    final CharSequence mBreadCrumbShortTitleText;
    final int mBreadCrumbTitleRes;
    final CharSequence mBreadCrumbTitleText;
    final int[] mCurrentMaxLifecycleStates;
    final ArrayList<String> mFragmentWhos;
    final int mIndex;
    final String mName;
    final int[] mOldMaxLifecycleStates;
    final int[] mOps;
    final boolean mReorderingAllowed;
    final ArrayList<String> mSharedElementSourceNames;
    final ArrayList<String> mSharedElementTargetNames;
    final int mTransition;
    final int mTransitionStyle;

    public BackStackState(BackStackRecord bse) {
        int numOps = bse.mOps.size();
        this.mOps = new int[(numOps * 5)];
        if (bse.mAddToBackStack) {
            this.mFragmentWhos = new ArrayList<>(numOps);
            this.mOldMaxLifecycleStates = new int[numOps];
            this.mCurrentMaxLifecycleStates = new int[numOps];
            int pos = 0;
            int opNum = 0;
            while (opNum < numOps) {
                C0275Op op = (C0275Op) bse.mOps.get(opNum);
                int pos2 = pos + 1;
                this.mOps[pos] = op.mCmd;
                this.mFragmentWhos.add(op.mFragment != null ? op.mFragment.mWho : null);
                int pos3 = pos2 + 1;
                this.mOps[pos2] = op.mEnterAnim;
                int pos4 = pos3 + 1;
                this.mOps[pos3] = op.mExitAnim;
                int pos5 = pos4 + 1;
                this.mOps[pos4] = op.mPopEnterAnim;
                int pos6 = pos5 + 1;
                this.mOps[pos5] = op.mPopExitAnim;
                this.mOldMaxLifecycleStates[opNum] = op.mOldMaxState.ordinal();
                this.mCurrentMaxLifecycleStates[opNum] = op.mCurrentMaxState.ordinal();
                opNum++;
                pos = pos6;
            }
            this.mTransition = bse.mTransition;
            this.mTransitionStyle = bse.mTransitionStyle;
            this.mName = bse.mName;
            this.mIndex = bse.mIndex;
            this.mBreadCrumbTitleRes = bse.mBreadCrumbTitleRes;
            this.mBreadCrumbTitleText = bse.mBreadCrumbTitleText;
            this.mBreadCrumbShortTitleRes = bse.mBreadCrumbShortTitleRes;
            this.mBreadCrumbShortTitleText = bse.mBreadCrumbShortTitleText;
            this.mSharedElementSourceNames = bse.mSharedElementSourceNames;
            this.mSharedElementTargetNames = bse.mSharedElementTargetNames;
            this.mReorderingAllowed = bse.mReorderingAllowed;
            return;
        }
        throw new IllegalStateException("Not on back stack");
    }

    public BackStackState(Parcel in) {
        this.mOps = in.createIntArray();
        this.mFragmentWhos = in.createStringArrayList();
        this.mOldMaxLifecycleStates = in.createIntArray();
        this.mCurrentMaxLifecycleStates = in.createIntArray();
        this.mTransition = in.readInt();
        this.mTransitionStyle = in.readInt();
        this.mName = in.readString();
        this.mIndex = in.readInt();
        this.mBreadCrumbTitleRes = in.readInt();
        this.mBreadCrumbTitleText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        this.mBreadCrumbShortTitleRes = in.readInt();
        this.mBreadCrumbShortTitleText = (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(in);
        this.mSharedElementSourceNames = in.createStringArrayList();
        this.mSharedElementTargetNames = in.createStringArrayList();
        this.mReorderingAllowed = in.readInt() != 0;
    }

    public BackStackRecord instantiate(FragmentManagerImpl fm) {
        BackStackRecord bse = new BackStackRecord(fm);
        int pos = 0;
        int num = 0;
        while (pos < this.mOps.length) {
            C0275Op op = new C0275Op();
            int pos2 = pos + 1;
            op.mCmd = this.mOps[pos];
            if (FragmentManagerImpl.DEBUG) {
                StringBuilder sb = new StringBuilder();
                sb.append("Instantiate ");
                sb.append(bse);
                sb.append(" op #");
                sb.append(num);
                sb.append(" base fragment #");
                sb.append(this.mOps[pos2]);
                Log.v("FragmentManager", sb.toString());
            }
            String fWho = (String) this.mFragmentWhos.get(num);
            if (fWho != null) {
                op.mFragment = (Fragment) fm.mActive.get(fWho);
            } else {
                op.mFragment = null;
            }
            op.mOldMaxState = State.values()[this.mOldMaxLifecycleStates[num]];
            op.mCurrentMaxState = State.values()[this.mCurrentMaxLifecycleStates[num]];
            int pos3 = pos2 + 1;
            op.mEnterAnim = this.mOps[pos2];
            int pos4 = pos3 + 1;
            op.mExitAnim = this.mOps[pos3];
            int pos5 = pos4 + 1;
            op.mPopEnterAnim = this.mOps[pos4];
            int pos6 = pos5 + 1;
            op.mPopExitAnim = this.mOps[pos5];
            bse.mEnterAnim = op.mEnterAnim;
            bse.mExitAnim = op.mExitAnim;
            bse.mPopEnterAnim = op.mPopEnterAnim;
            bse.mPopExitAnim = op.mPopExitAnim;
            bse.addOp(op);
            num++;
            pos = pos6;
        }
        bse.mTransition = this.mTransition;
        bse.mTransitionStyle = this.mTransitionStyle;
        bse.mName = this.mName;
        bse.mIndex = this.mIndex;
        bse.mAddToBackStack = true;
        bse.mBreadCrumbTitleRes = this.mBreadCrumbTitleRes;
        bse.mBreadCrumbTitleText = this.mBreadCrumbTitleText;
        bse.mBreadCrumbShortTitleRes = this.mBreadCrumbShortTitleRes;
        bse.mBreadCrumbShortTitleText = this.mBreadCrumbShortTitleText;
        bse.mSharedElementSourceNames = this.mSharedElementSourceNames;
        bse.mSharedElementTargetNames = this.mSharedElementTargetNames;
        bse.mReorderingAllowed = this.mReorderingAllowed;
        bse.bumpBackStackNesting(1);
        return bse;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeIntArray(this.mOps);
        dest.writeStringList(this.mFragmentWhos);
        dest.writeIntArray(this.mOldMaxLifecycleStates);
        dest.writeIntArray(this.mCurrentMaxLifecycleStates);
        dest.writeInt(this.mTransition);
        dest.writeInt(this.mTransitionStyle);
        dest.writeString(this.mName);
        dest.writeInt(this.mIndex);
        dest.writeInt(this.mBreadCrumbTitleRes);
        TextUtils.writeToParcel(this.mBreadCrumbTitleText, dest, 0);
        dest.writeInt(this.mBreadCrumbShortTitleRes);
        TextUtils.writeToParcel(this.mBreadCrumbShortTitleText, dest, 0);
        dest.writeStringList(this.mSharedElementSourceNames);
        dest.writeStringList(this.mSharedElementTargetNames);
        dest.writeInt(this.mReorderingAllowed ? 1 : 0);
    }
}
