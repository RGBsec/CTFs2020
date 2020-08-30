package com.google.android.material.stateful;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.ClassLoaderCreator;
import android.os.Parcelable.Creator;
import androidx.collection.SimpleArrayMap;
import androidx.customview.view.AbsSavedState;

public class ExtendableSavedState extends AbsSavedState {
    public static final Creator<ExtendableSavedState> CREATOR = new ClassLoaderCreator<ExtendableSavedState>() {
        public ExtendableSavedState createFromParcel(Parcel in, ClassLoader loader) {
            return new ExtendableSavedState(in, loader);
        }

        public ExtendableSavedState createFromParcel(Parcel in) {
            return new ExtendableSavedState(in, null);
        }

        public ExtendableSavedState[] newArray(int size) {
            return new ExtendableSavedState[size];
        }
    };
    public final SimpleArrayMap<String, Bundle> extendableStates;

    public ExtendableSavedState(Parcelable superState) {
        super(superState);
        this.extendableStates = new SimpleArrayMap<>();
    }

    private ExtendableSavedState(Parcel in, ClassLoader loader) {
        super(in, loader);
        int size = in.readInt();
        String[] keys = new String[size];
        in.readStringArray(keys);
        Bundle[] states = new Bundle[size];
        in.readTypedArray(states, Bundle.CREATOR);
        this.extendableStates = new SimpleArrayMap<>(size);
        for (int i = 0; i < size; i++) {
            this.extendableStates.put(keys[i], states[i]);
        }
    }

    public void writeToParcel(Parcel out, int flags) {
        super.writeToParcel(out, flags);
        int size = this.extendableStates.size();
        out.writeInt(size);
        String[] keys = new String[size];
        Bundle[] states = new Bundle[size];
        for (int i = 0; i < size; i++) {
            keys[i] = (String) this.extendableStates.keyAt(i);
            states[i] = (Bundle) this.extendableStates.valueAt(i);
        }
        out.writeStringArray(keys);
        out.writeTypedArray(states, 0);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ExtendableSavedState{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" states=");
        sb.append(this.extendableStates);
        sb.append("}");
        return sb.toString();
    }
}
