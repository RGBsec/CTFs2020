package androidx.lifecycle;

import androidx.arch.core.util.Function;

public class Transformations {
    private Transformations() {
    }

    public static <X, Y> LiveData<Y> map(LiveData<X> source, final Function<X, Y> mapFunction) {
        final MediatorLiveData<Y> result = new MediatorLiveData<>();
        result.addSource(source, new Observer<X>() {
            public void onChanged(X x) {
                result.setValue(mapFunction.apply(x));
            }
        });
        return result;
    }

    public static <X, Y> LiveData<Y> switchMap(LiveData<X> source, final Function<X, LiveData<Y>> switchMapFunction) {
        final MediatorLiveData<Y> result = new MediatorLiveData<>();
        result.addSource(source, new Observer<X>() {
            LiveData<Y> mSource;

            public void onChanged(X x) {
                LiveData<Y> newLiveData = (LiveData) switchMapFunction.apply(x);
                LiveData<Y> liveData = this.mSource;
                if (liveData != newLiveData) {
                    if (liveData != null) {
                        result.removeSource(liveData);
                    }
                    this.mSource = newLiveData;
                    if (newLiveData != null) {
                        result.addSource(newLiveData, new Observer<Y>() {
                            public void onChanged(Y y) {
                                result.setValue(y);
                            }
                        });
                    }
                }
            }
        });
        return result;
    }

    public static <X> LiveData<X> distinctUntilChanged(LiveData<X> source) {
        final MediatorLiveData<X> outputLiveData = new MediatorLiveData<>();
        outputLiveData.addSource(source, new Observer<X>() {
            boolean mFirstTime = true;

            public void onChanged(X currentValue) {
                X previousValue = outputLiveData.getValue();
                if (this.mFirstTime || ((previousValue == null && currentValue != null) || (previousValue != null && !previousValue.equals(currentValue)))) {
                    this.mFirstTime = false;
                    outputLiveData.setValue(currentValue);
                }
            }
        });
        return outputLiveData;
    }
}
