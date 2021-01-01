package androidx.lifecycle;

import androidx.arch.core.internal.FastSafeIterableMap;
import androidx.lifecycle.Lifecycle.Event;
import androidx.lifecycle.Lifecycle.State;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map.Entry;

public class LifecycleRegistry extends Lifecycle {
    private int mAddingObserverCounter = 0;
    private boolean mHandlingEvent = false;
    private final WeakReference<LifecycleOwner> mLifecycleOwner;
    private boolean mNewEventOccurred = false;
    private FastSafeIterableMap<LifecycleObserver, ObserverWithState> mObserverMap = new FastSafeIterableMap<>();
    private ArrayList<State> mParentStates = new ArrayList<>();
    private State mState;

    /* renamed from: androidx.lifecycle.LifecycleRegistry$1 */
    static /* synthetic */ class C02931 {
        static final /* synthetic */ int[] $SwitchMap$androidx$lifecycle$Lifecycle$Event;
        static final /* synthetic */ int[] $SwitchMap$androidx$lifecycle$Lifecycle$State;

        static {
            int[] iArr = new int[State.values().length];
            $SwitchMap$androidx$lifecycle$Lifecycle$State = iArr;
            try {
                iArr[State.INITIALIZED.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[State.CREATED.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[State.STARTED.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[State.RESUMED.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$State[State.DESTROYED.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            int[] iArr2 = new int[Event.values().length];
            $SwitchMap$androidx$lifecycle$Lifecycle$Event = iArr2;
            try {
                iArr2[Event.ON_CREATE.ordinal()] = 1;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_STOP.ordinal()] = 2;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_START.ordinal()] = 3;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_PAUSE.ordinal()] = 4;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_RESUME.ordinal()] = 5;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_DESTROY.ordinal()] = 6;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$androidx$lifecycle$Lifecycle$Event[Event.ON_ANY.ordinal()] = 7;
            } catch (NoSuchFieldError e12) {
            }
        }
    }

    static class ObserverWithState {
        LifecycleEventObserver mLifecycleObserver;
        State mState;

        ObserverWithState(LifecycleObserver observer, State initialState) {
            this.mLifecycleObserver = Lifecycling.lifecycleEventObserver(observer);
            this.mState = initialState;
        }

        /* access modifiers changed from: 0000 */
        public void dispatchEvent(LifecycleOwner owner, Event event) {
            State newState = LifecycleRegistry.getStateAfter(event);
            this.mState = LifecycleRegistry.min(this.mState, newState);
            this.mLifecycleObserver.onStateChanged(owner, event);
            this.mState = newState;
        }
    }

    public LifecycleRegistry(LifecycleOwner provider) {
        this.mLifecycleOwner = new WeakReference<>(provider);
        this.mState = State.INITIALIZED;
    }

    @Deprecated
    public void markState(State state) {
        setCurrentState(state);
    }

    public void setCurrentState(State state) {
        moveToState(state);
    }

    public void handleLifecycleEvent(Event event) {
        moveToState(getStateAfter(event));
    }

    private void moveToState(State next) {
        if (this.mState != next) {
            this.mState = next;
            if (this.mHandlingEvent || this.mAddingObserverCounter != 0) {
                this.mNewEventOccurred = true;
                return;
            }
            this.mHandlingEvent = true;
            sync();
            this.mHandlingEvent = false;
        }
    }

    private boolean isSynced() {
        boolean z = true;
        if (this.mObserverMap.size() == 0) {
            return true;
        }
        State eldestObserverState = ((ObserverWithState) this.mObserverMap.eldest().getValue()).mState;
        State newestObserverState = ((ObserverWithState) this.mObserverMap.newest().getValue()).mState;
        if (!(eldestObserverState == newestObserverState && this.mState == newestObserverState)) {
            z = false;
        }
        return z;
    }

    private State calculateTargetState(LifecycleObserver observer) {
        Entry<LifecycleObserver, ObserverWithState> previous = this.mObserverMap.ceil(observer);
        State parentState = null;
        State siblingState = previous != null ? ((ObserverWithState) previous.getValue()).mState : null;
        if (!this.mParentStates.isEmpty()) {
            ArrayList<State> arrayList = this.mParentStates;
            parentState = (State) arrayList.get(arrayList.size() - 1);
        }
        return min(min(this.mState, siblingState), parentState);
    }

    public void addObserver(LifecycleObserver observer) {
        ObserverWithState statefulObserver = new ObserverWithState(observer, this.mState == State.DESTROYED ? State.DESTROYED : State.INITIALIZED);
        if (((ObserverWithState) this.mObserverMap.putIfAbsent(observer, statefulObserver)) == null) {
            LifecycleOwner lifecycleOwner = (LifecycleOwner) this.mLifecycleOwner.get();
            if (lifecycleOwner != null) {
                boolean isReentrance = this.mAddingObserverCounter != 0 || this.mHandlingEvent;
                State targetState = calculateTargetState(observer);
                this.mAddingObserverCounter++;
                while (statefulObserver.mState.compareTo(targetState) < 0 && this.mObserverMap.contains(observer)) {
                    pushParentState(statefulObserver.mState);
                    statefulObserver.dispatchEvent(lifecycleOwner, upEvent(statefulObserver.mState));
                    popParentState();
                    targetState = calculateTargetState(observer);
                }
                if (!isReentrance) {
                    sync();
                }
                this.mAddingObserverCounter--;
            }
        }
    }

    private void popParentState() {
        ArrayList<State> arrayList = this.mParentStates;
        arrayList.remove(arrayList.size() - 1);
    }

    private void pushParentState(State state) {
        this.mParentStates.add(state);
    }

    public void removeObserver(LifecycleObserver observer) {
        this.mObserverMap.remove(observer);
    }

    public int getObserverCount() {
        return this.mObserverMap.size();
    }

    public State getCurrentState() {
        return this.mState;
    }

    static State getStateAfter(Event event) {
        switch (C02931.$SwitchMap$androidx$lifecycle$Lifecycle$Event[event.ordinal()]) {
            case 1:
            case 2:
                return State.CREATED;
            case 3:
            case 4:
                return State.STARTED;
            case 5:
                return State.RESUMED;
            case 6:
                return State.DESTROYED;
            default:
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected event value ");
                sb.append(event);
                throw new IllegalArgumentException(sb.toString());
        }
    }

    private static Event downEvent(State state) {
        int i = C02931.$SwitchMap$androidx$lifecycle$Lifecycle$State[state.ordinal()];
        if (i == 1) {
            throw new IllegalArgumentException();
        } else if (i == 2) {
            return Event.ON_DESTROY;
        } else {
            if (i == 3) {
                return Event.ON_STOP;
            }
            if (i == 4) {
                return Event.ON_PAUSE;
            }
            if (i != 5) {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected state value ");
                sb.append(state);
                throw new IllegalArgumentException(sb.toString());
            }
            throw new IllegalArgumentException();
        }
    }

    private static Event upEvent(State state) {
        int i = C02931.$SwitchMap$androidx$lifecycle$Lifecycle$State[state.ordinal()];
        if (i != 1) {
            if (i == 2) {
                return Event.ON_START;
            }
            if (i == 3) {
                return Event.ON_RESUME;
            }
            if (i == 4) {
                throw new IllegalArgumentException();
            } else if (i != 5) {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected state value ");
                sb.append(state);
                throw new IllegalArgumentException(sb.toString());
            }
        }
        return Event.ON_CREATE;
    }

    private void forwardPass(LifecycleOwner lifecycleOwner) {
        Iterator<Entry<LifecycleObserver, ObserverWithState>> ascendingIterator = this.mObserverMap.iteratorWithAdditions();
        while (ascendingIterator.hasNext() && !this.mNewEventOccurred) {
            Entry<LifecycleObserver, ObserverWithState> entry = (Entry) ascendingIterator.next();
            ObserverWithState observer = (ObserverWithState) entry.getValue();
            while (observer.mState.compareTo(this.mState) < 0 && !this.mNewEventOccurred && this.mObserverMap.contains(entry.getKey())) {
                pushParentState(observer.mState);
                observer.dispatchEvent(lifecycleOwner, upEvent(observer.mState));
                popParentState();
            }
        }
    }

    private void backwardPass(LifecycleOwner lifecycleOwner) {
        Iterator<Entry<LifecycleObserver, ObserverWithState>> descendingIterator = this.mObserverMap.descendingIterator();
        while (descendingIterator.hasNext() && !this.mNewEventOccurred) {
            Entry<LifecycleObserver, ObserverWithState> entry = (Entry) descendingIterator.next();
            ObserverWithState observer = (ObserverWithState) entry.getValue();
            while (observer.mState.compareTo(this.mState) > 0 && !this.mNewEventOccurred && this.mObserverMap.contains(entry.getKey())) {
                Event event = downEvent(observer.mState);
                pushParentState(getStateAfter(event));
                observer.dispatchEvent(lifecycleOwner, event);
                popParentState();
            }
        }
    }

    private void sync() {
        LifecycleOwner lifecycleOwner = (LifecycleOwner) this.mLifecycleOwner.get();
        if (lifecycleOwner != null) {
            while (!isSynced()) {
                this.mNewEventOccurred = false;
                if (this.mState.compareTo(((ObserverWithState) this.mObserverMap.eldest().getValue()).mState) < 0) {
                    backwardPass(lifecycleOwner);
                }
                Entry<LifecycleObserver, ObserverWithState> newest = this.mObserverMap.newest();
                if (!this.mNewEventOccurred && newest != null && this.mState.compareTo(((ObserverWithState) newest.getValue()).mState) > 0) {
                    forwardPass(lifecycleOwner);
                }
            }
            this.mNewEventOccurred = false;
            return;
        }
        throw new IllegalStateException("LifecycleOwner of this LifecycleRegistry is alreadygarbage collected. It is too late to change lifecycle state.");
    }

    static State min(State state1, State state2) {
        return (state2 == null || state2.compareTo(state1) >= 0) ? state1 : state2;
    }
}
