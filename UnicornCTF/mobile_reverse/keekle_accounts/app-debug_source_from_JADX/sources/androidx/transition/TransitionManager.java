package androidx.transition;

import android.view.View;
import android.view.View.OnAttachStateChangeListener;
import android.view.ViewGroup;
import android.view.ViewTreeObserver.OnPreDrawListener;
import androidx.collection.ArrayMap;
import androidx.core.view.ViewCompat;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;

public class TransitionManager {
    private static final String LOG_TAG = "TransitionManager";
    private static Transition sDefaultTransition = new AutoTransition();
    static ArrayList<ViewGroup> sPendingTransitions = new ArrayList<>();
    private static ThreadLocal<WeakReference<ArrayMap<ViewGroup, ArrayList<Transition>>>> sRunningTransitions = new ThreadLocal<>();
    private ArrayMap<Scene, ArrayMap<Scene, Transition>> mScenePairTransitions = new ArrayMap<>();
    private ArrayMap<Scene, Transition> mSceneTransitions = new ArrayMap<>();

    private static class MultiListener implements OnPreDrawListener, OnAttachStateChangeListener {
        ViewGroup mSceneRoot;
        Transition mTransition;

        MultiListener(Transition transition, ViewGroup sceneRoot) {
            this.mTransition = transition;
            this.mSceneRoot = sceneRoot;
        }

        private void removeListeners() {
            this.mSceneRoot.getViewTreeObserver().removeOnPreDrawListener(this);
            this.mSceneRoot.removeOnAttachStateChangeListener(this);
        }

        public void onViewAttachedToWindow(View v) {
        }

        public void onViewDetachedFromWindow(View v) {
            removeListeners();
            TransitionManager.sPendingTransitions.remove(this.mSceneRoot);
            ArrayList<Transition> runningTransitions = (ArrayList) TransitionManager.getRunningTransitions().get(this.mSceneRoot);
            if (runningTransitions != null && runningTransitions.size() > 0) {
                Iterator it = runningTransitions.iterator();
                while (it.hasNext()) {
                    ((Transition) it.next()).resume(this.mSceneRoot);
                }
            }
            this.mTransition.clearValues(true);
        }

        public boolean onPreDraw() {
            removeListeners();
            if (!TransitionManager.sPendingTransitions.remove(this.mSceneRoot)) {
                return true;
            }
            final ArrayMap<ViewGroup, ArrayList<Transition>> runningTransitions = TransitionManager.getRunningTransitions();
            ArrayList arrayList = (ArrayList) runningTransitions.get(this.mSceneRoot);
            ArrayList arrayList2 = null;
            if (arrayList == null) {
                arrayList = new ArrayList();
                runningTransitions.put(this.mSceneRoot, arrayList);
            } else if (arrayList.size() > 0) {
                arrayList2 = new ArrayList(arrayList);
            }
            arrayList.add(this.mTransition);
            this.mTransition.addListener(new TransitionListenerAdapter() {
                public void onTransitionEnd(Transition transition) {
                    ((ArrayList) runningTransitions.get(MultiListener.this.mSceneRoot)).remove(transition);
                }
            });
            this.mTransition.captureValues(this.mSceneRoot, false);
            if (arrayList2 != null) {
                Iterator it = arrayList2.iterator();
                while (it.hasNext()) {
                    ((Transition) it.next()).resume(this.mSceneRoot);
                }
            }
            this.mTransition.playTransition(this.mSceneRoot);
            return true;
        }
    }

    public void setTransition(Scene scene, Transition transition) {
        this.mSceneTransitions.put(scene, transition);
    }

    public void setTransition(Scene fromScene, Scene toScene, Transition transition) {
        ArrayMap arrayMap = (ArrayMap) this.mScenePairTransitions.get(toScene);
        if (arrayMap == null) {
            arrayMap = new ArrayMap();
            this.mScenePairTransitions.put(toScene, arrayMap);
        }
        arrayMap.put(fromScene, transition);
    }

    private Transition getTransition(Scene scene) {
        ViewGroup sceneRoot = scene.getSceneRoot();
        if (sceneRoot != null) {
            Scene currScene = Scene.getCurrentScene(sceneRoot);
            if (currScene != null) {
                ArrayMap<Scene, Transition> sceneTransitionMap = (ArrayMap) this.mScenePairTransitions.get(scene);
                if (sceneTransitionMap != null) {
                    Transition transition = (Transition) sceneTransitionMap.get(currScene);
                    if (transition != null) {
                        return transition;
                    }
                }
            }
        }
        Transition transition2 = (Transition) this.mSceneTransitions.get(scene);
        return transition2 != null ? transition2 : sDefaultTransition;
    }

    private static void changeScene(Scene scene, Transition transition) {
        ViewGroup sceneRoot = scene.getSceneRoot();
        if (sPendingTransitions.contains(sceneRoot)) {
            return;
        }
        if (transition == null) {
            scene.enter();
            return;
        }
        sPendingTransitions.add(sceneRoot);
        Transition transitionClone = transition.clone();
        transitionClone.setSceneRoot(sceneRoot);
        Scene oldScene = Scene.getCurrentScene(sceneRoot);
        if (oldScene != null && oldScene.isCreatedFromLayoutResource()) {
            transitionClone.setCanRemoveViews(true);
        }
        sceneChangeSetup(sceneRoot, transitionClone);
        scene.enter();
        sceneChangeRunTransition(sceneRoot, transitionClone);
    }

    static ArrayMap<ViewGroup, ArrayList<Transition>> getRunningTransitions() {
        WeakReference<ArrayMap<ViewGroup, ArrayList<Transition>>> runningTransitions = (WeakReference) sRunningTransitions.get();
        if (runningTransitions != null) {
            ArrayMap<ViewGroup, ArrayList<Transition>> transitions = (ArrayMap) runningTransitions.get();
            if (transitions != null) {
                return transitions;
            }
        }
        ArrayMap<ViewGroup, ArrayList<Transition>> transitions2 = new ArrayMap<>();
        sRunningTransitions.set(new WeakReference(transitions2));
        return transitions2;
    }

    private static void sceneChangeRunTransition(ViewGroup sceneRoot, Transition transition) {
        if (transition != null && sceneRoot != null) {
            MultiListener listener = new MultiListener(transition, sceneRoot);
            sceneRoot.addOnAttachStateChangeListener(listener);
            sceneRoot.getViewTreeObserver().addOnPreDrawListener(listener);
        }
    }

    private static void sceneChangeSetup(ViewGroup sceneRoot, Transition transition) {
        ArrayList<Transition> runningTransitions = (ArrayList) getRunningTransitions().get(sceneRoot);
        if (runningTransitions != null && runningTransitions.size() > 0) {
            Iterator it = runningTransitions.iterator();
            while (it.hasNext()) {
                ((Transition) it.next()).pause(sceneRoot);
            }
        }
        if (transition != null) {
            transition.captureValues(sceneRoot, true);
        }
        Scene previousScene = Scene.getCurrentScene(sceneRoot);
        if (previousScene != null) {
            previousScene.exit();
        }
    }

    public void transitionTo(Scene scene) {
        changeScene(scene, getTransition(scene));
    }

    /* renamed from: go */
    public static void m14go(Scene scene) {
        changeScene(scene, sDefaultTransition);
    }

    /* renamed from: go */
    public static void m15go(Scene scene, Transition transition) {
        changeScene(scene, transition);
    }

    public static void beginDelayedTransition(ViewGroup sceneRoot) {
        beginDelayedTransition(sceneRoot, null);
    }

    public static void beginDelayedTransition(ViewGroup sceneRoot, Transition transition) {
        if (!sPendingTransitions.contains(sceneRoot) && ViewCompat.isLaidOut(sceneRoot)) {
            sPendingTransitions.add(sceneRoot);
            if (transition == null) {
                transition = sDefaultTransition;
            }
            Transition transitionClone = transition.clone();
            sceneChangeSetup(sceneRoot, transitionClone);
            Scene.setCurrentScene(sceneRoot, null);
            sceneChangeRunTransition(sceneRoot, transitionClone);
        }
    }

    public static void endTransitions(ViewGroup sceneRoot) {
        sPendingTransitions.remove(sceneRoot);
        ArrayList<Transition> runningTransitions = (ArrayList) getRunningTransitions().get(sceneRoot);
        if (runningTransitions != null && !runningTransitions.isEmpty()) {
            ArrayList<Transition> copy = new ArrayList<>(runningTransitions);
            for (int i = copy.size() - 1; i >= 0; i--) {
                ((Transition) copy.get(i)).forceToEnd(sceneRoot);
            }
        }
    }
}
