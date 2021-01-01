package androidx.fragment.app;

import android.graphics.Rect;
import android.os.Build.VERSION;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.collection.ArrayMap;
import androidx.core.app.SharedElementCallback;
import androidx.core.view.OneShotPreDrawListener;
import androidx.core.view.ViewCompat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class FragmentTransition {
    private static final int[] INVERSE_OPS = {0, 3, 0, 1, 5, 4, 7, 6, 9, 8, 10};
    private static final FragmentTransitionImpl PLATFORM_IMPL = (VERSION.SDK_INT >= 21 ? new FragmentTransitionCompat21() : null);
    private static final FragmentTransitionImpl SUPPORT_IMPL = resolveSupportImpl();

    static class FragmentContainerTransition {
        public Fragment firstOut;
        public boolean firstOutIsPop;
        public BackStackRecord firstOutTransaction;
        public Fragment lastIn;
        public boolean lastInIsPop;
        public BackStackRecord lastInTransaction;

        FragmentContainerTransition() {
        }
    }

    private static FragmentTransitionImpl resolveSupportImpl() {
        try {
            return (FragmentTransitionImpl) Class.forName("androidx.transition.FragmentTransitionSupport").getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (Exception e) {
            return null;
        }
    }

    static void startTransitions(FragmentManagerImpl fragmentManager, ArrayList<BackStackRecord> records, ArrayList<Boolean> isRecordPop, int startIndex, int endIndex, boolean isReordered) {
        if (fragmentManager.mCurState >= 1) {
            SparseArray<FragmentContainerTransition> transitioningFragments = new SparseArray<>();
            for (int i = startIndex; i < endIndex; i++) {
                BackStackRecord record = (BackStackRecord) records.get(i);
                if (((Boolean) isRecordPop.get(i)).booleanValue()) {
                    calculatePopFragments(record, transitioningFragments, isReordered);
                } else {
                    calculateFragments(record, transitioningFragments, isReordered);
                }
            }
            if (transitioningFragments.size() != 0) {
                View nonExistentView = new View(fragmentManager.mHost.getContext());
                int numContainers = transitioningFragments.size();
                for (int i2 = 0; i2 < numContainers; i2++) {
                    int containerId = transitioningFragments.keyAt(i2);
                    ArrayMap<String, String> nameOverrides = calculateNameOverrides(containerId, records, isRecordPop, startIndex, endIndex);
                    FragmentContainerTransition containerTransition = (FragmentContainerTransition) transitioningFragments.valueAt(i2);
                    if (isReordered) {
                        configureTransitionsReordered(fragmentManager, containerId, containerTransition, nonExistentView, nameOverrides);
                    } else {
                        configureTransitionsOrdered(fragmentManager, containerId, containerTransition, nonExistentView, nameOverrides);
                    }
                }
            }
        }
    }

    private static ArrayMap<String, String> calculateNameOverrides(int containerId, ArrayList<BackStackRecord> records, ArrayList<Boolean> isRecordPop, int startIndex, int endIndex) {
        ArrayList<String> sources;
        ArrayList<String> targets;
        ArrayMap<String, String> nameOverrides = new ArrayMap<>();
        for (int recordNum = endIndex - 1; recordNum >= startIndex; recordNum--) {
            BackStackRecord record = (BackStackRecord) records.get(recordNum);
            if (record.interactsWith(containerId)) {
                boolean isPop = ((Boolean) isRecordPop.get(recordNum)).booleanValue();
                if (record.mSharedElementSourceNames != null) {
                    int numSharedElements = record.mSharedElementSourceNames.size();
                    if (isPop) {
                        targets = record.mSharedElementSourceNames;
                        sources = record.mSharedElementTargetNames;
                    } else {
                        sources = record.mSharedElementSourceNames;
                        targets = record.mSharedElementTargetNames;
                    }
                    for (int i = 0; i < numSharedElements; i++) {
                        String sourceName = (String) sources.get(i);
                        String targetName = (String) targets.get(i);
                        String previousTarget = (String) nameOverrides.remove(targetName);
                        if (previousTarget != null) {
                            nameOverrides.put(sourceName, previousTarget);
                        } else {
                            nameOverrides.put(sourceName, targetName);
                        }
                    }
                }
            }
        }
        return nameOverrides;
    }

    private static void configureTransitionsReordered(FragmentManagerImpl fragmentManager, int containerId, FragmentContainerTransition fragments, View nonExistentView, ArrayMap<String, String> nameOverrides) {
        ViewGroup sceneRoot;
        Object exitTransition;
        FragmentManagerImpl fragmentManagerImpl = fragmentManager;
        FragmentContainerTransition fragmentContainerTransition = fragments;
        View view = nonExistentView;
        if (fragmentManagerImpl.mContainer.onHasView()) {
            sceneRoot = (ViewGroup) fragmentManagerImpl.mContainer.onFindViewById(containerId);
        } else {
            int i = containerId;
            sceneRoot = null;
        }
        if (sceneRoot != null) {
            Fragment inFragment = fragmentContainerTransition.lastIn;
            Fragment outFragment = fragmentContainerTransition.firstOut;
            FragmentTransitionImpl impl = chooseImpl(outFragment, inFragment);
            if (impl != null) {
                boolean inIsPop = fragmentContainerTransition.lastInIsPop;
                boolean outIsPop = fragmentContainerTransition.firstOutIsPop;
                ArrayList arrayList = new ArrayList();
                ArrayList arrayList2 = new ArrayList();
                Object enterTransition = getEnterTransition(impl, inFragment, inIsPop);
                Object exitTransition2 = getExitTransition(impl, outFragment, outIsPop);
                ArrayList arrayList3 = arrayList2;
                ArrayList arrayList4 = arrayList;
                boolean z = outIsPop;
                boolean inIsPop2 = inIsPop;
                Object enterTransition2 = enterTransition;
                FragmentTransitionImpl impl2 = impl;
                Object sharedElementTransition = configureSharedElementsReordered(impl, sceneRoot, nonExistentView, nameOverrides, fragments, arrayList3, arrayList4, enterTransition2, exitTransition2);
                if (enterTransition2 == null && sharedElementTransition == null) {
                    exitTransition = exitTransition2;
                    if (exitTransition == null) {
                        return;
                    }
                } else {
                    exitTransition = exitTransition2;
                }
                ArrayList<View> exitingViews = configureEnteringExitingViews(impl2, exitTransition, outFragment, arrayList3, view);
                ArrayList arrayList5 = arrayList4;
                ArrayList<View> enteringViews = configureEnteringExitingViews(impl2, enterTransition2, inFragment, arrayList5, view);
                setViewVisibility(enteringViews, 4);
                ArrayList<View> enteringViews2 = enteringViews;
                ArrayList arrayList6 = arrayList5;
                ArrayList<View> exitingViews2 = exitingViews;
                Object transition = mergeTransitions(impl2, enterTransition2, exitTransition, sharedElementTransition, inFragment, inIsPop2);
                if (transition != null) {
                    replaceHide(impl2, exitTransition, outFragment, exitingViews2);
                    ArrayList<String> inNames = impl2.prepareSetNameOverridesReordered(arrayList6);
                    Object transition2 = transition;
                    Object obj = exitTransition;
                    Object obj2 = enterTransition2;
                    impl2.scheduleRemoveTargets(transition, enterTransition2, enteringViews2, exitTransition, exitingViews2, sharedElementTransition, arrayList6);
                    impl2.beginDelayedTransition(sceneRoot, transition2);
                    impl2.setNameOverridesReordered(sceneRoot, arrayList3, arrayList6, inNames, nameOverrides);
                    setViewVisibility(enteringViews2, 0);
                    impl2.swapSharedElementTargets(sharedElementTransition, arrayList3, arrayList6);
                } else {
                    Object obj3 = exitTransition;
                    Object obj4 = enterTransition2;
                    ArrayList arrayList7 = enteringViews2;
                    ArrayList arrayList8 = arrayList3;
                }
            }
        }
    }

    private static void replaceHide(FragmentTransitionImpl impl, Object exitTransition, Fragment exitingFragment, final ArrayList<View> exitingViews) {
        if (exitingFragment != null && exitTransition != null && exitingFragment.mAdded && exitingFragment.mHidden && exitingFragment.mHiddenChanged) {
            exitingFragment.setHideReplaced(true);
            impl.scheduleHideFragmentView(exitTransition, exitingFragment.getView(), exitingViews);
            OneShotPreDrawListener.add(exitingFragment.mContainer, new Runnable() {
                public void run() {
                    FragmentTransition.setViewVisibility(exitingViews, 4);
                }
            });
        }
    }

    private static void configureTransitionsOrdered(FragmentManagerImpl fragmentManager, int containerId, FragmentContainerTransition fragments, View nonExistentView, ArrayMap<String, String> nameOverrides) {
        ViewGroup sceneRoot;
        Object exitTransition;
        Object exitTransition2;
        FragmentManagerImpl fragmentManagerImpl = fragmentManager;
        FragmentContainerTransition fragmentContainerTransition = fragments;
        View view = nonExistentView;
        ArrayMap<String, String> arrayMap = nameOverrides;
        if (fragmentManagerImpl.mContainer.onHasView()) {
            sceneRoot = (ViewGroup) fragmentManagerImpl.mContainer.onFindViewById(containerId);
        } else {
            int i = containerId;
            sceneRoot = null;
        }
        if (sceneRoot != null) {
            Fragment inFragment = fragmentContainerTransition.lastIn;
            Fragment outFragment = fragmentContainerTransition.firstOut;
            FragmentTransitionImpl impl = chooseImpl(outFragment, inFragment);
            if (impl != null) {
                boolean inIsPop = fragmentContainerTransition.lastInIsPop;
                boolean outIsPop = fragmentContainerTransition.firstOutIsPop;
                Object enterTransition = getEnterTransition(impl, inFragment, inIsPop);
                Object exitTransition3 = getExitTransition(impl, outFragment, outIsPop);
                ArrayList arrayList = new ArrayList();
                ArrayList arrayList2 = new ArrayList();
                ArrayList arrayList3 = arrayList;
                Object exitTransition4 = exitTransition3;
                Object enterTransition2 = enterTransition;
                boolean z = outIsPop;
                boolean z2 = inIsPop;
                FragmentTransitionImpl impl2 = impl;
                Fragment outFragment2 = outFragment;
                Object sharedElementTransition = configureSharedElementsOrdered(impl, sceneRoot, nonExistentView, nameOverrides, fragments, arrayList3, arrayList2, enterTransition2, exitTransition4);
                Object enterTransition3 = enterTransition2;
                if (enterTransition3 == null && sharedElementTransition == null) {
                    exitTransition = exitTransition4;
                    if (exitTransition == null) {
                        return;
                    }
                } else {
                    exitTransition = exitTransition4;
                }
                ArrayList arrayList4 = arrayList3;
                ArrayList<View> sharedElementsOut = configureEnteringExitingViews(impl2, exitTransition, outFragment2, arrayList4, view);
                if (sharedElementsOut == null || sharedElementsOut.isEmpty()) {
                    exitTransition2 = null;
                } else {
                    exitTransition2 = exitTransition;
                }
                impl2.addTarget(enterTransition3, view);
                Object transition = mergeTransitions(impl2, enterTransition3, exitTransition2, sharedElementTransition, inFragment, fragmentContainerTransition.lastInIsPop);
                if (transition != null) {
                    ArrayList<View> enteringViews = new ArrayList<>();
                    impl2.scheduleRemoveTargets(transition, enterTransition3, enteringViews, exitTransition2, sharedElementsOut, sharedElementTransition, arrayList2);
                    Object transition2 = transition;
                    ArrayList arrayList5 = arrayList4;
                    Object obj = enterTransition3;
                    scheduleTargetChange(impl2, sceneRoot, inFragment, nonExistentView, arrayList2, enterTransition3, enteringViews, exitTransition2, sharedElementsOut);
                    ArrayList arrayList6 = arrayList2;
                    impl2.setNameOverridesOrdered(sceneRoot, arrayList6, arrayMap);
                    impl2.beginDelayedTransition(sceneRoot, transition2);
                    impl2.scheduleNameReset(sceneRoot, arrayList6, arrayMap);
                } else {
                    ArrayList arrayList7 = arrayList4;
                    Object obj2 = enterTransition3;
                    ArrayList arrayList8 = arrayList2;
                }
            }
        }
    }

    private static void scheduleTargetChange(FragmentTransitionImpl impl, ViewGroup sceneRoot, Fragment inFragment, View nonExistentView, ArrayList<View> sharedElementsIn, Object enterTransition, ArrayList<View> enteringViews, Object exitTransition, ArrayList<View> exitingViews) {
        final Object obj = enterTransition;
        final FragmentTransitionImpl fragmentTransitionImpl = impl;
        final View view = nonExistentView;
        final Fragment fragment = inFragment;
        final ArrayList<View> arrayList = sharedElementsIn;
        final ArrayList<View> arrayList2 = enteringViews;
        final ArrayList<View> arrayList3 = exitingViews;
        final Object obj2 = exitTransition;
        C02772 r0 = new Runnable() {
            public void run() {
                Object obj = obj;
                if (obj != null) {
                    fragmentTransitionImpl.removeTarget(obj, view);
                    arrayList2.addAll(FragmentTransition.configureEnteringExitingViews(fragmentTransitionImpl, obj, fragment, arrayList, view));
                }
                if (arrayList3 != null) {
                    if (obj2 != null) {
                        ArrayList<View> tempExiting = new ArrayList<>();
                        tempExiting.add(view);
                        fragmentTransitionImpl.replaceTargets(obj2, arrayList3, tempExiting);
                    }
                    arrayList3.clear();
                    arrayList3.add(view);
                }
            }
        };
        ViewGroup viewGroup = sceneRoot;
        OneShotPreDrawListener.add(sceneRoot, r0);
    }

    private static FragmentTransitionImpl chooseImpl(Fragment outFragment, Fragment inFragment) {
        ArrayList<Object> transitions = new ArrayList<>();
        if (outFragment != null) {
            Object exitTransition = outFragment.getExitTransition();
            if (exitTransition != null) {
                transitions.add(exitTransition);
            }
            Object returnTransition = outFragment.getReturnTransition();
            if (returnTransition != null) {
                transitions.add(returnTransition);
            }
            Object sharedReturnTransition = outFragment.getSharedElementReturnTransition();
            if (sharedReturnTransition != null) {
                transitions.add(sharedReturnTransition);
            }
        }
        if (inFragment != null) {
            Object enterTransition = inFragment.getEnterTransition();
            if (enterTransition != null) {
                transitions.add(enterTransition);
            }
            Object reenterTransition = inFragment.getReenterTransition();
            if (reenterTransition != null) {
                transitions.add(reenterTransition);
            }
            Object sharedEnterTransition = inFragment.getSharedElementEnterTransition();
            if (sharedEnterTransition != null) {
                transitions.add(sharedEnterTransition);
            }
        }
        if (transitions.isEmpty()) {
            return null;
        }
        FragmentTransitionImpl fragmentTransitionImpl = PLATFORM_IMPL;
        if (fragmentTransitionImpl != null && canHandleAll(fragmentTransitionImpl, transitions)) {
            return PLATFORM_IMPL;
        }
        FragmentTransitionImpl fragmentTransitionImpl2 = SUPPORT_IMPL;
        if (fragmentTransitionImpl2 != null && canHandleAll(fragmentTransitionImpl2, transitions)) {
            return SUPPORT_IMPL;
        }
        if (PLATFORM_IMPL == null && SUPPORT_IMPL == null) {
            return null;
        }
        throw new IllegalArgumentException("Invalid Transition types");
    }

    private static boolean canHandleAll(FragmentTransitionImpl impl, List<Object> transitions) {
        int size = transitions.size();
        for (int i = 0; i < size; i++) {
            if (!impl.canHandle(transitions.get(i))) {
                return false;
            }
        }
        return true;
    }

    private static Object getSharedElementTransition(FragmentTransitionImpl impl, Fragment inFragment, Fragment outFragment, boolean isPop) {
        Object obj;
        if (inFragment == null || outFragment == null) {
            return null;
        }
        if (isPop) {
            obj = outFragment.getSharedElementReturnTransition();
        } else {
            obj = inFragment.getSharedElementEnterTransition();
        }
        return impl.wrapTransitionInSet(impl.cloneTransition(obj));
    }

    private static Object getEnterTransition(FragmentTransitionImpl impl, Fragment inFragment, boolean isPop) {
        Object obj;
        if (inFragment == null) {
            return null;
        }
        if (isPop) {
            obj = inFragment.getReenterTransition();
        } else {
            obj = inFragment.getEnterTransition();
        }
        return impl.cloneTransition(obj);
    }

    private static Object getExitTransition(FragmentTransitionImpl impl, Fragment outFragment, boolean isPop) {
        Object obj;
        if (outFragment == null) {
            return null;
        }
        if (isPop) {
            obj = outFragment.getReturnTransition();
        } else {
            obj = outFragment.getExitTransition();
        }
        return impl.cloneTransition(obj);
    }

    private static Object configureSharedElementsReordered(FragmentTransitionImpl impl, ViewGroup sceneRoot, View nonExistentView, ArrayMap<String, String> nameOverrides, FragmentContainerTransition fragments, ArrayList<View> sharedElementsOut, ArrayList<View> sharedElementsIn, Object enterTransition, Object exitTransition) {
        Object sharedElementTransition;
        Object sharedElementTransition2;
        Object sharedElementTransition3;
        View epicenterView;
        Rect epicenter;
        ArrayMap<String, View> inSharedElements;
        FragmentTransitionImpl fragmentTransitionImpl = impl;
        View view = nonExistentView;
        ArrayMap<String, String> arrayMap = nameOverrides;
        FragmentContainerTransition fragmentContainerTransition = fragments;
        ArrayList<View> arrayList = sharedElementsOut;
        ArrayList<View> arrayList2 = sharedElementsIn;
        Object obj = enterTransition;
        Fragment inFragment = fragmentContainerTransition.lastIn;
        Fragment outFragment = fragmentContainerTransition.firstOut;
        if (inFragment != null) {
            inFragment.requireView().setVisibility(0);
        }
        if (inFragment == null) {
            ViewGroup viewGroup = sceneRoot;
            Fragment fragment = outFragment;
        } else if (outFragment == null) {
            ViewGroup viewGroup2 = sceneRoot;
            Fragment fragment2 = outFragment;
        } else {
            boolean inIsPop = fragmentContainerTransition.lastInIsPop;
            if (nameOverrides.isEmpty()) {
                sharedElementTransition = null;
            } else {
                sharedElementTransition = getSharedElementTransition(fragmentTransitionImpl, inFragment, outFragment, inIsPop);
            }
            ArrayMap<String, View> outSharedElements = captureOutSharedElements(fragmentTransitionImpl, arrayMap, sharedElementTransition, fragmentContainerTransition);
            ArrayMap<String, View> inSharedElements2 = captureInSharedElements(fragmentTransitionImpl, arrayMap, sharedElementTransition, fragmentContainerTransition);
            if (nameOverrides.isEmpty()) {
                if (outSharedElements != null) {
                    outSharedElements.clear();
                }
                if (inSharedElements2 != null) {
                    inSharedElements2.clear();
                }
                sharedElementTransition2 = null;
            } else {
                addSharedElementsWithMatchingNames(arrayList, outSharedElements, nameOverrides.keySet());
                addSharedElementsWithMatchingNames(arrayList2, inSharedElements2, nameOverrides.values());
                sharedElementTransition2 = sharedElementTransition;
            }
            if (obj == null && exitTransition == null && sharedElementTransition2 == null) {
                return null;
            }
            callSharedElementStartEnd(inFragment, outFragment, inIsPop, outSharedElements, true);
            if (sharedElementTransition2 != null) {
                arrayList2.add(view);
                fragmentTransitionImpl.setSharedElementTargets(sharedElementTransition2, view, arrayList);
                boolean outIsPop = fragmentContainerTransition.firstOutIsPop;
                boolean outIsPop2 = outIsPop;
                sharedElementTransition3 = sharedElementTransition2;
                inSharedElements = inSharedElements2;
                ArrayMap arrayMap2 = outSharedElements;
                setOutEpicenter(impl, sharedElementTransition2, exitTransition, outSharedElements, outIsPop2, fragmentContainerTransition.firstOutTransaction);
                Rect epicenter2 = new Rect();
                View epicenterView2 = getInEpicenterView(inSharedElements, fragmentContainerTransition, obj, inIsPop);
                if (epicenterView2 != null) {
                    fragmentTransitionImpl.setEpicenter(obj, epicenter2);
                }
                epicenter = epicenter2;
                epicenterView = epicenterView2;
            } else {
                sharedElementTransition3 = sharedElementTransition2;
                inSharedElements = inSharedElements2;
                ArrayMap arrayMap3 = outSharedElements;
                epicenter = null;
                epicenterView = null;
            }
            final Fragment fragment3 = inFragment;
            final Fragment fragment4 = outFragment;
            final boolean z = inIsPop;
            final ArrayMap arrayMap4 = inSharedElements;
            C02783 r8 = r0;
            final View view2 = epicenterView;
            boolean z2 = inIsPop;
            final FragmentTransitionImpl fragmentTransitionImpl2 = impl;
            Fragment fragment5 = outFragment;
            final Rect rect = epicenter;
            C02783 r0 = new Runnable() {
                public void run() {
                    FragmentTransition.callSharedElementStartEnd(fragment3, fragment4, z, arrayMap4, false);
                    View view = view2;
                    if (view != null) {
                        fragmentTransitionImpl2.getBoundsOnScreen(view, rect);
                    }
                }
            };
            OneShotPreDrawListener.add(sceneRoot, r8);
            return sharedElementTransition3;
        }
        return null;
    }

    private static void addSharedElementsWithMatchingNames(ArrayList<View> views, ArrayMap<String, View> sharedElements, Collection<String> nameOverridesSet) {
        for (int i = sharedElements.size() - 1; i >= 0; i--) {
            View view = (View) sharedElements.valueAt(i);
            if (nameOverridesSet.contains(ViewCompat.getTransitionName(view))) {
                views.add(view);
            }
        }
    }

    private static Object configureSharedElementsOrdered(FragmentTransitionImpl impl, ViewGroup sceneRoot, View nonExistentView, ArrayMap<String, String> nameOverrides, FragmentContainerTransition fragments, ArrayList<View> sharedElementsOut, ArrayList<View> sharedElementsIn, Object enterTransition, Object exitTransition) {
        Object sharedElementTransition;
        Object sharedElementTransition2;
        Rect inEpicenter;
        FragmentTransitionImpl fragmentTransitionImpl = impl;
        FragmentContainerTransition fragmentContainerTransition = fragments;
        ArrayList<View> arrayList = sharedElementsOut;
        Object obj = enterTransition;
        Fragment inFragment = fragmentContainerTransition.lastIn;
        Fragment outFragment = fragmentContainerTransition.firstOut;
        if (inFragment == null) {
            ViewGroup viewGroup = sceneRoot;
            Fragment fragment = outFragment;
            Fragment fragment2 = inFragment;
        } else if (outFragment == null) {
            ViewGroup viewGroup2 = sceneRoot;
            Fragment fragment3 = outFragment;
            Fragment fragment4 = inFragment;
        } else {
            final boolean inIsPop = fragmentContainerTransition.lastInIsPop;
            if (nameOverrides.isEmpty()) {
                sharedElementTransition = null;
            } else {
                sharedElementTransition = getSharedElementTransition(fragmentTransitionImpl, inFragment, outFragment, inIsPop);
            }
            ArrayMap<String, View> outSharedElements = captureOutSharedElements(fragmentTransitionImpl, nameOverrides, sharedElementTransition, fragmentContainerTransition);
            if (nameOverrides.isEmpty()) {
                sharedElementTransition2 = null;
            } else {
                arrayList.addAll(outSharedElements.values());
                sharedElementTransition2 = sharedElementTransition;
            }
            if (obj == null && exitTransition == null && sharedElementTransition2 == null) {
                return null;
            }
            callSharedElementStartEnd(inFragment, outFragment, inIsPop, outSharedElements, true);
            if (sharedElementTransition2 != null) {
                Rect inEpicenter2 = new Rect();
                fragmentTransitionImpl.setSharedElementTargets(sharedElementTransition2, nonExistentView, arrayList);
                boolean outIsPop = fragmentContainerTransition.firstOutIsPop;
                boolean outIsPop2 = outIsPop;
                ArrayMap arrayMap = outSharedElements;
                Rect inEpicenter3 = inEpicenter2;
                setOutEpicenter(impl, sharedElementTransition2, exitTransition, outSharedElements, outIsPop2, fragmentContainerTransition.firstOutTransaction);
                if (obj != null) {
                    fragmentTransitionImpl.setEpicenter(obj, inEpicenter3);
                }
                inEpicenter = inEpicenter3;
            } else {
                inEpicenter = null;
            }
            final Object finalSharedElementTransition = sharedElementTransition2;
            final FragmentTransitionImpl fragmentTransitionImpl2 = impl;
            final ArrayMap<String, String> arrayMap2 = nameOverrides;
            final FragmentContainerTransition fragmentContainerTransition2 = fragments;
            final ArrayList<View> arrayList2 = sharedElementsIn;
            Object sharedElementTransition3 = sharedElementTransition2;
            final View view = nonExistentView;
            C02794 r13 = r0;
            final Fragment fragment5 = inFragment;
            final Fragment fragment6 = outFragment;
            boolean z = inIsPop;
            Fragment fragment7 = outFragment;
            final ArrayList<View> arrayList3 = sharedElementsOut;
            Fragment fragment8 = inFragment;
            final Object obj2 = enterTransition;
            final Rect rect = inEpicenter;
            C02794 r0 = new Runnable() {
                public void run() {
                    ArrayMap<String, View> inSharedElements = FragmentTransition.captureInSharedElements(fragmentTransitionImpl2, arrayMap2, finalSharedElementTransition, fragmentContainerTransition2);
                    if (inSharedElements != null) {
                        arrayList2.addAll(inSharedElements.values());
                        arrayList2.add(view);
                    }
                    FragmentTransition.callSharedElementStartEnd(fragment5, fragment6, inIsPop, inSharedElements, false);
                    Object obj = finalSharedElementTransition;
                    if (obj != null) {
                        fragmentTransitionImpl2.swapSharedElementTargets(obj, arrayList3, arrayList2);
                        View inEpicenterView = FragmentTransition.getInEpicenterView(inSharedElements, fragmentContainerTransition2, obj2, inIsPop);
                        if (inEpicenterView != null) {
                            fragmentTransitionImpl2.getBoundsOnScreen(inEpicenterView, rect);
                        }
                    }
                }
            };
            OneShotPreDrawListener.add(sceneRoot, r13);
            return sharedElementTransition3;
        }
        return null;
    }

    private static ArrayMap<String, View> captureOutSharedElements(FragmentTransitionImpl impl, ArrayMap<String, String> nameOverrides, Object sharedElementTransition, FragmentContainerTransition fragments) {
        ArrayList<String> names;
        SharedElementCallback sharedElementCallback;
        if (nameOverrides.isEmpty() || sharedElementTransition == null) {
            nameOverrides.clear();
            return null;
        }
        Fragment outFragment = fragments.firstOut;
        ArrayMap<String, View> outSharedElements = new ArrayMap<>();
        impl.findNamedViews(outSharedElements, outFragment.requireView());
        BackStackRecord outTransaction = fragments.firstOutTransaction;
        if (fragments.firstOutIsPop) {
            sharedElementCallback = outFragment.getEnterTransitionCallback();
            names = outTransaction.mSharedElementTargetNames;
        } else {
            sharedElementCallback = outFragment.getExitTransitionCallback();
            names = outTransaction.mSharedElementSourceNames;
        }
        outSharedElements.retainAll(names);
        if (sharedElementCallback != null) {
            sharedElementCallback.onMapSharedElements(names, outSharedElements);
            for (int i = names.size() - 1; i >= 0; i--) {
                String name = (String) names.get(i);
                View view = (View) outSharedElements.get(name);
                if (view == null) {
                    nameOverrides.remove(name);
                } else if (!name.equals(ViewCompat.getTransitionName(view))) {
                    nameOverrides.put(ViewCompat.getTransitionName(view), (String) nameOverrides.remove(name));
                }
            }
        } else {
            nameOverrides.retainAll(outSharedElements.keySet());
        }
        return outSharedElements;
    }

    static ArrayMap<String, View> captureInSharedElements(FragmentTransitionImpl impl, ArrayMap<String, String> nameOverrides, Object sharedElementTransition, FragmentContainerTransition fragments) {
        ArrayList<String> names;
        SharedElementCallback sharedElementCallback;
        Fragment inFragment = fragments.lastIn;
        View fragmentView = inFragment.getView();
        if (nameOverrides.isEmpty() || sharedElementTransition == null || fragmentView == null) {
            nameOverrides.clear();
            return null;
        }
        ArrayMap<String, View> inSharedElements = new ArrayMap<>();
        impl.findNamedViews(inSharedElements, fragmentView);
        BackStackRecord inTransaction = fragments.lastInTransaction;
        if (fragments.lastInIsPop) {
            sharedElementCallback = inFragment.getExitTransitionCallback();
            names = inTransaction.mSharedElementSourceNames;
        } else {
            sharedElementCallback = inFragment.getEnterTransitionCallback();
            names = inTransaction.mSharedElementTargetNames;
        }
        if (names != null) {
            inSharedElements.retainAll(names);
            inSharedElements.retainAll(nameOverrides.values());
        }
        if (sharedElementCallback != null) {
            sharedElementCallback.onMapSharedElements(names, inSharedElements);
            for (int i = names.size() - 1; i >= 0; i--) {
                String name = (String) names.get(i);
                View view = (View) inSharedElements.get(name);
                if (view == null) {
                    String key = findKeyForValue(nameOverrides, name);
                    if (key != null) {
                        nameOverrides.remove(key);
                    }
                } else if (!name.equals(ViewCompat.getTransitionName(view))) {
                    String key2 = findKeyForValue(nameOverrides, name);
                    if (key2 != null) {
                        nameOverrides.put(key2, ViewCompat.getTransitionName(view));
                    }
                }
            }
        } else {
            retainValues(nameOverrides, inSharedElements);
        }
        return inSharedElements;
    }

    private static String findKeyForValue(ArrayMap<String, String> map, String value) {
        int numElements = map.size();
        for (int i = 0; i < numElements; i++) {
            if (value.equals(map.valueAt(i))) {
                return (String) map.keyAt(i);
            }
        }
        return null;
    }

    static View getInEpicenterView(ArrayMap<String, View> inSharedElements, FragmentContainerTransition fragments, Object enterTransition, boolean inIsPop) {
        String targetName;
        BackStackRecord inTransaction = fragments.lastInTransaction;
        if (enterTransition == null || inSharedElements == null || inTransaction.mSharedElementSourceNames == null || inTransaction.mSharedElementSourceNames.isEmpty()) {
            return null;
        }
        if (inIsPop) {
            targetName = (String) inTransaction.mSharedElementSourceNames.get(0);
        } else {
            targetName = (String) inTransaction.mSharedElementTargetNames.get(0);
        }
        return (View) inSharedElements.get(targetName);
    }

    private static void setOutEpicenter(FragmentTransitionImpl impl, Object sharedElementTransition, Object exitTransition, ArrayMap<String, View> outSharedElements, boolean outIsPop, BackStackRecord outTransaction) {
        String sourceName;
        if (outTransaction.mSharedElementSourceNames != null && !outTransaction.mSharedElementSourceNames.isEmpty()) {
            if (outIsPop) {
                sourceName = (String) outTransaction.mSharedElementTargetNames.get(0);
            } else {
                sourceName = (String) outTransaction.mSharedElementSourceNames.get(0);
            }
            View outEpicenterView = (View) outSharedElements.get(sourceName);
            impl.setEpicenter(sharedElementTransition, outEpicenterView);
            if (exitTransition != null) {
                impl.setEpicenter(exitTransition, outEpicenterView);
            }
        }
    }

    private static void retainValues(ArrayMap<String, String> nameOverrides, ArrayMap<String, View> namedViews) {
        for (int i = nameOverrides.size() - 1; i >= 0; i--) {
            if (!namedViews.containsKey((String) nameOverrides.valueAt(i))) {
                nameOverrides.removeAt(i);
            }
        }
    }

    static void callSharedElementStartEnd(Fragment inFragment, Fragment outFragment, boolean isPop, ArrayMap<String, View> sharedElements, boolean isStart) {
        SharedElementCallback sharedElementCallback;
        if (isPop) {
            sharedElementCallback = outFragment.getEnterTransitionCallback();
        } else {
            sharedElementCallback = inFragment.getEnterTransitionCallback();
        }
        if (sharedElementCallback != null) {
            ArrayList<View> views = new ArrayList<>();
            ArrayList<String> names = new ArrayList<>();
            int count = sharedElements == null ? 0 : sharedElements.size();
            for (int i = 0; i < count; i++) {
                names.add(sharedElements.keyAt(i));
                views.add(sharedElements.valueAt(i));
            }
            if (isStart) {
                sharedElementCallback.onSharedElementStart(names, views, null);
            } else {
                sharedElementCallback.onSharedElementEnd(names, views, null);
            }
        }
    }

    static ArrayList<View> configureEnteringExitingViews(FragmentTransitionImpl impl, Object transition, Fragment fragment, ArrayList<View> sharedElements, View nonExistentView) {
        ArrayList<View> viewList = null;
        if (transition != null) {
            viewList = new ArrayList<>();
            View root = fragment.getView();
            if (root != null) {
                impl.captureTransitioningViews(viewList, root);
            }
            if (sharedElements != null) {
                viewList.removeAll(sharedElements);
            }
            if (!viewList.isEmpty()) {
                viewList.add(nonExistentView);
                impl.addTargets(transition, viewList);
            }
        }
        return viewList;
    }

    static void setViewVisibility(ArrayList<View> views, int visibility) {
        if (views != null) {
            for (int i = views.size() - 1; i >= 0; i--) {
                ((View) views.get(i)).setVisibility(visibility);
            }
        }
    }

    private static Object mergeTransitions(FragmentTransitionImpl impl, Object enterTransition, Object exitTransition, Object sharedElementTransition, Fragment inFragment, boolean isPop) {
        boolean z;
        boolean overlap = true;
        if (!(enterTransition == null || exitTransition == null || inFragment == null)) {
            if (isPop) {
                z = inFragment.getAllowReturnTransitionOverlap();
            } else {
                z = inFragment.getAllowEnterTransitionOverlap();
            }
            overlap = z;
        }
        if (overlap) {
            return impl.mergeTransitionsTogether(exitTransition, enterTransition, sharedElementTransition);
        }
        return impl.mergeTransitionsInSequence(exitTransition, enterTransition, sharedElementTransition);
    }

    public static void calculateFragments(BackStackRecord transaction, SparseArray<FragmentContainerTransition> transitioningFragments, boolean isReordered) {
        int numOps = transaction.mOps.size();
        for (int opNum = 0; opNum < numOps; opNum++) {
            addToFirstInLastOut(transaction, (C0275Op) transaction.mOps.get(opNum), transitioningFragments, false, isReordered);
        }
    }

    public static void calculatePopFragments(BackStackRecord transaction, SparseArray<FragmentContainerTransition> transitioningFragments, boolean isReordered) {
        if (transaction.mManager.mContainer.onHasView()) {
            for (int opNum = transaction.mOps.size() - 1; opNum >= 0; opNum--) {
                addToFirstInLastOut(transaction, (C0275Op) transaction.mOps.get(opNum), transitioningFragments, true, isReordered);
            }
        }
    }

    static boolean supportsTransition() {
        return (PLATFORM_IMPL == null && SUPPORT_IMPL == null) ? false : true;
    }

    /* JADX WARNING: Removed duplicated region for block: B:102:0x012a  */
    /* JADX WARNING: Removed duplicated region for block: B:78:0x00c5  */
    /* JADX WARNING: Removed duplicated region for block: B:79:0x00d2  */
    /* JADX WARNING: Removed duplicated region for block: B:82:0x00d6 A[ADDED_TO_REGION] */
    /* JADX WARNING: Removed duplicated region for block: B:97:0x0116  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static void addToFirstInLastOut(androidx.fragment.app.BackStackRecord r22, androidx.fragment.app.FragmentTransaction.C0275Op r23, android.util.SparseArray<androidx.fragment.app.FragmentTransition.FragmentContainerTransition> r24, boolean r25, boolean r26) {
        /*
            r0 = r22
            r1 = r23
            r2 = r24
            r3 = r25
            androidx.fragment.app.Fragment r10 = r1.mFragment
            if (r10 != 0) goto L_0x000d
            return
        L_0x000d:
            int r11 = r10.mContainerId
            if (r11 != 0) goto L_0x0012
            return
        L_0x0012:
            if (r3 == 0) goto L_0x001b
            int[] r4 = INVERSE_OPS
            int r5 = r1.mCmd
            r4 = r4[r5]
            goto L_0x001d
        L_0x001b:
            int r4 = r1.mCmd
        L_0x001d:
            r12 = r4
            r4 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r9 = 1
            if (r12 == r9) goto L_0x00a8
            r13 = 3
            if (r12 == r13) goto L_0x0079
            r13 = 4
            if (r12 == r13) goto L_0x0057
            r13 = 5
            if (r12 == r13) goto L_0x003c
            r13 = 6
            if (r12 == r13) goto L_0x0079
            r13 = 7
            if (r12 == r13) goto L_0x00a8
            r13 = r4
            r14 = r5
            r15 = r6
            r16 = r7
            goto L_0x00bd
        L_0x003c:
            if (r26 == 0) goto L_0x004d
            boolean r13 = r10.mHiddenChanged
            if (r13 == 0) goto L_0x004b
            boolean r13 = r10.mHidden
            if (r13 != 0) goto L_0x004b
            boolean r13 = r10.mAdded
            if (r13 == 0) goto L_0x004b
            r8 = r9
        L_0x004b:
            r4 = r8
            goto L_0x004f
        L_0x004d:
            boolean r4 = r10.mHidden
        L_0x004f:
            r7 = 1
            r13 = r4
            r14 = r5
            r15 = r6
            r16 = r7
            goto L_0x00bd
        L_0x0057:
            if (r26 == 0) goto L_0x0068
            boolean r13 = r10.mHiddenChanged
            if (r13 == 0) goto L_0x0066
            boolean r13 = r10.mAdded
            if (r13 == 0) goto L_0x0066
            boolean r13 = r10.mHidden
            if (r13 == 0) goto L_0x0066
            r8 = r9
        L_0x0066:
            r6 = r8
            goto L_0x0072
        L_0x0068:
            boolean r13 = r10.mAdded
            if (r13 == 0) goto L_0x0071
            boolean r13 = r10.mHidden
            if (r13 != 0) goto L_0x0071
            r8 = r9
        L_0x0071:
            r6 = r8
        L_0x0072:
            r5 = 1
            r13 = r4
            r14 = r5
            r15 = r6
            r16 = r7
            goto L_0x00bd
        L_0x0079:
            if (r26 == 0) goto L_0x0097
            boolean r13 = r10.mAdded
            if (r13 != 0) goto L_0x0094
            android.view.View r13 = r10.mView
            if (r13 == 0) goto L_0x0094
            android.view.View r13 = r10.mView
            int r13 = r13.getVisibility()
            if (r13 != 0) goto L_0x0094
            float r13 = r10.mPostponedAlpha
            r14 = 0
            int r13 = (r13 > r14 ? 1 : (r13 == r14 ? 0 : -1))
            if (r13 < 0) goto L_0x0094
            r8 = r9
            goto L_0x0095
        L_0x0094:
        L_0x0095:
            r6 = r8
            goto L_0x00a1
        L_0x0097:
            boolean r13 = r10.mAdded
            if (r13 == 0) goto L_0x00a0
            boolean r13 = r10.mHidden
            if (r13 != 0) goto L_0x00a0
            r8 = r9
        L_0x00a0:
            r6 = r8
        L_0x00a1:
            r5 = 1
            r13 = r4
            r14 = r5
            r15 = r6
            r16 = r7
            goto L_0x00bd
        L_0x00a8:
            if (r26 == 0) goto L_0x00ad
            boolean r4 = r10.mIsNewlyAdded
            goto L_0x00b7
        L_0x00ad:
            boolean r13 = r10.mAdded
            if (r13 != 0) goto L_0x00b6
            boolean r13 = r10.mHidden
            if (r13 != 0) goto L_0x00b6
            r8 = r9
        L_0x00b6:
            r4 = r8
        L_0x00b7:
            r7 = 1
            r13 = r4
            r14 = r5
            r15 = r6
            r16 = r7
        L_0x00bd:
            java.lang.Object r4 = r2.get(r11)
            androidx.fragment.app.FragmentTransition$FragmentContainerTransition r4 = (androidx.fragment.app.FragmentTransition.FragmentContainerTransition) r4
            if (r13 == 0) goto L_0x00d2
            androidx.fragment.app.FragmentTransition$FragmentContainerTransition r4 = ensureContainer(r4, r2, r11)
            r4.lastIn = r10
            r4.lastInIsPop = r3
            r4.lastInTransaction = r0
            r8 = r4
            goto L_0x00d3
        L_0x00d2:
            r8 = r4
        L_0x00d3:
            r7 = 0
            if (r26 != 0) goto L_0x0111
            if (r16 == 0) goto L_0x0111
            if (r8 == 0) goto L_0x00e0
            androidx.fragment.app.Fragment r4 = r8.firstOut
            if (r4 != r10) goto L_0x00e0
            r8.firstOut = r7
        L_0x00e0:
            androidx.fragment.app.FragmentManagerImpl r6 = r0.mManager
            int r4 = r10.mState
            if (r4 >= r9) goto L_0x010b
            int r4 = r6.mCurState
            if (r4 < r9) goto L_0x010b
            boolean r4 = r0.mReorderingAllowed
            if (r4 != 0) goto L_0x010b
            r6.makeActive(r10)
            r9 = 1
            r17 = 0
            r18 = 0
            r19 = 0
            r4 = r6
            r5 = r10
            r20 = r6
            r6 = r9
            r9 = r7
            r7 = r17
            r21 = r8
            r8 = r18
            r1 = r9
            r9 = r19
            r4.moveToState(r5, r6, r7, r8, r9)
            goto L_0x0114
        L_0x010b:
            r20 = r6
            r1 = r7
            r21 = r8
            goto L_0x0114
        L_0x0111:
            r1 = r7
            r21 = r8
        L_0x0114:
            if (r15 == 0) goto L_0x012a
            r4 = r21
            if (r4 == 0) goto L_0x011e
            androidx.fragment.app.Fragment r5 = r4.firstOut
            if (r5 != 0) goto L_0x012c
        L_0x011e:
            androidx.fragment.app.FragmentTransition$FragmentContainerTransition r8 = ensureContainer(r4, r2, r11)
            r8.firstOut = r10
            r8.firstOutIsPop = r3
            r8.firstOutTransaction = r0
            goto L_0x012d
        L_0x012a:
            r4 = r21
        L_0x012c:
            r8 = r4
        L_0x012d:
            if (r26 != 0) goto L_0x0139
            if (r14 == 0) goto L_0x0139
            if (r8 == 0) goto L_0x0139
            androidx.fragment.app.Fragment r4 = r8.lastIn
            if (r4 != r10) goto L_0x0139
            r8.lastIn = r1
        L_0x0139:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.FragmentTransition.addToFirstInLastOut(androidx.fragment.app.BackStackRecord, androidx.fragment.app.FragmentTransaction$Op, android.util.SparseArray, boolean, boolean):void");
    }

    private static FragmentContainerTransition ensureContainer(FragmentContainerTransition containerTransition, SparseArray<FragmentContainerTransition> transitioningFragments, int containerId) {
        if (containerTransition != null) {
            return containerTransition;
        }
        FragmentContainerTransition containerTransition2 = new FragmentContainerTransition();
        transitioningFragments.put(containerId, containerTransition2);
        return containerTransition2;
    }

    private FragmentTransition() {
    }
}
