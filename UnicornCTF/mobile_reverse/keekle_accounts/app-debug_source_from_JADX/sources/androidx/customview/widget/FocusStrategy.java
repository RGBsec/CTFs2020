package androidx.customview.widget;

import android.graphics.Rect;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

class FocusStrategy {

    public interface BoundsAdapter<T> {
        void obtainBounds(T t, Rect rect);
    }

    public interface CollectionAdapter<T, V> {
        V get(T t, int i);

        int size(T t);
    }

    private static class SequentialComparator<T> implements Comparator<T> {
        private final BoundsAdapter<T> mAdapter;
        private final boolean mIsLayoutRtl;
        private final Rect mTemp1 = new Rect();
        private final Rect mTemp2 = new Rect();

        SequentialComparator(boolean isLayoutRtl, BoundsAdapter<T> adapter) {
            this.mIsLayoutRtl = isLayoutRtl;
            this.mAdapter = adapter;
        }

        public int compare(T first, T second) {
            Rect firstRect = this.mTemp1;
            Rect secondRect = this.mTemp2;
            this.mAdapter.obtainBounds(first, firstRect);
            this.mAdapter.obtainBounds(second, secondRect);
            int i = -1;
            if (firstRect.top < secondRect.top) {
                return -1;
            }
            if (firstRect.top > secondRect.top) {
                return 1;
            }
            if (firstRect.left < secondRect.left) {
                if (this.mIsLayoutRtl) {
                    i = 1;
                }
                return i;
            } else if (firstRect.left > secondRect.left) {
                if (!this.mIsLayoutRtl) {
                    i = 1;
                }
                return i;
            } else if (firstRect.bottom < secondRect.bottom) {
                return -1;
            } else {
                if (firstRect.bottom > secondRect.bottom) {
                    return 1;
                }
                if (firstRect.right < secondRect.right) {
                    if (this.mIsLayoutRtl) {
                        i = 1;
                    }
                    return i;
                } else if (firstRect.right <= secondRect.right) {
                    return 0;
                } else {
                    if (!this.mIsLayoutRtl) {
                        i = 1;
                    }
                    return i;
                }
            }
        }
    }

    public static <L, T> T findNextFocusInRelativeDirection(L focusables, CollectionAdapter<L, T> collectionAdapter, BoundsAdapter<T> adapter, T focused, int direction, boolean isLayoutRtl, boolean wrap) {
        int count = collectionAdapter.size(focusables);
        ArrayList<T> sortedFocusables = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            sortedFocusables.add(collectionAdapter.get(focusables, i));
        }
        Collections.sort(sortedFocusables, new SequentialComparator<>(isLayoutRtl, adapter));
        if (direction == 1) {
            return getPreviousFocusable(focused, sortedFocusables, wrap);
        }
        if (direction == 2) {
            return getNextFocusable(focused, sortedFocusables, wrap);
        }
        throw new IllegalArgumentException("direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD}.");
    }

    private static <T> T getNextFocusable(T focused, ArrayList<T> focusables, boolean wrap) {
        int count = focusables.size();
        int position = (focused == null ? -1 : focusables.lastIndexOf(focused)) + 1;
        if (position < count) {
            return focusables.get(position);
        }
        if (!wrap || count <= 0) {
            return null;
        }
        return focusables.get(0);
    }

    private static <T> T getPreviousFocusable(T focused, ArrayList<T> focusables, boolean wrap) {
        int count = focusables.size();
        int position = (focused == null ? count : focusables.indexOf(focused)) - 1;
        if (position >= 0) {
            return focusables.get(position);
        }
        if (!wrap || count <= 0) {
            return null;
        }
        return focusables.get(count - 1);
    }

    public static <L, T> T findNextFocusInAbsoluteDirection(L focusables, CollectionAdapter<L, T> collectionAdapter, BoundsAdapter<T> adapter, T focused, Rect focusedRect, int direction) {
        Rect bestCandidateRect = new Rect(focusedRect);
        if (direction == 17) {
            bestCandidateRect.offset(focusedRect.width() + 1, 0);
        } else if (direction == 33) {
            bestCandidateRect.offset(0, focusedRect.height() + 1);
        } else if (direction == 66) {
            bestCandidateRect.offset(-(focusedRect.width() + 1), 0);
        } else if (direction == 130) {
            bestCandidateRect.offset(0, -(focusedRect.height() + 1));
        } else {
            throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
        }
        T closest = null;
        int count = collectionAdapter.size(focusables);
        Rect focusableRect = new Rect();
        for (int i = 0; i < count; i++) {
            T focusable = collectionAdapter.get(focusables, i);
            if (focusable != focused) {
                adapter.obtainBounds(focusable, focusableRect);
                if (isBetterCandidate(direction, focusedRect, focusableRect, bestCandidateRect)) {
                    bestCandidateRect.set(focusableRect);
                    closest = focusable;
                }
            }
        }
        return closest;
    }

    private static boolean isBetterCandidate(int direction, Rect source, Rect candidate, Rect currentBest) {
        boolean z = false;
        if (!isCandidate(source, candidate, direction)) {
            return false;
        }
        if (!isCandidate(source, currentBest, direction) || beamBeats(direction, source, candidate, currentBest)) {
            return true;
        }
        if (beamBeats(direction, source, currentBest, candidate)) {
            return false;
        }
        if (getWeightedDistanceFor(majorAxisDistance(direction, source, candidate), minorAxisDistance(direction, source, candidate)) < getWeightedDistanceFor(majorAxisDistance(direction, source, currentBest), minorAxisDistance(direction, source, currentBest))) {
            z = true;
        }
        return z;
    }

    private static boolean beamBeats(int direction, Rect source, Rect rect1, Rect rect2) {
        boolean rect1InSrcBeam = beamsOverlap(direction, source, rect1);
        boolean z = false;
        if (beamsOverlap(direction, source, rect2) || !rect1InSrcBeam) {
            return false;
        }
        if (!isToDirectionOf(direction, source, rect2) || direction == 17 || direction == 66) {
            return true;
        }
        if (majorAxisDistance(direction, source, rect1) < majorAxisDistanceToFarEdge(direction, source, rect2)) {
            z = true;
        }
        return z;
    }

    private static int getWeightedDistanceFor(int majorAxisDistance, int minorAxisDistance) {
        return (majorAxisDistance * 13 * majorAxisDistance) + (minorAxisDistance * minorAxisDistance);
    }

    private static boolean isCandidate(Rect srcRect, Rect destRect, int direction) {
        boolean z = true;
        if (direction == 17) {
            if ((srcRect.right <= destRect.right && srcRect.left < destRect.right) || srcRect.left <= destRect.left) {
                z = false;
            }
            return z;
        } else if (direction == 33) {
            if ((srcRect.bottom <= destRect.bottom && srcRect.top < destRect.bottom) || srcRect.top <= destRect.top) {
                z = false;
            }
            return z;
        } else if (direction == 66) {
            if ((srcRect.left >= destRect.left && srcRect.right > destRect.left) || srcRect.right >= destRect.right) {
                z = false;
            }
            return z;
        } else if (direction == 130) {
            if ((srcRect.top >= destRect.top && srcRect.bottom > destRect.top) || srcRect.bottom >= destRect.bottom) {
                z = false;
            }
            return z;
        } else {
            throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
        }
    }

    private static boolean beamsOverlap(int direction, Rect rect1, Rect rect2) {
        boolean z = true;
        if (direction != 17) {
            if (direction != 33) {
                if (direction != 66) {
                    if (direction != 130) {
                        throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
                    }
                }
            }
            if (rect2.right < rect1.left || rect2.left > rect1.right) {
                z = false;
            }
            return z;
        }
        if (rect2.bottom < rect1.top || rect2.top > rect1.bottom) {
            z = false;
        }
        return z;
    }

    private static boolean isToDirectionOf(int direction, Rect src, Rect dest) {
        boolean z = true;
        if (direction == 17) {
            if (src.left < dest.right) {
                z = false;
            }
            return z;
        } else if (direction == 33) {
            if (src.top < dest.bottom) {
                z = false;
            }
            return z;
        } else if (direction == 66) {
            if (src.right > dest.left) {
                z = false;
            }
            return z;
        } else if (direction == 130) {
            if (src.bottom > dest.top) {
                z = false;
            }
            return z;
        } else {
            throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
        }
    }

    private static int majorAxisDistance(int direction, Rect source, Rect dest) {
        return Math.max(0, majorAxisDistanceRaw(direction, source, dest));
    }

    private static int majorAxisDistanceRaw(int direction, Rect source, Rect dest) {
        if (direction == 17) {
            return source.left - dest.right;
        }
        if (direction == 33) {
            return source.top - dest.bottom;
        }
        if (direction == 66) {
            return dest.left - source.right;
        }
        if (direction == 130) {
            return dest.top - source.bottom;
        }
        throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
    }

    private static int majorAxisDistanceToFarEdge(int direction, Rect source, Rect dest) {
        return Math.max(1, majorAxisDistanceToFarEdgeRaw(direction, source, dest));
    }

    private static int majorAxisDistanceToFarEdgeRaw(int direction, Rect source, Rect dest) {
        if (direction == 17) {
            return source.left - dest.left;
        }
        if (direction == 33) {
            return source.top - dest.top;
        }
        if (direction == 66) {
            return dest.right - source.right;
        }
        if (direction == 130) {
            return dest.bottom - source.bottom;
        }
        throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
    }

    private static int minorAxisDistance(int direction, Rect source, Rect dest) {
        if (direction != 17) {
            if (direction != 33) {
                if (direction != 66) {
                    if (direction != 130) {
                        throw new IllegalArgumentException("direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}.");
                    }
                }
            }
            return Math.abs((source.left + (source.width() / 2)) - (dest.left + (dest.width() / 2)));
        }
        return Math.abs((source.top + (source.height() / 2)) - (dest.top + (dest.height() / 2)));
    }

    private FocusStrategy() {
    }
}
