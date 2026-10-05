import { act, renderHook } from '@testing-library/react';
import { useSurfaceHistory } from '../useSurfaceHistory';

describe('useSurfaceHistory', () => {
  it('starts empty: no undo or redo available', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
    expect(result.current.undo()).toBeNull();
    expect(result.current.redo()).toBeNull();
  });

  it('reset sets the committed baseline without enabling undo', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
  });

  it('commit pushes prior committed onto past; undo restores it', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    expect(result.current.canUndo).toBe(true);
    let popped: string | null = null;
    act(() => {
      popped = result.current.undo();
    });
    expect(popped).toBe('a');
    expect(result.current.canRedo).toBe(true);
  });

  it('redo walks forward through future after undo', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    act(() => result.current.commit('c'));
    act(() => {
      result.current.undo();
    }); // committed = b
    act(() => {
      result.current.undo();
    }); // committed = a
    let r1: string | null = null;
    let r2: string | null = null;
    act(() => {
      r1 = result.current.redo();
    });
    act(() => {
      r2 = result.current.redo();
    });
    expect(r1).toBe('b');
    expect(r2).toBe('c');
    expect(result.current.canRedo).toBe(false);
  });

  it('commit clears future (no redo after a new edit)', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    act(() => {
      result.current.undo();
    });
    expect(result.current.canRedo).toBe(true);
    act(() => result.current.commit('c'));
    expect(result.current.canRedo).toBe(false);
  });

  it('committing identical state to current committed is a no-op', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('a'));
    expect(result.current.canUndo).toBe(false);
  });

  it('replaceCommitted updates committed in-place without growing past', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    expect(result.current.canUndo).toBe(true);
    act(() => result.current.replaceCommitted('c'));
    // Past depth unchanged (still 1 entry: 'a'); undo returns 'a'.
    let popped: string | null = null;
    act(() => {
      popped = result.current.undo();
    });
    expect(popped).toBe('a');
  });

  it('respects the limit by evicting the oldest entry from past', () => {
    const { result } = renderHook(() => useSurfaceHistory(2));
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    act(() => result.current.commit('c'));
    act(() => result.current.commit('d')); // past: [b, c], committed: d (a evicted)
    let p1: string | null = null;
    let p2: string | null = null;
    act(() => {
      p1 = result.current.undo();
    }); // c
    act(() => {
      p2 = result.current.undo();
    }); // b
    expect(p1).toBe('c');
    expect(p2).toBe('b');
    expect(result.current.canUndo).toBe(false);
  });

  it('reset wipes past and future', () => {
    const { result } = renderHook(() => useSurfaceHistory());
    act(() => result.current.reset('a'));
    act(() => result.current.commit('b'));
    act(() => result.current.commit('c'));
    act(() => {
      result.current.undo();
    });
    expect(result.current.canUndo).toBe(true);
    expect(result.current.canRedo).toBe(true);
    act(() => result.current.reset('z'));
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
  });
});
