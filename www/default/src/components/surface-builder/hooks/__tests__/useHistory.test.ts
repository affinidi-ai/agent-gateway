import { act, renderHook } from '@testing-library/react';
import { useHistory } from '../useHistory';

describe('useHistory', () => {
  it('initial state is exposed; canUndo and canRedo start false', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    expect(result.current.state).toBe(0);
    expect(result.current.canUndo).toBe(false);
    expect(result.current.canRedo).toBe(false);
  });

  it('set updates state without enabling undo (live edits do not snapshot)', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => result.current.set(1));
    expect(result.current.state).toBe(1);
    // No commit yet and no prior snapshot in the history stack, so
    // canUndo is false — uncommitted live edits alone do not enable
    // undo (prevents hydration effects from showing a spurious undo).
    expect(result.current.canUndo).toBe(false);
  });

  it('commit snapshots current state; undo restores previous committed', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => {
      result.current.set(1);
      result.current.commit();
    });
    act(() => {
      result.current.set(2);
      result.current.commit();
    });
    expect(result.current.state).toBe(2);
    act(() => result.current.undo());
    expect(result.current.state).toBe(1);
    act(() => result.current.undo());
    expect(result.current.state).toBe(0);
    expect(result.current.canUndo).toBe(false);
  });

  it('redo restores forward through committed snapshots', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => {
      result.current.set(1);
      result.current.commit();
      result.current.set(2);
      result.current.commit();
    });
    act(() => result.current.undo());
    act(() => result.current.undo());
    expect(result.current.state).toBe(0);
    expect(result.current.canRedo).toBe(true);
    act(() => result.current.redo());
    expect(result.current.state).toBe(1);
    act(() => result.current.redo());
    expect(result.current.state).toBe(2);
    expect(result.current.canRedo).toBe(false);
  });

  it('undo with uncommitted changes auto-commits them before stepping back', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => {
      result.current.set(1);
      result.current.commit();
    });
    act(() => result.current.set(99));
    act(() => result.current.undo());
    expect(result.current.state).toBe(1);
    act(() => result.current.redo());
    expect(result.current.state).toBe(99);
  });

  it('committing identical state is a no-op', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => result.current.commit());
    expect(result.current.canUndo).toBe(false);
  });

  it('respects history limit by evicting the oldest snapshot', () => {
    const { result } = renderHook(() => useHistory<number>(0, 3));
    act(() => {
      for (let i = 1; i <= 5; i++) {
        result.current.set(i);
        result.current.commit();
      }
    });
    expect(result.current.state).toBe(5);
    let undos = 0;
    while (result.current.canUndo && undos < 10) {
      act(() => result.current.undo());
      undos++;
    }
    expect(undos).toBe(3);
    expect(result.current.state).toBe(2);
  });

  it('committing after an undo clears the redo branch', () => {
    const { result } = renderHook(() => useHistory<number>(0));
    act(() => {
      result.current.set(1);
      result.current.commit();
      result.current.set(2);
      result.current.commit();
    });
    act(() => result.current.undo());
    expect(result.current.state).toBe(1);
    act(() => {
      result.current.set(10);
      result.current.commit();
    });
    expect(result.current.canRedo).toBe(false);
    expect(result.current.state).toBe(10);
  });
});
