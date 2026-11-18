import { fireEvent, renderHook } from '@testing-library/react';
import { useSurfaceBuilder } from '../useSurfaceBuilder';

const renderBuilder = () =>
  renderHook(() => useSurfaceBuilder({ nodes: [], selectedNodeId: 'n1' }));

describe('useSurfaceBuilder keyboard shortcuts', () => {
  const modals: HTMLElement[] = [];

  afterEach(() => {
    modals.splice(0).forEach(modal => modal.remove());
  });

  it('clears the selection on Escape', () => {
    const { result } = renderBuilder();

    fireEvent.keyDown(window, { key: 'Escape' });

    expect(result.current.state.selectedNodeId).toBeNull();
  });

  it('ignores the keyboard while a modal dialog is open', () => {
    const modal = document.createElement('div');
    modal.setAttribute('aria-modal', 'true');
    document.body.appendChild(modal);
    modals.push(modal);
    const { result } = renderBuilder();

    fireEvent.keyDown(window, { key: 'Escape' });

    expect(result.current.state.selectedNodeId).toBe('n1');
  });
});
