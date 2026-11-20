import React, { useEffect } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import { useDiscardWithUndo } from '../useDiscardWithUndo';

const Editor: React.FC<{
  restoreOnlyOnUndo: boolean;
  restore: (saved: string) => void;
  save: () => string;
}> = ({ restoreOnlyOnUndo, restore, save }) => {
  const { discard, popPendingRestore } = useDiscardWithUndo({
    dirty: true,
    navigateTo: '/list',
    snapshot: { storageKey: 'draft:test', save, restore, restoreOnlyOnUndo },
  });
  useEffect(() => {
    popPendingRestore();
  }, [popPendingRestore]);
  return (
    <button type="button" onClick={discard}>
      Back
    </button>
  );
};

const List: React.FC = () => {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate('/edit')}>
      Open
    </button>
  );
};

/** Opens the editor and returns its `restore` mock. */
function openEditor(restoreOnlyOnUndo: boolean, save: () => string = () => 'draft') {
  const restore = jest.fn();
  render(
    <MemoryRouter initialEntries={['/edit']}>
      <Routes>
        <Route
          path="/edit"
          element={<Editor restoreOnlyOnUndo={restoreOnlyOnUndo} restore={restore} save={save} />}
        />
        <Route path="/list" element={<List />} />
      </Routes>
    </MemoryRouter>
  );
  return restore;
}

const toastClose = () => screen.queryByTitle('Dismiss');

beforeEach(() => {
  jest.useFakeTimers();
  window.sessionStorage.clear();
});

afterEach(() => {
  const close = toastClose();
  if (close) fireEvent.click(close);
  jest.useRealTimers();
});

describe('useDiscardWithUndo', () => {
  it('removes the discard toast when an Undo-only editor is opened another way', () => {
    const restore = openEditor(true);
    fireEvent.click(screen.getByText('Back'));
    expect(screen.getByText('Changes discarded.')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Open'));

    expect(restore).not.toHaveBeenCalled();
    expect(screen.queryByText('Changes discarded.')).toBeNull();
    expect(window.sessionStorage.getItem('draft:test')).toBeNull();
    fireEvent.keyDown(document, { key: 'u' });
    expect(screen.getByText('Back')).toBeInTheDocument();
    expect(restore).not.toHaveBeenCalled();
  });

  it('restores an Undo-only draft when the toast Undo reopens the editor', () => {
    const restore = openEditor(true);
    fireEvent.click(screen.getByText('Back'));

    fireEvent.keyDown(document, { key: 'u' });

    expect(restore).toHaveBeenCalledWith('draft');
    expect(screen.queryByText('Changes discarded.')).toBeNull();
  });

  it('keeps the toast and restores the draft on any visit without restoreOnlyOnUndo', () => {
    const restore = openEditor(false);
    fireEvent.click(screen.getByText('Back'));

    fireEvent.click(screen.getByText('Open'));

    expect(restore).toHaveBeenCalledWith('draft');
    expect(screen.getByText('Changes discarded.')).toBeInTheDocument();
  });

  it('restores the second draft when the editor is discarded again while the first toast shows', () => {
    let saves = 0;
    const restore = openEditor(false, () => `draft ${++saves}`);
    fireEvent.click(screen.getByText('Back'));
    fireEvent.click(screen.getByText('Open'));
    expect(restore).toHaveBeenLastCalledWith('draft 1');

    fireEvent.click(screen.getByText('Back'));
    expect(window.sessionStorage.getItem('draft:test')).toBe('draft 2');
    fireEvent.keyDown(document, { key: 'u' });

    expect(restore).toHaveBeenLastCalledWith('draft 2');
  });
});
