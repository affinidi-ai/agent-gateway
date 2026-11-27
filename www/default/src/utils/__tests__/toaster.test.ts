import { act } from 'react';
import {
  ANNOUNCE_DELAY_MS,
  closeKeptToast,
  removeToast,
  showKeepOpenWarningToast,
  showSuccessCountdownToast,
  showToast,
  showUndoToast,
} from '../toaster';

const PAYLOAD = '<img src=x onerror="window.__toastXss = true">';

const getToast = (): HTMLElement => {
  const toast = document.getElementById('app-toast');
  if (!toast) throw new Error('no toast in the document');
  return toast;
};

describe('showToast', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    (window as unknown as { __toastXss?: boolean }).__toastXss = undefined;
  });

  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  describe('a save with warnings', () => {
    it('shows the saved message and every warning in the one toast, one per line', () => {
      showToast('error', 'Saved, with warnings:\nfirst warning\nsecond warning');
      expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
      const toast = getToast();
      expect(toast.textContent).toContain('Saved, with warnings:');
      expect(toast.textContent).toContain('first warning');
      expect(toast.textContent).toContain('second warning');
      expect((toast.querySelector('span[style*="pre-line"]') as HTMLElement).style.whiteSpace).toBe(
        'pre-line'
      );
    });

    it('is replaced by a later toast, which is why a save sends one', () => {
      showToast('success', 'saved');
      showToast('error', 'a warning');
      expect(getToast().textContent).not.toContain('saved');
    });
  });

  describe('text rendering', () => {
    it('renders markup in the message literally and adds no element for it', () => {
      showToast('error', PAYLOAD);

      const toast = getToast();
      expect(toast.querySelector('img')).toBeNull();
      expect(toast.textContent).toContain(PAYLOAD);
      expect((window as unknown as { __toastXss?: boolean }).__toastXss).toBeUndefined();
    });

    it('renders markup in the action label literally and adds no element for it', () => {
      showToast('warning', 'Something happened', {
        action: { label: PAYLOAD, onClick: jest.fn() },
      });

      const toast = getToast();
      expect(toast.querySelector('img')).toBeNull();
      expect(toast.querySelector('#app-toast-action')?.textContent).toBe(PAYLOAD);
    });

    it('does not let a message close the surrounding markup or add elements', () => {
      showToast('success', '</span><script>window.__toastXss = true</script><b>bold</b>');

      const toast = getToast();
      expect(toast.querySelector('script')).toBeNull();
      expect(toast.querySelector('b')).toBeNull();
      expect(toast.textContent).toContain('<b>bold</b>');
    });

    it('renders ampersand entities literally', () => {
      showToast('success', 'Tom &amp; Jerry &lt;3');

      expect(getToast().textContent).toContain('Tom &amp; Jerry &lt;3');
    });
  });

  describe('structure and behaviour', () => {
    it.each([
      ['success', 'alert-success', 'Success!', 'fa-check-circle'],
      ['warning', 'alert-warning', 'Warning', 'fa-exclamation-triangle'],
      ['error', 'alert-danger', 'Error!', 'fa-exclamation-circle'],
      ['loading', 'alert-info', 'Loading...', 'fa-spinner'],
    ] as const)(
      'shows a %s toast with its class, icon and label',
      (type, alertClass, label, icon) => {
        showToast(type, 'Hello there');

        const toast = getToast();
        const alert = toast.querySelector('.alert');
        expect(alert).not.toBeNull();
        expect(alert).toHaveClass(alertClass, 'fade', 'show');
        expect(alert).not.toHaveClass('alert-dismissible');
        expect(toast.querySelector('strong')?.textContent).toBe(label);
        expect(toast.querySelector('i.fas')).toHaveClass(icon);
        expect(toast.querySelector('.flex-grow-1 span')?.textContent).toBe('Hello there');
      }
    );

    it('keeps the layout classes of the message block', () => {
      showToast('success', 'Hello');

      const toast = getToast();
      expect(toast.querySelector('.d-flex.align-items-center > .me-3')).not.toBeNull();
      expect(toast.querySelector('.d-flex.align-items-center > .flex-grow-1')).not.toBeNull();
      expect(toast.querySelector('.flex-grow-1 br')).not.toBeNull();
    });

    it('lets a long unbroken message shrink and wrap so the close button stays in the toast', () => {
      showToast('success', `Surface "${'x'.repeat(200)}" deleted`);

      const body = getToast().querySelector<HTMLElement>('.flex-grow-1');
      expect(body?.style.minWidth).toBe('0px');
      expect(body?.style.overflowWrap).toBe('anywhere');
    });

    it('replaces an existing toast', () => {
      showToast('success', 'first');
      showToast('success', 'second');

      expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
      expect(getToast().textContent).toContain('second');
      expect(getToast().textContent).not.toContain('first');
    });

    it('removes the toast with the close button, the last item of its row as on the undo toast', () => {
      showToast('error', 'Closable');

      const close = getToast().querySelector<HTMLButtonElement>(
        '.d-flex.align-items-center > #app-toast-close'
      );
      expect(close).not.toBeNull();
      expect(close?.parentElement?.lastElementChild).toBe(close);
      expect(close).toHaveAttribute('title', 'Dismiss');
      expect(close?.textContent?.trim()).toBe('×');
      close?.click();

      expect(document.getElementById('app-toast')).toBeNull();
    });

    it('auto-removes when autoRemove is set, after the duration', () => {
      showToast('success', 'Gone soon', { autoRemove: true, duration: 1000 });

      jest.advanceTimersByTime(999);
      expect(document.getElementById('app-toast')).not.toBeNull();
      jest.advanceTimersByTime(1);
      expect(document.getElementById('app-toast')).toBeNull();
    });

    it('does not auto-remove without autoRemove, nor a loading toast', () => {
      showToast('success', 'Stays', { autoRemove: false });
      jest.advanceTimersByTime(60000);
      expect(document.getElementById('app-toast')).not.toBeNull();

      showToast('loading', 'Working', { autoRemove: true, duration: 100 });
      jest.advanceTimersByTime(60000);
      expect(document.getElementById('app-toast')).not.toBeNull();
    });

    it('runs the action callback once on click and removes the toast', () => {
      const onClick = jest.fn();
      showToast('warning', 'Do something', { action: { label: 'Fix it', onClick } });

      const link = getToast().querySelector<HTMLAnchorElement>('#app-toast-action');
      expect(link?.textContent).toBe('Fix it');
      expect(link).toHaveAttribute('href', '#');
      link?.click();

      expect(onClick).toHaveBeenCalledTimes(1);
      expect(document.getElementById('app-toast')).toBeNull();
    });

    it('runs the action callback on mousedown as well', () => {
      const onClick = jest.fn();
      showToast('warning', 'Do something', { action: { label: 'Fix it', onClick } });

      getToast()
        .querySelector('#app-toast-action')
        ?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));

      expect(onClick).toHaveBeenCalledTimes(1);
      expect(document.getElementById('app-toast')).toBeNull();
    });

    it('renders no action link without an action', () => {
      showToast('success', 'No action');

      expect(getToast().querySelector('#app-toast-action')).toBeNull();
    });
  });
});

describe('showUndoToast', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    (window as unknown as { __toastXss?: boolean }).__toastXss = undefined;
  });

  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  it('renders markup in the message literally and adds no element for it', () => {
    showUndoToast({ message: PAYLOAD, duration: 60000, onUndo: jest.fn() });

    const toast = getToast();
    expect(toast.querySelector('img')).toBeNull();
    expect(toast.textContent).toContain(PAYLOAD);
    expect((window as unknown as { __toastXss?: boolean }).__toastXss).toBeUndefined();
  });

  it('stops a replaced toast: its timer leaves the new toast and u undoes only the new one', () => {
    const firstUndo = jest.fn();
    const firstExpire = jest.fn();
    const secondUndo = jest.fn();
    showUndoToast({ message: 'first', onUndo: firstUndo, onExpire: firstExpire });
    jest.advanceTimersByTime(4000);
    showUndoToast({ message: 'second', onUndo: secondUndo });
    expect(firstExpire).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(1500);
    expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
    expect(getToast().textContent).toContain('second');

    act(() => {
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'u' }));
    });
    expect(secondUndo).toHaveBeenCalledTimes(1);
    expect(firstUndo).not.toHaveBeenCalled();
    expect(document.getElementById('app-toast')).toBeNull();
  });

  it('leaves a newer toast in place when the replaced one is dismissed late', () => {
    const dismiss = showUndoToast({ message: 'first', onUndo: jest.fn() });
    showUndoToast({ message: 'second', onUndo: jest.fn() });
    dismiss();
    expect(getToast().textContent).toContain('second');
  });

  it('is replaced by a plain toast, whose timer then is the only one', () => {
    const onUndo = jest.fn();
    showUndoToast({ message: 'first', duration: 1000, onUndo });
    showToast('success', 'saved', { autoRemove: true, duration: 3000 });
    jest.advanceTimersByTime(1500);
    expect(getToast().textContent).toContain('saved');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'u' }));
    expect(onUndo).not.toHaveBeenCalled();
  });
});

describe('showKeepOpenWarningToast', () => {
  beforeEach(() => jest.useFakeTimers());

  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  const keepOpenedButton = () =>
    Array.from(getToast().querySelectorAll('button')).find(b => b.textContent === 'Keep open');

  it('counts down beside Keep open and the close button, then closes', () => {
    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst\nsecond', 8000);
    });

    const fill = getToast().querySelector<HTMLElement>('#app-toast-bar-fill');
    expect(fill?.style.transitionDuration).toBe('8000ms');
    expect(fill?.style.width).toBe('0%');
    expect(keepOpenedButton()).toBeDefined();
    expect(getToast().querySelector('#app-toast-close')).not.toBeNull();
    expect(getToast().querySelector('#app-toast-message')?.textContent).toBe(
      'Saved, with warnings:\nfirst\nsecond'
    );

    act(() => {
      jest.advanceTimersByTime(7999);
    });
    expect(document.getElementById('app-toast')).not.toBeNull();
    act(() => {
      jest.advanceTimersByTime(1);
    });
    expect(document.getElementById('app-toast')).toBeNull();
  });

  const kept = () => document.getElementById('app-toast-kept');

  const showAndKeep = (message: string) => {
    act(() => {
      showKeepOpenWarningToast(message, 8000);
    });
    act(() => {
      keepOpenedButton()?.click();
    });
  };

  it('stays open after Keep open, with no bar or button, until it is closed', () => {
    showAndKeep('Saved, with warnings:\nfirst');
    act(() => {
      jest.advanceTimersByTime(60000);
    });

    expect(kept()).not.toBeNull();
    expect(document.getElementById('app-toast')).toBeNull();
    expect(kept()?.querySelector('#app-toast-bar-fill')).toBeNull();
    expect(kept()?.querySelector('[data-testid="app-toast-keep-open-button"]')).toBeNull();
    expect(document.activeElement).toBe(kept()?.querySelector('#app-toast-close'));

    act(() => {
      kept()?.querySelector<HTMLButtonElement>('#app-toast-close')?.click();
    });
    expect(kept()).toBeNull();
  });

  it('is not replaced by a later toast once kept: the later toast is shown below it', () => {
    showAndKeep('Saved, with warnings:\nfirst');

    act(() => {
      showToast('error', 'Save blocked');
    });

    expect(kept()?.textContent).toContain('first');
    expect(getToast().textContent).toContain('Save blocked');
    expect(getToast().querySelector<HTMLElement>('.alert')?.style.top).toBe('30px');

    act(() => {
      kept()?.querySelector<HTMLButtonElement>('#app-toast-close')?.click();
    });
    expect(kept()).toBeNull();
    expect(getToast().querySelector<HTMLElement>('.alert')?.style.top).toBe('20px');
  });

  it('is replaced by a later toast while it is still counting down', () => {
    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst');
    });
    act(() => {
      showToast('error', 'Save blocked');
    });

    expect(kept()).toBeNull();
    expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
    expect(getToast().textContent).not.toContain('first');
  });

  it('closes an earlier kept toast when a newer one is kept, so only the latest stays', () => {
    showAndKeep('Saved, with warnings:\nfirst');
    showAndKeep('Saved, with warnings:\nsecond');

    expect(document.querySelectorAll('#app-toast-kept')).toHaveLength(1);
    expect(kept()?.textContent).toContain('second');
  });

  it('is closed by closeKeptToast, which leaves the replaceable toast in place', () => {
    showAndKeep('Saved, with warnings:\nfirst');
    act(() => {
      showToast('error', 'Save blocked');
    });

    act(() => {
      closeKeptToast();
    });
    expect(kept()).toBeNull();
    expect(getToast().textContent).toContain('Save blocked');
  });

  it('is removed by removeToast', () => {
    showAndKeep('Saved, with warnings:\nfirst');

    act(() => {
      removeToast();
    });
    expect(kept()).toBeNull();
  });

  it('renders markup in the message literally', () => {
    act(() => {
      showKeepOpenWarningToast(PAYLOAD);
    });

    expect(getToast().querySelector('img')).toBeNull();
    expect(getToast().textContent).toContain(PAYLOAD);
  });

  it('colours its icon with the text-safe warning token, keeping the brand colour for the border', () => {
    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst');
    });

    expect(getToast().querySelector('i.fas')?.getAttribute('style')).toContain(
      'var(--warning-text)'
    );
  });

  it('gives Keep open its test id', () => {
    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst');
    });

    expect(
      getToast().querySelector('[data-testid="app-toast-keep-open-button"]')?.textContent
    ).toBe('Keep open');
  });

  it('announces the warning through a live region that outlives the toast, without focus', () => {
    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst');
    });

    const region = document.getElementById('app-toast-live-assertive');
    expect(region).not.toBeNull();
    expect(region).toHaveAttribute('role', 'alert');
    expect(region).toHaveAttribute('aria-live', 'assertive');
    expect(getToast().contains(region)).toBe(false);
    expect(document.activeElement).toBe(document.body);

    act(() => {
      jest.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    });
    expect(region?.textContent).toBe('Saved, with warnings:\nfirst');

    act(() => {
      showKeepOpenWarningToast('Saved, with warnings:\nfirst');
    });
    expect(region?.textContent).toBe('');
    act(() => {
      jest.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    });
    expect(region?.textContent).toBe('Saved, with warnings:\nfirst');
    expect(document.querySelectorAll('#app-toast-live-assertive')).toHaveLength(1);
  });
});

describe('showSuccessCountdownToast', () => {
  beforeEach(() => jest.useFakeTimers());

  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  it('counts down beside the close button alone, then closes', () => {
    showSuccessCountdownToast('Agent Surface "orders" saved', 3000);

    const toast = getToast();
    expect(toast.querySelector('i.fas')).toHaveClass('fa-check-circle');
    expect(toast.querySelector('i.fas')?.getAttribute('style')).toContain('var(--success-text)');
    expect(toast.querySelector<HTMLElement>('#app-toast-bar-fill')?.style.transitionDuration).toBe(
      '3000ms'
    );
    expect(toast.querySelector('#app-toast-button-mount')).toBeNull();
    expect(toast.querySelectorAll('button')).toHaveLength(1);
    expect(toast.querySelector('#app-toast-close')).not.toBeNull();
    expect(toast.querySelector('#app-toast-message')?.textContent).toBe(
      'Agent Surface "orders" saved'
    );

    jest.advanceTimersByTime(3000);
    expect(document.getElementById('app-toast')).toBeNull();
  });

  it('announces the message politely', () => {
    showSuccessCountdownToast('Agent Surface "orders" saved');

    const region = document.getElementById('app-toast-live-polite');
    expect(region).toHaveAttribute('role', 'status');
    expect(region).toHaveAttribute('aria-live', 'polite');
    jest.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    expect(region?.textContent).toBe('Agent Surface "orders" saved');
  });
});

describe('a replaced plain toast', () => {
  beforeEach(() => jest.useFakeTimers());

  afterEach(() => {
    removeToast();
    jest.useRealTimers();
  });

  it('does not remove the newer toast when its own timer ends', () => {
    showToast('success', 'first', { autoRemove: true, duration: 1000 });
    jest.advanceTimersByTime(500);
    showToast('success', 'second', { autoRemove: true, duration: 3000 });
    jest.advanceTimersByTime(600);
    expect(getToast().textContent).toContain('second');
  });
});
