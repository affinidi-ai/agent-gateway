import { removeToast, showToast, showUndoToast } from '../toaster';

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
        expect(alert).toHaveClass(alertClass, 'alert-dismissible', 'fade', 'show');
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

    it('replaces an existing toast', () => {
      showToast('success', 'first');
      showToast('success', 'second');

      expect(document.querySelectorAll('#app-toast')).toHaveLength(1);
      expect(getToast().textContent).toContain('second');
      expect(getToast().textContent).not.toContain('first');
    });

    it('removes the toast with the close button', () => {
      showToast('error', 'Closable');

      const close = getToast().querySelector<HTMLButtonElement>('button.close');
      expect(close).not.toBeNull();
      expect(close).toHaveAttribute('title', 'Close notification');
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
});
