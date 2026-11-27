/**
 * Common toaster utility for displaying notifications across the application
 */
import React from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { UI_COLORS } from './uiPalette';
import { AppButton } from '../components/shared/AppButton';

export type ToastType = 'success' | 'warning' | 'error' | 'loading';

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastOptions {
  autoRemove?: boolean;
  duration?: number; // in milliseconds
  /** Optional inline action rendered as a link inside the toast body. */
  action?: ToastAction;
}

/** Every toast's close button: the last item of its row, vertically centred. */
const closeButtonHtml = (closeColor: string) => `
        <button id="app-toast-close" type="button" title="Dismiss"
                style="flex-shrink:0;background:transparent;border:none;
                       padding:0;cursor:pointer;line-height:1;">
          <span style="font-size:1.2em;color:${closeColor};">&times;</span>
        </button>`;

/**
 * Live regions that stay in the page between toasts, one per politeness, so a screen reader
 * announces a toast's message without the toast taking focus. A region inserted together with
 * its text is often not announced, which is why these outlive any one toast.
 */
const LIVE_REGION_ID = {
  polite: 'app-toast-live-polite',
  assertive: 'app-toast-live-assertive',
} as const;

/** How long a cleared live region stays empty before it gets the new text, so a repeat is read. */
export const ANNOUNCE_DELAY_MS = 100;

const announce = (message: string, politeness: keyof typeof LIVE_REGION_ID) => {
  const id = LIVE_REGION_ID[politeness];
  let region = document.getElementById(id);
  if (!region) {
    region = document.createElement('div');
    region.id = id;
    region.className = 'visually-hidden';
    region.setAttribute('role', politeness === 'assertive' ? 'alert' : 'status');
    region.setAttribute('aria-live', politeness);
    region.setAttribute('aria-atomic', 'true');
    document.body.appendChild(region);
  }
  const target = region;
  target.textContent = '';
  setTimeout(() => {
    target.textContent = message;
  }, ANNOUNCE_DELAY_MS);
};

// Removes the toast on screen with its timer and key handler; a new toast replaces it through this.
let dismissActive: (() => void) | null = null;

const replaceActiveToast = () => {
  dismissActive?.();
  document.getElementById('app-toast')?.remove();
};

/**
 * A toast its user chose to keep (Keep open) leaves the replaceable slot: it takes this id,
 * a new toast no longer replaces it, and the toast on screen is laid out below it.
 */
const KEPT_TOAST_ID = 'app-toast-kept';
let dismissKept: (() => void) | null = null;

const TOAST_TOP_PX = 20;
const TOAST_GAP_PX = 10;

/** Places the replaceable toast below a kept one, or at the top when none is kept. */
const layoutToasts = () => {
  const active = document.getElementById('app-toast')?.firstElementChild as HTMLElement | null;
  if (!active) return;
  const kept = document.getElementById(KEPT_TOAST_ID)?.firstElementChild;
  const below = kept ? kept.getBoundingClientRect().height + TOAST_GAP_PX : 0;
  active.style.top = `${TOAST_TOP_PX + below}px`;
};

export const showToast = (
  type: ToastType,
  text: string,
  options: ToastOptions = { autoRemove: true, duration: 3000 }
) => {
  replaceActiveToast();

  // Create new toast element
  const toast = document.createElement('div');
  toast.id = 'app-toast';
  let timer: ReturnType<typeof setTimeout> | undefined;
  const close = () => {
    clearTimeout(timer);
    toast.remove();
    if (dismissActive === close) dismissActive = null;
  };

  // Set class based on type
  let alertClass = 'alert-info'; // Default for loading
  let borderColor = UI_COLORS.primary;
  let icon = 'fa-spinner fa-spin';
  let label = 'Loading...';

  if (type === 'success') {
    alertClass = 'alert-success';
    borderColor = UI_COLORS.success;
    icon = 'fa-check-circle';
    label = 'Success!';
  } else if (type === 'warning') {
    alertClass = 'alert-warning';
    borderColor = UI_COLORS.warning;
    icon = 'fa-exclamation-triangle';
    label = 'Warning';
  } else if (type === 'error') {
    alertClass = 'alert-danger';
    borderColor = UI_COLORS.danger;
    icon = 'fa-exclamation-circle';
    label = 'Error!';
  }

  const isDark = document.body.classList.contains('dark-theme');
  const bgColor = isDark ? 'rgba(15, 23, 42, 0.85)' : 'rgba(255, 255, 255, 0.95)';
  const borderRing = isDark
    ? '1px solid rgba(255, 255, 255, 0.08)'
    : '1px solid rgba(0, 0, 0, 0.06)';
  const textColor = isDark ? '#f1f5f9' : 'inherit';
  const closeColor = isDark ? '#94a3b8' : UI_COLORS.neutralMuted;

  // The template below holds only constants (classes, colours, the type's label). The caller's
  // `text` and the action label are attached afterwards as text nodes, never parsed as HTML,
  // because toasts carry user-controlled names and server error messages.
  toast.innerHTML = `
    <div class="alert ${alertClass} fade show" style="
      position: fixed; 
      top: 20px; 
      right: 20px; 
      z-index: 9999; 
      min-width: 350px; 
      max-width: 500px; 
      border-left: 4px solid ${borderColor};
      border-top: ${borderRing};
      border-right: ${borderRing};
      border-bottom: ${borderRing};
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
      backdrop-filter: blur(10px);
      background: ${bgColor};
      color: ${textColor};
    ">
      <div class="d-flex align-items-center">
        <div class="me-3">
          <i class="fas ${icon}" style="font-size: 1.2em; color: ${borderColor};"></i>
        </div>
        <div class="flex-grow-1 me-2" style="min-width:0;overflow-wrap:anywhere;">
          <strong>${label}</strong><br/>
        </div>${closeButtonHtml(closeColor)}
      </div>
    </div>
  `;

  const body = toast.querySelector<HTMLElement>('.flex-grow-1');
  if (body) {
    const message = document.createElement('span');
    message.style.fontSize = '0.9em';
    message.style.whiteSpace = 'pre-line';
    message.textContent = text;
    body.appendChild(message);

    if (options.action) {
      const action = options.action;
      const wrapper = document.createElement('div');
      wrapper.style.marginTop = '6px';

      const link = document.createElement('a');
      link.href = '#';
      link.id = 'app-toast-action';
      link.setAttribute(
        'style',
        `font-size: 0.9em; color: ${borderColor}; font-weight: 600; text-decoration: underline; cursor: pointer; position: relative; z-index: 1100;`
      );
      link.textContent = action.label;

      // Attach via mousedown as well as click so the listener fires before any
      // auto-remove timers or focus-loss handlers can swallow the click.
      const fire = (e: Event) => {
        e.preventDefault();
        e.stopPropagation();
        try {
          action.onClick();
        } finally {
          close();
        }
      };
      link.addEventListener('click', fire);
      link.addEventListener('mousedown', fire);

      wrapper.appendChild(link);
      body.appendChild(wrapper);
    }
  }

  toast.querySelector('#app-toast-close')?.addEventListener('click', close);

  // Add to page
  document.body.appendChild(toast);
  dismissActive = close;
  layoutToasts();

  // Auto-remove with different timers based on type and options
  if (options.autoRemove && type !== 'loading') {
    const duration =
      type === 'error' || type === 'warning' ? options.duration || 5000 : options.duration || 3000;
    timer = setTimeout(close, duration);
  }
};

/** Closes the kept toast, if any; the replaceable one stays. */
export const closeKeptToast = () => {
  dismissKept?.();
};

/** Removes every toast on screen, a kept one included. */
export const removeToast = () => {
  replaceActiveToast();
  closeKeptToast();
};

export interface UndoToastOptions {
  message?: string;
  duration?: number;
  onUndo: () => void;
  /** Called when the toast expires or is dismissed WITHOUT clicking Undo. */
  onExpire?: () => void;
}

/** What the button of a countdown toast can do to its toast. */
interface CountdownToastControls {
  /** Removes the toast; `expired` runs its `onExpire`. */
  remove: (expired: boolean) => void;
  /** Stops the countdown and removes the bar and the button, so the toast stays until closed. */
  stopCountdown: () => void;
  /**
   * Stops the countdown and keeps the toast until it is closed: a later toast is shown below it
   * instead of replacing it, and an earlier kept toast is closed.
   */
  keep: () => void;
}

interface CountdownToastOptions {
  message: string;
  duration: number;
  accent: string;
  /** Font Awesome icon class shown before the message. */
  icon?: string;
  /** The icon's colour; `accent` when unset. */
  iconColor?: string;
  /** The button beside the close button; none without a label. */
  buttonLabel?: string;
  /** The button's `data-testid`. */
  buttonTestId?: string;
  onButton?: (controls: CountdownToastControls) => void;
  /** How a screen reader announces the message: `assertive` interrupts, `polite` waits. */
  politeness?: keyof typeof LIVE_REGION_ID;
  /** Called when the toast expires or is closed without its button removing it. */
  onExpire?: () => void;
  /** A key that presses the button while the toast is visible (ignored inside inputs). */
  shortcut?: string;
}

/**
 * Toast with a countdown progress bar and, with `buttonLabel`, one button beside its close
 * button. Closes after `duration` ms. Returns a function that closes it, as its close button
 * does.
 */
const showCountdownToast = ({
  message,
  duration,
  accent,
  icon = 'fa-exclamation-triangle',
  iconColor = accent,
  buttonLabel,
  buttonTestId,
  onButton,
  politeness = 'polite',
  onExpire,
  shortcut,
}: CountdownToastOptions): (() => void) => {
  replaceActiveToast();

  const isDark = document.body.classList.contains('dark-theme');
  const bgColor = isDark ? 'rgba(15, 23, 42, 0.85)' : 'rgba(255, 255, 255, 0.95)';
  const borderRing = isDark ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(0,0,0,0.06)';
  const textColor = isDark ? '#f1f5f9' : 'inherit';
  const closeColor = isDark ? '#94a3b8' : UI_COLORS.neutralMuted;
  // Progress bar: 2 neutral levels lighter than the toast background
  // light ≈ neutral-50 → neutral-200 (#e5e5e5); dark ≈ neutral-900 → neutral-700 (#404040)
  const barColor = isDark ? '#404040' : '#e5e5e5';

  const toast = document.createElement('div');
  toast.id = 'app-toast';
  toast.innerHTML = `
    <div style="
      position:fixed;top:20px;right:20px;z-index:9999;
      min-width:350px;max-width:500px;
      border-left:4px solid ${accent};
      border-top:${borderRing};border-right:${borderRing};border-bottom:${borderRing};
      border-radius:4px;
      box-shadow:0 4px 15px rgba(0,0,0,0.2);
      backdrop-filter:blur(10px);
      background:${bgColor};color:${textColor};
      overflow:hidden;">
      <div id="app-toast-bar-fill"
           style="height:3px;width:100%;background:${barColor};transition:width linear;"></div>
      <div style="height:1.5em;"></div>
      <div style="display:flex;align-items:center;gap:10px;padding:0 12px;font-size:0.9em;">
        <i class="fas ${icon}" style="color:${iconColor};flex-shrink:0;"></i>
        <span id="app-toast-message" style="flex:1;white-space:pre-line;max-height:40vh;overflow-y:auto;overflow-wrap:anywhere;"></span>
        <span id="app-toast-button-mount" style="flex-shrink:0;"></span>${closeButtonHtml(closeColor)}
      </div>
      <div style="height:1.5em;"></div>
    </div>`;
  // `message` is attached as text, never parsed as HTML.
  const messageEl = toast.querySelector<HTMLElement>('#app-toast-message');
  if (messageEl) messageEl.textContent = message;
  document.body.appendChild(toast);
  layoutToasts();
  announce(message, politeness);

  let buttonRoot: Root | null = null;
  const unmountButton = () => {
    buttonRoot?.unmount();
    buttonRoot = null;
  };

  let removed = false;
  const remove = (expired: boolean) => {
    if (removed) return;
    removed = true;
    if (dismissActive === dismiss) dismissActive = null;
    if (dismissKept === dismiss) dismissKept = null;
    document.removeEventListener('keydown', keyHandler);
    clearTimeout(timer);
    unmountButton();
    toast.remove();
    layoutToasts();
    if (expired) onExpire?.();
  };
  const dismiss = () => remove(true);

  const fill = toast.querySelector<HTMLElement>('#app-toast-bar-fill');
  const mountEl = toast.querySelector<HTMLElement>('#app-toast-button-mount');
  const stopCountdown = () => {
    clearTimeout(timer);
    document.removeEventListener('keydown', keyHandler);
    toast.querySelector<HTMLElement>('#app-toast-close')?.focus();
    fill?.remove();
    unmountButton();
    mountEl?.remove();
  };
  const keep = () => {
    stopCountdown();
    dismissKept?.();
    if (dismissActive === dismiss) dismissActive = null;
    toast.id = KEPT_TOAST_ID;
    dismissKept = dismiss;
  };
  const pressButton = () => onButton?.({ remove, stopCountdown, keep });

  if (!buttonLabel) {
    mountEl?.remove();
  } else if (mountEl) {
    const buttonProps: React.ComponentProps<typeof AppButton> & { 'data-testid'?: string } = {
      variant: 'secondary',
      size: 'sm',
      onClick: pressButton,
      'data-testid': buttonTestId,
    };
    buttonRoot = createRoot(mountEl);
    buttonRoot.render(React.createElement(AppButton, buttonProps, buttonLabel));
  }

  toast.querySelector('#app-toast-close')?.addEventListener('click', dismiss);

  const keyHandler = (e: KeyboardEvent) => {
    if (!shortcut || e.key !== shortcut || e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = ((document.activeElement as HTMLElement | null)?.tagName ?? '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    pressButton();
  };
  document.addEventListener('keydown', keyHandler);

  // Progress bar: animate from 100% → 0% over `duration`
  if (fill) {
    fill.style.transitionDuration = `${duration}ms`;
    void fill.offsetWidth; // force reflow so transition fires from 100%
    fill.style.width = '0%';
  }

  const timer = setTimeout(dismiss, duration);
  dismissActive = dismiss;
  return dismiss;
};

/**
 * Toast with an Undo action and a live countdown progress bar.
 * Auto-dismisses after `duration` ms (default 5000). Returns a function that dismisses it
 * without Undo, as its close button does.
 */
export const showUndoToast = ({
  message = 'Changes discarded.',
  duration = 5000,
  onUndo,
  onExpire,
}: UndoToastOptions): (() => void) =>
  showCountdownToast({
    message,
    duration,
    accent: UI_COLORS.primary,
    buttonLabel: 'Undo',
    onButton: ({ remove }) => {
      remove(false);
      onUndo();
    },
    onExpire,
    shortcut: 'u',
  });

/**
 * Warning toast laid out as the undo toast: a countdown progress bar, and a Keep open
 * button where Undo is, which keeps the toast until it is closed, with later toasts shown below
 * it. Closes after `duration` ms (default 8000). Screen readers announce it assertively.
 */
export const showKeepOpenWarningToast = (message: string, duration = 8000): (() => void) =>
  showCountdownToast({
    message,
    duration,
    accent: UI_COLORS.warning,
    iconColor: 'var(--warning-text)',
    buttonLabel: 'Keep open',
    buttonTestId: 'app-toast-keep-open-button',
    onButton: ({ keep }) => keep(),
    politeness: 'assertive',
  });

/**
 * Success toast laid out as the undo toast: a countdown progress bar and the close button,
 * with no other button. Closes after `duration` ms (default 3000, as a plain success toast).
 */
export const showSuccessCountdownToast = (message: string, duration = 3000): (() => void) =>
  showCountdownToast({
    message,
    duration,
    accent: UI_COLORS.success,
    iconColor: 'var(--success-text)',
    icon: 'fa-check-circle',
  });
