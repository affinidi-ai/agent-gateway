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

export const showToast = (
  type: ToastType,
  text: string,
  options: ToastOptions = { autoRemove: true, duration: 3000 }
) => {
  // Remove any existing toast
  const existingToast = document.getElementById('app-toast');
  if (existingToast) {
    existingToast.remove();
  }

  // Create new toast element
  const toast = document.createElement('div');
  toast.id = 'app-toast';

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
    <div class="alert ${alertClass} alert-dismissible fade show" style="
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
        <div class="flex-grow-1">
          <strong>${label}</strong><br/>
        </div>
      </div>
      <button type="button" class="close" title="Close notification" style="position: absolute; top: 10px; right: 15px; z-index: 1000; background: transparent; border: none;">
        <span style="font-size: 1.2em; color: ${closeColor};">&times;</span>
      </button>
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
          document.getElementById('app-toast')?.remove();
        }
      };
      link.addEventListener('click', fire);
      link.addEventListener('mousedown', fire);

      wrapper.appendChild(link);
      body.appendChild(wrapper);
    }
  }

  toast
    .querySelector('button.close')
    ?.addEventListener('click', () => document.getElementById('app-toast')?.remove());

  // Add to page
  document.body.appendChild(toast);

  // Auto-remove with different timers based on type and options
  if (options.autoRemove && type !== 'loading') {
    const duration =
      type === 'error' || type === 'warning' ? options.duration || 5000 : options.duration || 3000;
    setTimeout(() => {
      document.getElementById('app-toast')?.remove();
    }, duration);
  }
};

export const removeToast = () => {
  document.getElementById('app-toast')?.remove();
};

export interface UndoToastOptions {
  message?: string;
  duration?: number;
  onUndo: () => void;
  /** Called when the toast expires or is dismissed WITHOUT clicking Undo. */
  onExpire?: () => void;
}

/**
 * Toast with an Undo action and a live countdown progress bar.
 * Auto-dismisses after `duration` ms (default 5000).
 */
export const showUndoToast = ({
  message = 'Changes discarded.',
  duration = 5000,
  onUndo,
  onExpire,
}: UndoToastOptions): void => {
  document.getElementById('app-toast')?.remove();

  const isDark = document.body.classList.contains('dark-theme');
  const bgColor = isDark ? 'rgba(15, 23, 42, 0.85)' : 'rgba(255, 255, 255, 0.95)';
  const borderRing = isDark ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(0,0,0,0.06)';
  const textColor = isDark ? '#f1f5f9' : 'inherit';
  const closeColor = isDark ? '#94a3b8' : UI_COLORS.neutralMuted;
  const accent = UI_COLORS.primary;
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
        <i class="fas fa-exclamation-triangle" style="color:${accent};flex-shrink:0;"></i>
        <span id="app-toast-message" style="flex:1;"></span>
        <span id="app-toast-undo-mount" style="flex-shrink:0;"></span>
        <button id="app-toast-close" type="button" title="Dismiss"
                style="flex-shrink:0;background:transparent;border:none;
                       padding:0;cursor:pointer;line-height:1;">
          <span style="font-size:1.2em;color:${closeColor};">&times;</span>
        </button>
      </div>
      <div style="height:1.5em;"></div>
    </div>`;
  // `message` is attached as text, never parsed as HTML.
  const messageEl = toast.querySelector<HTMLElement>('#app-toast-message');
  if (messageEl) messageEl.textContent = message;
  document.body.appendChild(toast);

  let undoRoot: Root | null = null;

  let expired = false;
  const remove = (undone: boolean) => {
    document.removeEventListener('keydown', keyHandler);
    clearInterval(ticker);
    clearTimeout(timer);
    undoRoot?.unmount();
    undoRoot = null;
    document.getElementById('app-toast')?.remove();
    if (!undone && !expired) {
      expired = true;
      onExpire?.();
    }
  };

  const fireUndo = () => {
    remove(true);
    onUndo();
  };

  const mountEl = toast.querySelector<HTMLElement>('#app-toast-undo-mount');
  if (mountEl) {
    undoRoot = createRoot(mountEl);
    undoRoot.render(
      React.createElement(
        AppButton,
        { variant: 'secondary', size: 'sm', onClick: fireUndo },
        'Undo'
      )
    );
  }

  toast.querySelector('#app-toast-close')?.addEventListener('click', () => remove(false));

  // 'u' key triggers undo while the toast is visible (ignored inside inputs).
  const keyHandler = (e: KeyboardEvent) => {
    if (e.key !== 'u' || e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = ((document.activeElement as HTMLElement | null)?.tagName ?? '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    fireUndo();
  };
  document.addEventListener('keydown', keyHandler);

  // Progress bar: animate from 100% → 0% over `duration`
  const fill = toast.querySelector<HTMLElement>('#app-toast-bar-fill');
  if (fill) {
    fill.style.transitionDuration = `${duration}ms`;
    void fill.offsetWidth; // force reflow so transition fires from 100%
    fill.style.width = '0%';
  }

  const ticker = 0; // no visible countdown — kept for remove() signature compatibility

  const timer = setTimeout(() => remove(false), duration);
};
