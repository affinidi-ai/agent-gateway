import React from 'react';
import { useTwoStepDelete } from '../../hooks/useTwoStepDelete';

interface TwoStepButtonProps {
  /** Runs on the second click. */
  onConfirm: () => void | Promise<void>;
  /** The Font Awesome icon shown before the first click, such as `fa-ban`; none for a text button. */
  icon?: string;
  /** Text before the first click; none for an icon-only button. */
  label?: string;
  /** Text shown after the first click, asking for the second. */
  confirmLabel: string;
  title: string;
  confirmTitle: string;
  /** Accessible name before the first click; `title` when not given. */
  ariaLabel?: string;
  /**
   * Accessible name after the first click; when not given, `confirmLabel` for a danger confirm
   * and `confirmTitle` otherwise.
   */
  confirmAriaLabel?: string;
  className?: string;
  /**
   * How the second click is asked for: `inline`, the default, keeps the button's look and shows a
   * warning icon and `confirmLabel`; `danger` turns it into a danger button that reads
   * `confirmLabel`.
   */
  confirmAs?: 'inline' | 'danger';
  /** Offers a Cancel button with this test id beside the confirm while it asks. */
  cancelTestId?: string;
  'data-testid'?: string;
}

const DANGER_CONFIRM_CLASS = 'btn btn-danger btn-sm text-wrap';

/**
 * A button that acts on its second click and confirms in place: the first click shows
 * `confirmLabel`, the second runs `onConfirm`, and a click elsewhere, or Cancel when offered,
 * cancels. For an action that is not a delete; a delete uses `DeleteButton`.
 */
export const TwoStepButton: React.FC<TwoStepButtonProps> = ({
  onConfirm,
  icon,
  label,
  confirmLabel,
  title,
  confirmTitle,
  ariaLabel,
  confirmAriaLabel,
  className = '',
  confirmAs = 'inline',
  cancelTestId,
  'data-testid': testId,
}) => {
  const { isConfirming, isProcessing, handleClick, cancel, buttonRef } =
    useTwoStepDelete(onConfirm);
  const asksAsDanger = confirmAs === 'danger' && (isConfirming || isProcessing);
  const shownIcon = isProcessing
    ? 'fa-spinner fa-spin'
    : isConfirming
      ? 'fa-exclamation-triangle'
      : icon;
  const text = isConfirming ? confirmLabel : label;
  const confirmName = confirmAriaLabel ?? (confirmAs === 'danger' ? confirmLabel : confirmTitle);

  const button = (
    <button
      ref={buttonRef}
      type="button"
      className={asksAsDanger ? DANGER_CONFIRM_CLASS : className}
      data-testid={testId}
      title={isConfirming ? confirmTitle : title}
      aria-label={isConfirming ? confirmName : (ariaLabel ?? title)}
      disabled={isProcessing}
      onClick={handleClick}
    >
      {asksAsDanger ? (
        <>
          {isProcessing && <i className="fas fa-spinner fa-spin me-1" aria-hidden="true" />}
          {confirmLabel}
        </>
      ) : (
        <>
          {shownIcon && <i className={`fas ${shownIcon} fa-xs`} aria-hidden="true" />}
          {text && <span className={shownIcon ? 'ms-1 small' : undefined}>{text}</span>}
        </>
      )}
    </button>
  );

  if (!cancelTestId) return button;
  return (
    <span className="d-inline-flex flex-wrap align-items-center gap-2">
      {button}
      {isConfirming && (
        <button
          type="button"
          className="btn btn-link btn-sm p-0"
          data-testid={cancelTestId}
          onMouseDown={e => e.stopPropagation()}
          onClick={e => {
            e.stopPropagation();
            cancel();
            buttonRef.current?.focus();
          }}
        >
          Cancel
        </button>
      )}
    </span>
  );
};
