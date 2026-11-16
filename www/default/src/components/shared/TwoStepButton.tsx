import React from 'react';
import { useTwoStepDelete } from '../../hooks/useTwoStepDelete';

interface TwoStepButtonProps {
  /** Runs on the second click. */
  onConfirm: () => void | Promise<void>;
  /** The Font Awesome icon shown before the first click, such as `fa-ban`. */
  icon: string;
  /** Text beside the icon before the first click; none for an icon-only button. */
  label?: string;
  /** Text shown after the first click, asking for the second. */
  confirmLabel: string;
  title: string;
  confirmTitle: string;
  /** Accessible name before the first click; `title` when not given. */
  ariaLabel?: string;
  /** Accessible name after the first click; `confirmTitle` when not given. */
  confirmAriaLabel?: string;
  className?: string;
  /**
   * How the second click is asked for: `inline`, the default, keeps the button's look and shows a
   * warning icon and `confirmLabel`; `danger` turns it into a danger button that reads
   * `confirmLabel`.
   */
  confirmAs?: 'inline' | 'danger';
  'data-testid'?: string;
}

const DANGER_CONFIRM_CLASS = 'btn btn-danger btn-sm text-wrap';

/**
 * A button that acts on its second click and confirms in place: the first click shows
 * `confirmLabel`, the second runs `onConfirm`, and a click elsewhere cancels. For an action
 * that is not a delete; a delete uses `DeleteButton`.
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
  'data-testid': testId,
}) => {
  const { isConfirming, isProcessing, handleClick, buttonRef } = useTwoStepDelete(onConfirm);
  const asksAsDanger = confirmAs === 'danger' && (isConfirming || isProcessing);
  const shownIcon = isProcessing
    ? 'fa-spinner fa-spin'
    : isConfirming
      ? 'fa-exclamation-triangle'
      : icon;
  const text = isConfirming ? confirmLabel : label;
  return (
    <button
      ref={buttonRef}
      type="button"
      className={asksAsDanger ? DANGER_CONFIRM_CLASS : className}
      data-testid={testId}
      title={isConfirming ? confirmTitle : title}
      aria-label={isConfirming ? (confirmAriaLabel ?? confirmTitle) : (ariaLabel ?? title)}
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
          <i className={`fas ${shownIcon} fa-xs`} aria-hidden="true" />
          {text && <span className="ms-1 small">{text}</span>}
        </>
      )}
    </button>
  );
};
