import React from 'react';
import { useTwoStepDelete } from '../../hooks/useTwoStepDelete';

interface DeleteButtonProps extends Omit<
  React.ButtonHTMLAttributes<HTMLButtonElement>,
  'onClick' | 'type'
> {
  onDelete: () => void | Promise<void>;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'danger' | 'warning' | 'icon-only';
  confirmTitle?: string;
}

/**
 * A delete button with two-step confirmation
 * First click: Shows warning triangle
 * Second click: Executes delete
 * Click elsewhere: Cancels
 */
export const DeleteButton: React.FC<DeleteButtonProps> = ({
  onDelete,
  className = '',
  disabled = false,
  size = 'sm',
  variant = 'icon-only',
  children,
  title,
  confirmTitle = 'Click again to confirm deletion',
  style: customStyle,
  ...rest
}) => {
  const { isConfirming, isProcessing, handleClick, buttonRef } = useTwoStepDelete(onDelete);

  const baseClasses =
    variant === 'icon-only'
      ? `btn btn-danger btn-${size}`
      : variant === 'warning'
        ? `btn btn-outline-warning btn-${size}`
        : `btn btn-outline-danger btn-${size}`;

  const buttonTitle = isConfirming ? confirmTitle : title || 'Delete';

  // Always apply a box-shadow (transparent when not confirming) to prevent layout shift
  const glowStyle: React.CSSProperties = {
    boxShadow: isConfirming ? '0 0 0 0 rgba(220, 53, 69, 0.7)' : '0 0 0 0 rgba(0, 0, 0, 0)',
    animation: isConfirming ? 'pulse-warning 2s ease-in-out infinite' : undefined,
  };

  const combinedStyle = { ...customStyle, ...glowStyle };

  return (
    <>
      <button
        ref={buttonRef}
        className={`${baseClasses} ${className}`}
        onClick={handleClick}
        disabled={disabled || isProcessing}
        title={buttonTitle}
        type="button"
        style={combinedStyle}
        {...rest}
      >
        {isProcessing ? (
          <>
            <i className="fas fa-spinner fa-spin"></i>
            {children && <span className="ms-1">{children}</span>}
          </>
        ) : isConfirming ? (
          <>
            <i className="fas fa-exclamation-triangle"></i>
            {children && <span className="ms-1">{children}</span>}
          </>
        ) : (
          <>
            <i className="fas fa-trash"></i> {children && <span className="ms-1">{children}</span>}
          </>
        )}
      </button>
      {isConfirming && (
        <style>{`
        @keyframes pulse-warning {
          0%, 100% {
            opacity: 1;
            box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7);
          }
          50% {
            opacity: 0.9;
            box-shadow: 0 0 8px 2px rgba(220, 53, 69, 0.5);
          }
        }
      `}</style>
      )}
    </>
  );
};
