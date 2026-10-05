import React from 'react';

interface TopbarActionButtonProps extends Omit<
  React.ButtonHTMLAttributes<HTMLButtonElement>,
  'type'
> {
  appearance?: 'secondary' | 'primary' | 'avatar';
  shape?: 'icon' | 'content';
  iconClassName?: string;
  iconId?: string;
  badge?: React.ReactNode;
  isActive?: boolean;
  isOpen?: boolean;
  isLoading?: boolean;
}

export const TopbarActionButton: React.FC<TopbarActionButtonProps> = ({
  appearance = 'secondary',
  shape = 'icon',
  iconClassName,
  iconId,
  badge,
  isActive = false,
  isOpen = false,
  isLoading = false,
  className = '',
  children,
  ...rest
}) => {
  const classes = [
    'topbar-action-button',
    `topbar-action-button--${appearance}`,
    `topbar-action-button--${shape}`,
    isActive ? 'is-active' : '',
    isOpen ? 'is-open' : '',
    isLoading ? 'is-loading' : '',
    badge ? 'has-badge' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <button
      type="button"
      className={classes}
      disabled={rest.disabled || isLoading}
      aria-busy={isLoading}
      {...rest}
    >
      {isLoading ? (
        <i className="fas fa-spinner fa-spin"></i>
      ) : (
        <>
          {iconClassName && <i className={iconClassName} id={iconId}></i>}
          {children}
        </>
      )}
      {badge && !isLoading && <span className="topbar-action-button-badge">{badge}</span>}
    </button>
  );
};
