import React from 'react';

type AppButtonVariant =
  | 'primary'
  | 'secondary'
  | 'danger'
  | 'warning'
  | 'outline-primary'
  | 'outline-secondary'
  | 'outline-danger'
  | 'link';

type AppButtonSize = 'sm' | 'md';

interface AppButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: AppButtonVariant;
  size?: AppButtonSize;
  loading?: boolean;
  loadingLabel?: string;
  iconStart?: React.ReactNode;
  iconEnd?: React.ReactNode;
}

const VARIANT_CLASS: Record<AppButtonVariant, string> = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger: 'btn-danger',
  warning: 'btn-warning',
  'outline-primary': 'btn-outline-primary',
  'outline-secondary': 'btn-outline-secondary',
  'outline-danger': 'btn-outline-danger',
  link: 'btn-link',
};

const SIZE_CLASS: Record<AppButtonSize, string> = {
  sm: 'btn-sm',
  md: 'btn-md',
};

export const AppButton = React.forwardRef<HTMLButtonElement, AppButtonProps>(function AppButton(
  {
    variant = 'primary',
    size = 'sm',
    loading = false,
    loadingLabel,
    iconStart,
    iconEnd,
    className = '',
    disabled = false,
    type,
    children,
    ...rest
  },
  ref
) {
  const resolvedLoadingLabel =
    loadingLabel ?? (typeof children === 'string' ? children : 'Loading');

  const classes = [
    'btn',
    'app-button',
    VARIANT_CLASS[variant],
    SIZE_CLASS[size],
    variant === 'primary' ? 'shadow-sm' : '',
    variant === 'secondary' ? 'app-button-secondary' : '',
    loading ? 'app-button-loading' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <button
      {...rest}
      ref={ref}
      type={type ?? 'button'}
      className={classes}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
    >
      <span className="app-button-content">
        {loading ? (
          <>
            <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true" />
            <span>{resolvedLoadingLabel}</span>
          </>
        ) : (
          <>
            {iconStart}
            {children}
            {iconEnd}
          </>
        )}
      </span>
    </button>
  );
});
