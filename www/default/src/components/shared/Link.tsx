import React from 'react';

type LinkVariant = 'standalone' | 'inline';

interface LinkProps {
  href: string;
  children: React.ReactNode;
  variant?: LinkVariant;
  external?: boolean;
  disabled?: boolean;
  className?: string;
  testId?: string;
  onClick?: React.MouseEventHandler<HTMLAnchorElement>;
}

export const Link: React.FC<LinkProps> = ({
  href,
  children,
  variant = 'standalone',
  external = false,
  disabled = false,
  className = '',
  testId,
  onClick,
}) => {
  const classes = [`link-${variant}`, className].filter(Boolean).join(' ');
  const externalProps = external ? { target: '_blank', rel: 'noopener noreferrer' } : {};
  const disabledStyle: React.CSSProperties | undefined = disabled
    ? { pointerEvents: 'none', cursor: 'default' }
    : undefined;

  return (
    <a
      href={disabled ? undefined : href}
      className={classes}
      style={disabledStyle}
      aria-disabled={disabled || undefined}
      data-testid={testId}
      onClick={onClick}
      {...externalProps}
    >
      {children}
      {external && variant === 'standalone' && (
        <i className="fas fa-arrow-up-right-from-square fa-xs" aria-hidden="true" />
      )}
    </a>
  );
};

export default Link;
