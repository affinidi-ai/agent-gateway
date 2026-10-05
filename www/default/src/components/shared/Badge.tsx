import React from 'react';

type BadgeTone =
  | 'primary'
  | 'secondary'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'light'
  | 'dark';

type BadgeSize = 'sm' | 'md';

interface BadgeProps extends Omit<React.HTMLAttributes<HTMLSpanElement>, 'prefix' | 'suffix'> {
  value: React.ReactNode;
  tone?: BadgeTone;
  size?: BadgeSize;
  prefix?: React.ReactNode;
  suffix?: React.ReactNode;
  ariaLabel?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  value,
  tone = 'primary',
  size = 'md',
  prefix,
  suffix,
  className,
  ariaLabel,
  ...rest
}) => {
  const classes = ['badge', 'app-badge', `app-badge--${size}`, `text-bg-${tone}`, className]
    .filter(Boolean)
    .join(' ');

  return (
    <span className={classes} aria-label={ariaLabel} {...rest}>
      {prefix}
      {value}
      {suffix}
    </span>
  );
};
