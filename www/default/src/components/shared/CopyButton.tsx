import React, { useCallback, useEffect, useRef, useState } from 'react';

interface CopyButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  text: string;
  size?: 'sm' | 'xs' | 'md';
  variant?: 'link' | 'outline-primary';
  label?: string;
  copiedLabel?: string;
  onCopyError?: (error: unknown) => void;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  text,
  title = 'Copy',
  className = '',
  size = 'sm',
  variant = 'link',
  label,
  copiedLabel = 'Copied',
  onCopyError,
  style,
  ...rest
}) => {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (resetTimer.current) clearTimeout(resetTimer.current);
    },
    []
  );

  const handleCopy = useCallback(
    async (e: React.MouseEvent) => {
      e.stopPropagation();
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        if (resetTimer.current) clearTimeout(resetTimer.current);
        resetTimer.current = setTimeout(() => setCopied(false), 2000);
      } catch (error) {
        setCopied(false);
        onCopyError?.(error);
      }
    },
    [onCopyError, text]
  );

  const buttonClasses =
    variant === 'outline-primary'
      ? `btn btn-outline-primary btn-${size}`
      : `btn btn-link btn-${size} p-0 ms-2 align-baseline border-0`;

  return (
    <button
      {...rest}
      type="button"
      className={`${buttonClasses} ${className}`}
      onClick={handleCopy}
      title={title}
      style={{ ...style, lineHeight: 1 }}
    >
      <i
        className={`fas ${copied ? 'fa-check text-success' : 'fa-copy'}${label ? ' me-1' : ''}`}
        style={variant === 'link' ? { fontSize: '0.8em' } : undefined}
      ></i>
      {label && (copied ? copiedLabel : label)}
    </button>
  );
};
