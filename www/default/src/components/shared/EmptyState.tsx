import React from 'react';
import { AppButton } from './AppButton';
import { Link } from './Link';

type EmptyStateVariant = 'inline' | 'overlay';

interface EmptyStateProps {
  icon: string;
  title: string;
  body: React.ReactNode;
  ctaLabel?: string;
  ctaIcon?: string;
  onCtaClick?: () => void;
  docsHref?: string;
  docsLabel?: string;
  variant?: EmptyStateVariant;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  body,
  ctaLabel,
  ctaIcon,
  onCtaClick,
  docsHref,
  docsLabel = 'View Docs',
  variant = 'inline',
}) => {
  const hasCta = Boolean(ctaLabel && onCtaClick);
  const ctaIconStart = ctaIcon ? (
    <i className={`fas ${ctaIcon} fa-sm me-1`} aria-hidden="true" />
  ) : null;
  const docsLink = docsHref ? (
    <Link href={docsHref} external className="text-muted">
      {docsLabel}
    </Link>
  ) : null;

  if (variant === 'overlay') {
    return (
      <div className="connections-empty-overlay">
        <i className={`fas ${icon} fa-2x text-muted`} aria-hidden="true" />
        <h3 className="connections-empty-overlay__headline">{title}</h3>
        <p className="connections-empty-overlay__subtext">
          {body} {docsLink}
        </p>
        {hasCta && (
          <AppButton variant="primary" size="md" onClick={onCtaClick} iconStart={ctaIconStart}>
            {ctaLabel}
          </AppButton>
        )}
      </div>
    );
  }

  return (
    <div className="text-center py-5">
      <i className={`fas ${icon} fa-3x text-muted mb-3`} aria-hidden="true" />
      <h6 className="font-weight-bold">{title}</h6>
      <p className="text-muted mb-4">
        {body} {docsLink}
      </p>
      {hasCta && (
        <AppButton variant="primary" size="md" onClick={onCtaClick} iconStart={ctaIconStart}>
          {ctaLabel}
        </AppButton>
      )}
    </div>
  );
};

export default EmptyState;
