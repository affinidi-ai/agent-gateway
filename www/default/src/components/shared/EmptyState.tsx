import React from 'react';
import { Link as RouterLink } from 'react-router-dom';
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
  /** When set, the CTA renders as an in-app link to this route instead of a button. */
  ctaTo?: string;
  ctaTestId?: string;
  docsHref?: string;
  docsLabel?: string;
  docsTestId?: string;
  /** `body` appends the docs link to the body text; `actions` shows it beside the CTA. */
  docsPlacement?: 'body' | 'actions';
  variant?: EmptyStateVariant;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  body,
  ctaLabel,
  ctaIcon,
  onCtaClick,
  ctaTo,
  ctaTestId,
  docsHref,
  docsLabel = 'View Docs',
  docsTestId,
  docsPlacement = 'body',
  variant = 'inline',
}) => {
  const hasCta = Boolean(ctaLabel && (onCtaClick || ctaTo));
  const ctaIconStart = ctaIcon ? (
    <i className={`fas ${ctaIcon} fa-sm me-1`} aria-hidden="true" />
  ) : null;
  const docsLink = docsHref ? (
    <Link href={docsHref} external className="text-muted" testId={docsTestId}>
      {docsLabel}
    </Link>
  ) : null;
  const bodyDocsLink = docsPlacement === 'body' ? docsLink : null;
  const actionsDocsLink = docsPlacement === 'actions' ? docsLink : null;
  const cta = !hasCta ? null : ctaTo ? (
    <RouterLink to={ctaTo} data-testid={ctaTestId}>
      {ctaIconStart}
      {ctaLabel}
    </RouterLink>
  ) : (
    <AppButton
      data-testid={ctaTestId}
      variant="primary"
      size="md"
      onClick={onCtaClick}
      iconStart={ctaIconStart}
    >
      {ctaLabel}
    </AppButton>
  );
  const actions = actionsDocsLink ? (
    <div className="d-flex align-items-center justify-content-center gap-2">
      {cta}
      {cta && (
        <span className="text-muted" aria-hidden="true">
          ·
        </span>
      )}
      {actionsDocsLink}
    </div>
  ) : (
    cta
  );

  if (variant === 'overlay') {
    return (
      <div className="connections-empty-overlay">
        <i className={`fas ${icon} fa-2x text-muted`} aria-hidden="true" />
        <h3 className="connections-empty-overlay__headline">{title}</h3>
        <p className="connections-empty-overlay__subtext">
          {body} {bodyDocsLink}
        </p>
        {actions}
      </div>
    );
  }

  return (
    <div className="text-center py-5">
      <i className={`fas ${icon} fa-3x text-muted mb-3`} aria-hidden="true" />
      <h6 className="font-weight-bold">{title}</h6>
      <p className="text-muted mb-4">
        {body} {bodyDocsLink}
      </p>
      {actions}
    </div>
  );
};

export default EmptyState;
