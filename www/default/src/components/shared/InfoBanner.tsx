import React, { useState } from 'react';

type InfoBannerVariant = 'default' | 'warning' | 'danger' | 'success';

interface InfoBannerProps {
  title?: string;
  summary?: React.ReactNode;
  icon?: string;
  variant?: InfoBannerVariant;
  collapsible?: boolean;
  defaultOpen?: boolean;
  className?: string;
  testIdPrefix?: string;
  children?: React.ReactNode;
  /** Optional link to the official documentation site for this topic. */
  docLink?: string;
  /** Label for the doc link. Defaults to "Learn more". */
  docLinkLabel?: string;
}

const InfoBanner: React.FC<InfoBannerProps> = ({
  title,
  summary,
  icon = 'fa-info-circle',
  variant = 'default',
  collapsible = true,
  defaultOpen = false,
  className = 'config-section',
  testIdPrefix,
  children,
  docLink,
  docLinkLabel = 'Learn more',
}) => {
  const docLinkNode = docLink && (
    <div className="surface-info-panel-doclink">
      <a
        href={docLink}
        target="_blank"
        rel="noopener noreferrer"
        data-testid={testIdPrefix ? `${testIdPrefix}-context-doclink` : undefined}
      >
        {docLinkLabel} <i className="fas fa-arrow-right ms-1" aria-hidden="true" />
      </a>
    </div>
  );
  const [open, setOpen] = useState(defaultOpen);
  const variantClass = variant !== 'default' ? ` surface-info-panel--${variant}` : '';
  const collapsibleClass = collapsible ? ' surface-info-panel--collapsible' : '';

  return (
    <div
      className={`${className} surface-info-panel${collapsibleClass}${variantClass}`}
      data-testid={testIdPrefix ? `${testIdPrefix}-context` : undefined}
    >
      {title && collapsible && (
        <button
          type="button"
          className="surface-info-panel-title d-flex"
          onClick={() => setOpen(prev => !prev)}
          aria-expanded={open}
          data-testid={testIdPrefix ? `${testIdPrefix}-context-toggle` : undefined}
        >
          <i className={`fas ${icon} me-1`} aria-hidden="true" />
          <span className="flex-grow-1">{title}</span>
          <i className={`fas fa-chevron-${open ? 'up' : 'down'} ms-2`} aria-hidden="true" />
        </button>
      )}
      {title && !collapsible && (
        <div className="surface-info-panel-title">
          <i className={`fas ${icon} me-1`} aria-hidden="true" />
          {title}
        </div>
      )}
      {collapsible ? (
        open && (
          <div
            className="surface-info-panel-body"
            data-testid={testIdPrefix ? `${testIdPrefix}-context-body` : undefined}
          >
            {summary && <div className="surface-info-panel-summary">{summary}</div>}
            {children}
            {docLinkNode}
          </div>
        )
      ) : (
        <>
          {summary && (
            <div className="surface-info-panel-summary">
              {!title && <i className={`fas ${icon} me-2`} aria-hidden="true" />}
              {summary}
            </div>
          )}
          {children}
          {docLinkNode}
        </>
      )}
    </div>
  );
};

export default InfoBanner;
