import React from 'react';
import { DOCS_URL } from '../../config/docs';
import { EmptyState } from './EmptyState';

export const GraphEmptyState: React.FC<{ onCtaClick: () => void }> = ({ onCtaClick }) => (
  <EmptyState
    variant="overlay"
    icon="fa-chart-line"
    title="No connections yet"
    body="Add an Agent Surface and connect your first agent to start seeing connections here."
    ctaLabel="Add Agent Surface"
    ctaIcon="fa-plus"
    onCtaClick={onCtaClick}
    docsHref={DOCS_URL.createFirstSurface}
  />
);
