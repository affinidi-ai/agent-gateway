import React from 'react';
import {
  useAgentCardPreview,
  type PreviewRefreshResult,
  type ServedCardSnapshot,
} from '../../../hooks/useAgentCardPreview';
import { showToast } from '../../../utils/toaster';
import {
  describeFetchCause,
  describeFetchFailure,
  formatRelativeTime,
  type AgentCardPreview,
  type SupportedAgentCardPreview,
} from '../../../utils/agentCardPreview';
import { useOptionalSurfaceMeta } from '../SurfaceMetaContext';
import AgentCardHeader from './AgentCardHeader';
import AgentCardCompare from './AgentCardCompare';
import AgentCardRawJson, { type RawCardPanel } from './AgentCardRawJson';

interface AgentCardTabProps {
  surfaceId?: string;
  isCreate: boolean;
  isDirty: boolean;
  canEdit: boolean;
  hasVariants: boolean;
  refreshKey?: unknown;
  onRefreshed?: () => void;
}

const kb = (bytes: number) => Math.max(1, Math.round(bytes / 1024));

const Notice: React.FC<{
  testId: string;
  variant?: 'info' | 'danger' | 'warning' | 'secondary';
  role?: 'status' | 'alert';
  children: React.ReactNode;
}> = ({ testId, variant = 'info', role, children }) => (
  <div className={`alert alert-${variant} py-2 px-3 mb-3`} role={role} data-testid={testId}>
    {children}
  </div>
);

const StatusUnavailable: React.FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <Notice testId="agent-card-error" variant="danger" role="alert">
    <span>Agent card status unavailable.</span>
    <button
      type="button"
      className="btn btn-outline-secondary btn-sm ms-3"
      onClick={onRetry}
      data-testid="agent-card-retry-button"
    >
      Retry
    </button>
  </Notice>
);

const SurfaceLink: React.FC<{ onOpen: () => void }> = ({ onOpen }) => (
  <p className="agent-card-surface-link" data-testid="agent-card-surface-link">
    The Entry point URL and the rest of the surface settings are in the Surface view.
    <button
      type="button"
      className="btn btn-link btn-sm p-0 ms-2 align-baseline"
      onClick={onOpen}
      data-testid="agent-card-open-surface-button"
    >
      Open the Surface view
    </button>
  </p>
);

function oversizeBytes(p: SupportedAgentCardPreview): number | null {
  const omitted = [
    p.before === null ? p.before_bytes : null,
    p.after === null ? p.after_bytes : null,
  ].filter((n): n is number => n !== null && n > p.display_limit_bytes);
  return omitted.length > 0 ? Math.max(...omitted) : null;
}

function servedPanelOnFailure(
  preview: SupportedAgentCardPreview,
  lastServed: ServedCardSnapshot | null
): RawCardPanel {
  const { after, after_bytes: afterBytes, display_limit_bytes: limit } = preview;
  if (after !== null) {
    const reason =
      preview.fetch.status === 'not_served'
        ? 'the gateway refused to serve the card it fetched'
        : 'the latest fetch failed';
    return {
      card: after,
      note: `The card the gateway last served for this surface, before ${reason}. Callers do not get it until this is fixed.`,
    };
  }
  if (afterBytes !== null && afterBytes > limit) {
    return {
      card: null,
      missing: `The card the gateway last served is ${kb(afterBytes)} KB, more than the ${kb(limit)} KB the dashboard shows. Open the card URL to read it.`,
    };
  }
  if (lastServed) {
    const fetched = formatRelativeTime(lastServed.fetchedAt);
    return {
      card: lastServed.card,
      note: fetched
        ? `The last card the gateway served, fetched ${fetched}.`
        : 'The last card the gateway served.',
    };
  }
  return { card: null, missing: 'The gateway serves no card while the fetch fails.' };
}

function failedCardPanels(
  preview: SupportedAgentCardPreview,
  lastServed: ServedCardSnapshot | null
): { managed: RawCardPanel; served: RawCardPanel } {
  const failure = describeFetchFailure(preview.fetch);
  return {
    managed: {
      card: preview.before,
      missing: failure ? `Not available: ${failure}.` : 'Not available.',
    },
    served: servedPanelOnFailure(preview, lastServed),
  };
}

const FailedFetch: React.FC<{
  preview: SupportedAgentCardPreview;
  lastServed: ServedCardSnapshot | null;
}> = ({ preview, lastServed }) => {
  const panels = failedCardPanels(preview, lastServed);
  return (
    <>
      <Notice testId="agent-card-failed" variant="danger" role="alert">
        <strong className="d-block">
          {preview.fetch.status === 'not_served'
            ? "The gateway fetched the agent's card but will not serve it."
            : "The gateway could not fetch the agent's card. Callers get no card until this is fixed."}
        </strong>
        <span data-testid="agent-card-failed-cause">
          {describeFetchCause(preview.fetch, preview.auth)}
        </span>
      </Notice>
      <AgentCardRawJson managed={panels.managed} served={panels.served} defaultOpen />
    </>
  );
};

function refreshAnnouncement(preview: AgentCardPreview): string {
  if (!preview.supported || preview.generated) return 'Card refreshed.';
  if (preview.fetch.status === 'ok') return 'Card refreshed. The card fetch is OK.';
  if (preview.fetch.status === 'not_served') {
    return 'Card refreshed. The gateway will not serve the card.';
  }
  return 'Card refreshed. The card fetch is failing.';
}

const AgentCardTab: React.FC<AgentCardTabProps> = ({
  surfaceId,
  isCreate,
  isDirty,
  canEdit,
  hasVariants,
  refreshKey,
  onRefreshed,
}) => {
  const meta = useOptionalSurfaceMeta();
  const { state, refresh, reload, refreshing, lastServed } = useAgentCardPreview(
    isCreate ? undefined : surfaceId,
    refreshKey
  );
  const headingRef = React.useRef<HTMLHeadingElement>(null);
  const [announcement, setAnnouncement] = React.useState('');

  const handleRetry = () => {
    reload();
    headingRef.current?.focus();
  };

  const handleRefresh = async () => {
    setAnnouncement('');
    const result: PreviewRefreshResult = await refresh();
    if (result.kind === 'stale') return;
    if (result.kind === 'ok') {
      setAnnouncement(refreshAnnouncement(result.preview));
      onRefreshed?.();
    } else if (result.kind === 'rate_limited') {
      showToast('warning', 'Too many card refreshes. Try again in a minute.');
    } else if (result.kind === 'forbidden') {
      showToast('error', 'You need permission to edit surfaces to refresh the card.');
    } else if (result.kind === 'error') {
      showToast('error', 'Could not refresh the agent card.');
    }
  };

  const renderReady = (preview: SupportedAgentCardPreview): React.ReactNode => {
    const ok = preview.fetch.status === 'ok';
    const oversize = oversizeBytes(preview);
    const comparable = preview.after !== null && (preview.generated || preview.before !== null);
    const managedCard = preview.generated ? null : preview.before;
    return (
      <>
        <AgentCardHeader
          preview={preview}
          canEdit={canEdit}
          refreshing={refreshing}
          onRefresh={handleRefresh}
        />
        {preview.payment_required && (
          <Notice testId="agent-card-payment">Callers pay before they get this card.</Notice>
        )}
        {hasVariants && (
          <Notice testId="agent-card-variant-note">
            This shows the base route. A Surface Variant may serve a different card.
          </Notice>
        )}
        {!ok && <FailedFetch preview={preview} lastServed={lastServed} />}
        {ok && oversize !== null && (
          <Notice testId="agent-card-too-large" variant="warning">
            This card is {kb(oversize)} KB, more than the {kb(preview.display_limit_bytes)} KB the
            dashboard shows. Open the card URL to read it.
          </Notice>
        )}
        {ok && preview.generated && (
          <Notice testId="agent-card-generated">
            The gateway generates this card for an A2A proxy, so there is no agent card to compare.
          </Notice>
        )}
        {ok && oversize === null && !comparable && <StatusUnavailable onRetry={handleRetry} />}
        {ok && comparable && preview.after !== null && (
          <>
            <AgentCardCompare
              before={managedCard}
              after={preview.after}
              generated={preview.generated}
            />
            <AgentCardRawJson
              managed={preview.generated ? null : { card: managedCard }}
              served={{ card: preview.after }}
            />
          </>
        )}
      </>
    );
  };

  const renderBody = (): React.ReactNode => {
    if (isCreate || !surfaceId) {
      return (
        <Notice testId="agent-card-unsaved" variant="secondary">
          Save the surface to see its agent cards.
        </Notice>
      );
    }
    if (state.status === 'idle' || state.status === 'loading') {
      return (
        <div className="text-muted" role="status" data-testid="agent-card-loading">
          <span className="spinner-border spinner-border-sm me-2" aria-hidden="true" />
          Fetching the agent cards…
        </div>
      );
    }
    if (state.status === 'unavailable') {
      return <StatusUnavailable onRetry={handleRetry} />;
    }
    const { preview } = state;
    if (!preview.supported) {
      return (
        <Notice testId="agent-card-unsupported" variant="secondary" role="status">
          {preview.unsupported_reason === 'not_a2a'
            ? 'Only A2A and AP2 surfaces have agent cards.'
            : 'This surface is not running on this gateway, so its card cannot be fetched. Check that it is active.'}
        </Notice>
      );
    }
    return renderReady(preview);
  };

  return (
    <div className="card shadow-sm mb-0 agent-card-tab" data-testid="agent-card-tab">
      <div className="card-header">
        <h6
          className="m-0 font-weight-bold text-primary"
          tabIndex={-1}
          ref={headingRef}
          data-testid="agent-card-heading"
        >
          <i className="fas fa-id-card me-2" aria-hidden="true" /> Agent Cards
        </h6>
      </div>
      <div className="card-body">
        <div className="visually-hidden" role="status" data-testid="agent-card-refresh-status">
          {announcement}
        </div>
        {meta?.onOpenSurfaceView && <SurfaceLink onOpen={meta.onOpenSurfaceView} />}
        {!isCreate && isDirty && (
          <Notice testId="agent-card-unsaved-changes" variant="info" role="status">
            You have unsaved changes. The cards show the saved surface.
          </Notice>
        )}
        {renderBody()}
      </div>
    </div>
  );
};

export default AgentCardTab;
