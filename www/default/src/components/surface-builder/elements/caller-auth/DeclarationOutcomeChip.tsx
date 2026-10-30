import React from 'react';
import {
  useSurfaceDeclarations,
  type SurfaceDeclarationsState,
} from '../../../../hooks/useSurfaceDeclarations';
import {
  cardCarriesScheme,
  describeDeclaration,
  type SurfaceDeclaration,
} from '../../../../utils/surfaceDeclarations';
import { Badge } from '../../../shared/Badge';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import type { Protocol } from '../types';
import { declarationForVariant } from './protectedResource';

type OutcomeTone = 'secondary' | 'success' | 'warning' | 'danger';

interface Described {
  label: string;
  detail: string | null;
  tone: OutcomeTone;
  icon: string;
}

const NEUTRAL: Pick<Described, 'tone' | 'icon'> = { tone: 'secondary', icon: 'fa-circle-info' };

function describeOutcome(
  d: SurfaceDeclaration,
  protocol: Protocol | undefined,
  cardScheme: boolean
): Described {
  const described = describeDeclaration(d, protocol, cardScheme);
  if (d.outcome === 'unservable') {
    return { ...described, tone: 'danger', icon: 'fa-circle-xmark' };
  }
  if (d.outcome === 'declare') {
    return { ...described, tone: 'success', icon: 'fa-shield-halved' };
  }
  if (d.outcome === 'strip') {
    return { ...described, tone: 'warning', icon: 'fa-triangle-exclamation' };
  }
  return { ...described, ...NEUTRAL };
}

export interface DeclarationOutcomeViewProps {
  state: SurfaceDeclarationsState;
  surfaceId?: string;
  protocol?: Protocol;
}

/** The declaration outcome of the route being edited, from a declarations read. */
export const DeclarationOutcomeView: React.FC<DeclarationOutcomeViewProps> = ({
  state,
  surfaceId,
  protocol,
}) => {
  const meta = useOptionalSurfaceMeta();
  const shownProtocol = protocol ?? meta?.protocol;
  const servesCard = shownProtocol !== 'mcp';
  const noun = servesCard ? 'Agent card' : 'Protected resource metadata';
  const onOpenAgentCard =
    servesCard && shownProtocol !== 'didcomm' ? meta?.onOpenAgentCard : undefined;

  let described: Described = {
    label: 'Outcome shown after the first save',
    detail: null,
    ...NEUTRAL,
  };
  if (state.status === 'loading') {
    described = { ...described, label: `Checking the ${noun.toLowerCase()} outcome…` };
  } else if (state.status === 'unavailable') {
    described = { ...described, label: `${noun} outcome unavailable` };
  } else if (state.status === 'ready') {
    const entry = declarationForVariant(state.declarations, meta?.activeVariantAlias);
    described = entry
      ? describeOutcome(entry, shownProtocol, cardCarriesScheme(state.warnings, entry.variant))
      : { ...described, label: `${noun} outcome unavailable` };
  }

  return (
    <div className="mb-3" data-testid="caller-auth-outcome" aria-live="polite">
      <span className="fw-bold me-2">{noun}:</span>
      <Badge
        tone={described.tone}
        className="caller-auth-outcome-chip"
        data-testid="caller-auth-outcome-chip"
        prefix={
          <i
            className={`fas ${described.icon}`}
            aria-hidden="true"
            data-testid="caller-auth-outcome-icon"
          />
        }
        value={described.label}
      />
      {surfaceId && onOpenAgentCard && (
        <button
          type="button"
          className="btn btn-link btn-sm p-0 ms-2 align-baseline"
          onClick={onOpenAgentCard}
          data-testid="caller-auth-outcome-card-link"
        >
          See the card
        </button>
      )}
      {described.detail && (
        <small className="form-text text-muted d-block" data-testid="caller-auth-outcome-detail">
          {described.detail} This reflects the saved surface.
        </small>
      )}
    </div>
  );
};

interface DeclarationOutcomeChipProps {
  surfaceId?: string;
  refreshKey?: unknown;
  protocol?: Protocol;
}

const DeclarationOutcomeChip: React.FC<DeclarationOutcomeChipProps> = ({
  surfaceId,
  refreshKey,
  protocol,
}) => {
  const meta = useOptionalSurfaceMeta();
  const state = useSurfaceDeclarations(surfaceId, refreshKey ?? meta?.agentCardRevision);
  return <DeclarationOutcomeView state={state} surfaceId={surfaceId} protocol={protocol} />;
};

export default DeclarationOutcomeChip;
