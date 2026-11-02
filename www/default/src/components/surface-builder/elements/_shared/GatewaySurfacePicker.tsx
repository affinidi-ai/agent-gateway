import React from 'react';
import { Form } from 'react-bootstrap';
import AddResourceLink from '../../../shared/AddResourceLink';
import FieldHelp from '../../../shared/FieldHelp';
import { deepLinks } from '../../../../utils/deepLinks';
import type { GatewaySurfacesState, RemoteSurface } from './useGatewaySurfaces';

interface GatewaySurfacePickerProps {
  /** Prefix of every test id and element id, e.g. `transit-point`. */
  testIdPrefix: string;
  state: GatewaySurfacesState;
  gatewayId: string;
  surfaceId: string;
  /** The surfaces offered, after the caller's filter. */
  surfaces: RemoteSurface[];
  onGatewayChange: (gatewayId: string) => void;
  onSurfaceChange: (surfaceId: string) => void;
  gatewayLabel: string;
  gatewayPlaceholder: string;
  gatewayHelp: React.ReactNode;
  noGatewayTitle: string;
  noGatewayText: string;
  /** Where the Add link opens, in a new tab; defaults to the Connect Gateway wizard. */
  addGatewayLink?: string;
  addGatewayLabel?: string;
  /** Shown for a saved gateway that is not in the list. */
  savedGatewayName?: string;
  surfaceLabel: string;
  surfacePlaceholder: string;
  surfaceHelp: React.ReactNode;
  /** Shown when the gateway lists no surfaces at all. */
  emptySurfacesText: string;
  /** Shown when the gateway lists surfaces but the filter keeps none. */
  hiddenSurfacesText?: string;
  /** Option label for a saved surface id that is not in the list. */
  savedSurfaceLabel?: (surfaceId: string) => string;
}

const HINT_STYLE = { fontSize: '10px' } as const;

export function surfaceOptionLabel(surface: RemoteSurface): string {
  if (!surface.name || surface.name === surface.config_id) return surface.config_id;
  const id = surface.config_id;
  return `${surface.name} (${id.length > 8 ? `${id.slice(0, 8)}…` : id})`;
}

/** Gateway, then surface on that gateway: the picker behind every `fabric://` route and agent-pay. */
const GatewaySurfacePicker: React.FC<GatewaySurfacePickerProps> = ({
  testIdPrefix,
  state,
  gatewayId,
  surfaceId,
  surfaces,
  onGatewayChange,
  onSurfaceChange,
  gatewayLabel,
  gatewayPlaceholder,
  gatewayHelp,
  noGatewayTitle,
  noGatewayText,
  addGatewayLink = deepLinks.remoteGateway,
  addGatewayLabel = 'Add Gateway',
  savedGatewayName,
  surfaceLabel,
  surfacePlaceholder,
  surfaceHelp,
  emptySurfacesText,
  hiddenSurfacesText,
  savedSurfaceLabel,
}) => {
  const gatewaySelectId = `${testIdPrefix}-gateway-select`;
  const surfaceSelectId = `${testIdPrefix}-surface-select`;
  const noGateways = !state.gatewaysLoading && !state.gatewaysError && state.gateways.length === 0;
  const gatewayListed = state.gateways.some(g => g.id === gatewayId);
  const surfaceListed = surfaces.some(s => s.config_id === surfaceId);

  return (
    <>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label htmlFor={gatewaySelectId} className="small text-muted mb-0">
            {gatewayLabel}
          </Form.Label>
          <FieldHelp
            testId={`field-help-${testIdPrefix}-gateway`}
            ariaLabel={`About ${gatewayLabel}`}
          >
            {gatewayHelp}
          </FieldHelp>
        </div>
        {noGateways && !gatewayId ? (
          <div
            className="surface-info-panel surface-info-panel--warning"
            data-testid={`${testIdPrefix}-no-gateway`}
          >
            <div className="surface-info-panel-title">
              <i className="fas fa-plug me-1" aria-hidden="true" />
              {noGatewayTitle}
            </div>
            <div className="surface-info-panel-summary">{noGatewayText}</div>
            <AddResourceLink
              to={addGatewayLink}
              testid={`${testIdPrefix}-add-gateway-link`}
              className="btn btn-outline-primary btn-sm w-100 mt-2"
            >
              <i className="fas fa-link me-1" aria-hidden="true" /> {addGatewayLabel}
            </AddResourceLink>
          </div>
        ) : (
          <>
            <Form.Select
              id={gatewaySelectId}
              size="sm"
              data-testid={gatewaySelectId}
              value={gatewayId}
              disabled={state.gatewaysLoading}
              onChange={e => onGatewayChange(e.target.value)}
            >
              <option value="">{state.gatewaysLoading ? 'Loading…' : gatewayPlaceholder}</option>
              {gatewayId && !gatewayListed && !state.gatewaysLoading && (
                <option value={gatewayId}>
                  {savedGatewayName || gatewayId} (not currently connected)
                </option>
              )}
              {state.gateways.map(gw => (
                <option key={gw.id} value={gw.id}>
                  {gw.name || gw.id}
                </option>
              ))}
            </Form.Select>
            {state.gatewaysError ? (
              <Form.Text
                className="text-danger d-block"
                style={HINT_STYLE}
                role="alert"
                data-testid={`${testIdPrefix}-gateway-error`}
              >
                <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
                {state.gatewaysError}{' '}
                <button
                  type="button"
                  className="btn btn-link btn-sm p-0 align-baseline"
                  style={HINT_STYLE}
                  onClick={state.reloadGateways}
                  data-testid={`${testIdPrefix}-gateway-retry-button`}
                >
                  Retry
                </button>
              </Form.Text>
            ) : (
              !state.gatewaysLoading && (
                <Form.Text className="text-muted d-block" style={HINT_STYLE}>
                  {noGateways ? `${noGatewayTitle}. ` : "Don't see the one you need? "}
                  <AddResourceLink to={addGatewayLink} testid={`${testIdPrefix}-add-gateway-link`}>
                    {addGatewayLabel}
                  </AddResourceLink>
                </Form.Text>
              )
            )}
          </>
        )}
      </Form.Group>

      {gatewayId && (
        <Form.Group className="mb-2">
          <div className="d-flex justify-content-between align-items-center mb-1">
            <div className="d-flex align-items-center gap-1">
              <Form.Label htmlFor={surfaceSelectId} className="small text-muted mb-0">
                {surfaceLabel}
              </Form.Label>
              <FieldHelp
                testId={`field-help-${testIdPrefix}-surface`}
                ariaLabel={`About ${surfaceLabel}`}
              >
                {surfaceHelp}
              </FieldHelp>
            </div>
            <button
              type="button"
              className="btn btn-link btn-sm p-0"
              style={HINT_STYLE}
              onClick={state.refreshSurfaces}
              disabled={state.surfacesLoading}
              data-testid={`${testIdPrefix}-surface-refresh-button`}
            >
              <i
                className={`fas fa-rotate me-1${state.surfacesLoading ? ' fa-spin' : ''}`}
                aria-hidden="true"
              />
              {state.surfacesLoading ? 'Loading…' : 'Refresh'}
            </button>
          </div>
          <Form.Select
            id={surfaceSelectId}
            size="sm"
            data-testid={surfaceSelectId}
            value={surfaceId}
            disabled={state.surfacesLoading || (surfaces.length === 0 && !surfaceId)}
            onChange={e => onSurfaceChange(e.target.value)}
          >
            <option value="">{state.surfacesLoading ? 'Loading…' : surfacePlaceholder}</option>
            {surfaceId && !surfaceListed && !state.surfacesLoading && (
              <option value={surfaceId}>
                {savedSurfaceLabel?.(surfaceId) ?? `${surfaceId} (not currently exposed)`}
              </option>
            )}
            {surfaces.map(s => (
              <option key={s.config_id} value={s.config_id}>
                {surfaceOptionLabel(s)}
              </option>
            ))}
          </Form.Select>
          {state.surfacesError ? (
            <Form.Text
              className="text-danger d-block"
              style={HINT_STYLE}
              role="alert"
              data-testid={`${testIdPrefix}-surface-error`}
            >
              <i className="fas fa-triangle-exclamation me-1" aria-hidden="true" />
              {state.surfacesError}
            </Form.Text>
          ) : (
            !state.surfacesLoading &&
            surfaces.length === 0 && (
              <Form.Text
                className="text-muted d-block"
                style={HINT_STYLE}
                data-testid={`${testIdPrefix}-surface-empty`}
              >
                {state.surfaces.length > 0 && hiddenSurfacesText
                  ? hiddenSurfacesText
                  : emptySurfacesText}
              </Form.Text>
            )
          )}
        </Form.Group>
      )}
    </>
  );
};

export default GatewaySurfacePicker;
