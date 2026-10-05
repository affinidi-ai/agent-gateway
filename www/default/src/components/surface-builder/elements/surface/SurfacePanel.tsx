import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import InfoBanner from '../../../shared/InfoBanner';
import type { ConfigPanelProps } from '../types';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import { SURFACE_PROTOCOL_OPTIONS, getProtocolLabel } from '../../protocols';
import { formatDateTime, timeAgo } from '../../../../utils/stringUtils';
import { getIssuers } from '../../../../utils/issuersCache';
import type { Issuer } from '../../../../types';
import FieldHelp from '../../../shared/FieldHelp';

/**
 * Right-panel editor for the Surface element. Pulls its values from
 * `SurfaceMetaContext` rather than the node's `config` because the surface
 * meta lives at the page level (not in the canvas-node payload).
 */
const SurfacePanel: React.FC<ConfigPanelProps> = ({ hasAttemptedSave }) => {
  const meta = useOptionalSurfaceMeta();

  const [issuers, setIssuers] = useState<Issuer[]>([]);
  useEffect(() => {
    let alive = true;
    getIssuers()
      .then(data => {
        if (alive) setIssuers(data);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  if (!meta) {
    return <div className="text-muted small">Surface metadata is unavailable in this context.</div>;
  }

  const {
    name,
    description,
    tagsCsv,
    status,
    protocol,
    publishToDid,
    terminateTraceId,
    issuerId,
    didwebvh,
    readOnly,
    protocolLocked,
    isCreate,
    lastActivity,
    surfaceId,
    setName,
    setDescription,
    setTagsCsv,
    setStatus,
    setProtocol,
    setPublishToDid,
    setTerminateTraceId,
    setIssuerId,
    setDidwebvh,
    onSaveAsTemplate,
  } = meta;

  const disabled = readOnly;
  const protocolDisabled = disabled || protocolLocked;

  return (
    <>
      <div className="config-section">
        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">
            Name <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            id="surface-name"
            size="sm"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            disabled={disabled}
            isInvalid={!!hasAttemptedSave && !disabled && !name.trim()}
          />
          {!!hasAttemptedSave && !disabled && !name.trim() && (
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              Surface name is required.
            </Form.Control.Feedback>
          )}
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Description</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={description}
            onChange={e => setDescription(e.target.value)}
            disabled={disabled}
            placeholder="Optional description"
          />
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Tags</Form.Label>
          <Form.Control
            size="sm"
            type="text"
            value={tagsCsv}
            onChange={e => setTagsCsv(e.target.value)}
            disabled={disabled}
            placeholder="comma, separated, tags"
          />
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label className="small text-muted mb-1">Issuer</Form.Label>
          {issuers.length > 0 ? (
            <Form.Select
              size="sm"
              value={issuerId}
              onChange={e => setIssuerId(e.target.value)}
              disabled={disabled}
            >
              <option value="">-- Unassigned --</option>
              {issuers.map(d => (
                <option key={d.id} value={d.id}>
                  {d.name || d.id}
                  {d.description ? ` — ${d.description}` : ''}
                </option>
              ))}
              {issuerId && !issuers.some(d => d.id === issuerId) && (
                <option value={issuerId}>{issuerId} (not in list)</option>
              )}
            </Form.Select>
          ) : (
            <Form.Control
              size="sm"
              type="text"
              value={issuerId}
              onChange={e => setIssuerId(e.target.value)}
              disabled={disabled}
              placeholder="Issuer ID (optional)"
            />
          )}
          <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
            Owning issuer. Drives Trust Check / Trust Recorder authority defaults.
          </Form.Text>
        </Form.Group>
      </div>

      <div className="config-section">
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1 d-block">
            Protocol <span className="text-danger">*</span>
            {protocolLocked && (
              <span className="badge text-bg-primary ms-2">{getProtocolLabel(protocol)}</span>
            )}
          </Form.Label>
          <Form.Select
            size="sm"
            value={protocol}
            onChange={e => setProtocol(e.target.value as typeof protocol)}
            disabled={protocolDisabled}
          >
            {SURFACE_PROTOCOL_OPTIONS.map(p => (
              <option key={p} value={p}>
                {getProtocolLabel(p)}
              </option>
            ))}
          </Form.Select>
          <small className="form-text text-muted">
            {protocolLocked ? (
              <>
                <i className="fas fa-lock me-1" />
                Protocol locks once the surface contains configured elements.
              </>
            ) : (
              <>Choose the protocol for this surface. Locks when you start adding elements.</>
            )}
          </small>
        </Form.Group>
      </div>

      <div className="config-section">
        <div className="form-check">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-enabled"
            checked={status !== 'disabled'}
            onChange={e => setStatus(e.target.checked ? 'active' : 'disabled')}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-enabled">
            <strong>Surface enabled</strong>
            {status === 'disabled' && (
              <span className="badge text-bg-warning ms-2">
                <i className="fas fa-power-off" /> DISABLED
              </span>
            )}
          </label>
        </div>
        <div className="form-check mt-2">
          <input
            type="checkbox"
            className="form-check-input"
            id="surface-publish-did"
            checked={publishToDid}
            onChange={e => setPublishToDid(e.target.checked)}
            disabled={disabled}
          />
          <label className="form-check-label small" htmlFor="surface-publish-did">
            <strong>Publish to Gateway DID document</strong>
            {publishToDid && (
              <span className="badge text-bg-info ms-2">
                <i className="fas fa-globe" /> PUBLISHED
              </span>
            )}
          </label>
        </div>
        <Form.Text className="text-muted d-block mt-1" style={{ fontSize: '10px' }}>
          Makes this surface&apos;s endpoint publicly discoverable: adds it as a service entry in
          this gateway&apos;s DID document (<code>/.well-known/did.json</code>), visible to anyone
          who resolves the gateway&apos;s DID. Leave this off if this surface should only be
          reachable by callers who already have its address.
        </Form.Text>
      </div>

      <div className="config-section">
        <label>Gateway DID Injection</label>
        <Form.Text className="text-muted d-block mb-1" style={{ fontSize: '10px' }}>
          Stamps every outbound request from this surface with a verifiable did:webvh identity for
          this gateway.
        </Form.Text>
        <InfoBanner
          className="mb-2"
          title="What is did:webvh, and why would I turn this on?"
          summary={
            <>
              <p>
                A DID (decentralized identifier) is a unique, verifiable ID string. did:webvh works
                like a verifiable, web-hosted ID card for your gateway.
              </p>
              <p>
                When this is on, every outbound request that passes through this surface gets
                stamped with it, so the receiving system can confirm the request really did travel
                your gateway's declared route.
              </p>
            </>
          }
        />
        <Form.Check
          type="switch"
          id="surface-didwebvh-enabled"
          label="Enable Gateway DID injection (did:webvh)"
          checked={didwebvh.enabled}
          disabled={disabled}
          onChange={e => setDidwebvh({ ...didwebvh, enabled: e.target.checked })}
        />
        {didwebvh.enabled && (
          <>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Identity ID (optional)</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="existing identity UUID"
                value={didwebvh.identity_id}
                disabled={disabled}
                onChange={e => setDidwebvh({ ...didwebvh, identity_id: e.target.value })}
              />
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Bind to an existing managed identity. Leave blank to create a new one.
              </Form.Text>
            </Form.Group>
            <Form.Check
              type="switch"
              id="surface-didwebvh-autocreate"
              className="mt-2"
              label="Auto-create identity if it does not exist"
              checked={didwebvh.auto_create}
              disabled={disabled}
              onChange={e => setDidwebvh({ ...didwebvh, auto_create: e.target.checked })}
            />
            <Form.Group className="mt-2">
              <div className="d-flex align-items-center gap-1 mb-1">
                <Form.Label className="small text-muted mb-0">DID Path (optional)</Form.Label>
                <FieldHelp testId="field-help-surface-did-path" ariaLabel="About DID Path">
                  Sets the last segment of this surface's decentralized identifier (DID), a unique,
                  verifiable ID string that other systems use to look up and confirm your gateway's
                  identity. Leave blank to use the surface's name automatically.
                </FieldHelp>
              </div>
              <Form.Control
                size="sm"
                type="text"
                placeholder="custom-path-segment"
                value={didwebvh.did_path}
                disabled={disabled}
                onChange={e => setDidwebvh({ ...didwebvh, did_path: e.target.value })}
              />
            </Form.Group>
            <Form.Group className="mt-2">
              <Form.Label className="small text-muted mb-1">Injection Mode</Form.Label>
              <Form.Select
                size="sm"
                value={didwebvh.injection_mode}
                disabled={disabled}
                onChange={e =>
                  setDidwebvh({
                    ...didwebvh,
                    injection_mode: e.target.value as typeof didwebvh.injection_mode,
                  })
                }
              >
                <option value="header">Header (X-DID-Identity)</option>
                <option value="signed_header">Signed Header (X-DID-Signed-Identity)</option>
                <option value="protocol_native">Protocol Native (A2A ext / MCP _meta)</option>
              </Form.Select>
              <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
                Choose how the DID identity gets attached to outbound requests. Header: a plain,
                unsigned HTTP header. Signed Header: the same header, but cryptographically signed
                so it can&apos;t be tampered with. Protocol Native: embedded using the
                protocol&apos;s own extension mechanism instead of a header, for receivers that
                specifically expect it there.
              </Form.Text>
            </Form.Group>
          </>
        )}
      </div>

      <div className="config-section">
        <label>Trace ID Termination</label>
        <InfoBanner
          className="mb-2"
          collapsible={false}
          summary={
            <>
              By default this surface <strong>forwards</strong> the request&rsquo;s trace id to the
              next hop (via <code>X-Gateway-Trace-Id</code>, a transit token, or a fabric message),
              so a caller &rarr; gateway &rarr; gateway chain shares one trace across metrics,
              audit, the &ldquo;This request&rdquo; filter, and every injected VP&rsquo;s{' '}
              <code>traceId</code>. Enable termination to keep the incoming trace for{' '}
              <strong>this</strong> surface&rsquo;s own VP &amp; audit (so the
              caller&rarr;&hellip;&rarr;here past stays traceable) while forwarding a{' '}
              <strong>fresh</strong> trace id downstream: an egress firewall, so the trace never
              crosses to the next gateway or agent.
            </>
          }
        />
        <Form.Check
          type="switch"
          id="surface-terminate-trace-id"
          label="Terminate trace at egress (keep own trace, forward a fresh one downstream)"
          checked={terminateTraceId}
          disabled={disabled}
          onChange={e => setTerminateTraceId(e.target.checked)}
        />
      </div>

      {!isCreate && (
        <div className="config-section">
          {surfaceId && (
            <div className="mb-2">
              <Form.Label className="small text-muted mb-1">Surface ID</Form.Label>
              <Form.Control size="sm" type="text" value={surfaceId} readOnly disabled />
            </div>
          )}
          <div className="small">
            <i className="fas fa-clock text-muted me-2" />
            <strong>Last Activity:</strong>{' '}
            {lastActivity ? (
              <span>
                {timeAgo(lastActivity)}
                <span className="text-muted"> — {formatDateTime(lastActivity, true)}</span>
              </span>
            ) : (
              <span className="text-muted">No activity recorded</span>
            )}
          </div>
        </div>
      )}

      {onSaveAsTemplate && !disabled && (
        <div className="config-section">
          <button
            type="button"
            className="btn btn-outline-primary btn-sm w-100"
            onClick={onSaveAsTemplate}
            title="Snapshot the current surface as a reusable template"
          >
            <i className="fas fa-bookmark me-1" /> Save Surface as Template…
          </button>
        </div>
      )}
    </>
  );
};

export default SurfacePanel;
