import React, { useEffect, useRef, useState } from 'react';
import { Button } from 'react-bootstrap';
import { useApp } from '../../../context/AppContext';
import { usePermissions } from '../../../context/PermissionsContext';
import FieldHelp from '../../shared/FieldHelp';
import { useOptionalSurfaceMeta } from '../SurfaceMetaContext';

/**
 * Starts and stops listening to the surface's policy input on the dashboard WebSocket.
 * Listening lasts while this view stays open: leaving it, or reloading the page, stops it.
 */
const PolicyInputCaptureControl: React.FC = () => {
  const meta = useOptionalSurfaceMeta();
  const { hasPermission } = usePermissions();
  const { actions } = useApp();
  const [listening, setListening] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const surfaceId = meta?.surfaceId;
  const listenRef = useRef(actions.listenToPolicyInput);
  listenRef.current = actions.listenToPolicyInput;

  useEffect(() => {
    if (!surfaceId) return;
    const handler = (event: Event) => {
      const data = (event as CustomEvent).detail;
      if (!data || data.type !== 'policy_input_capture' || data.surface_id !== surfaceId) return;
      setListening(data.listening === true);
      setError(data.error ? `Could not listen to policy input: ${data.error}` : null);
    };
    window.addEventListener('ws-message', handler);
    return () => window.removeEventListener('ws-message', handler);
  }, [surfaceId]);

  useEffect(() => {
    if (!surfaceId || !listening) return;
    const listen = listenRef.current;
    return () => listen(surfaceId, false);
  }, [surfaceId, listening]);

  if (!meta || meta.isCreate || !surfaceId) return null;

  const allowed = hasPermission('surfaces.edit') && hasPermission('policies.edit');

  const toggle = () => {
    setError(null);
    const next = !listening;
    setListening(next);
    listenRef.current(surfaceId, next);
  };

  return (
    <div className="d-flex align-items-center flex-wrap gap-2" data-testid="policy-input-capture">
      <Button
        size="sm"
        variant={listening ? 'outline-danger' : 'outline-primary'}
        data-testid="policy-input-capture-listen"
        disabled={!allowed}
        onClick={toggle}
      >
        {listening ? (
          <>
            <i className="fas fa-stop"></i> Stop listening
          </>
        ) : (
          <>
            <i className="fas fa-play"></i> Listen to policy input
          </>
        )}
      </Button>
      <FieldHelp
        testId="field-help-policy-input-capture"
        ariaLabel="About listening to policy input"
      >
        While you listen, the input and the decision of every policy evaluation on this surface
        here, live. The input holds request data (messages, tool arguments, claims) with credentials
        masked. Only you receive it, and nothing is logged or stored. Listening stops when you stop
        it, leave this view or reload the page. A surface with no policy has nothing to capture, so
        add one first; one that allows everything is enough. Use it only to develop and test
        policies.
      </FieldHelp>
      {listening && (
        <span className="text-muted small" data-testid="policy-input-capture-listening">
          <span className="spinner-grow spinner-grow-sm text-success me-1" role="status" />
          Listening
        </span>
      )}
      {!allowed && (
        <span className="text-muted small" data-testid="policy-input-capture-not-allowed">
          Needs permission to edit surfaces and policies
        </span>
      )}
      {error && (
        <span className="text-danger small" role="alert" data-testid="policy-input-capture-error">
          {error}
        </span>
      )}
    </div>
  );
};

export default PolicyInputCaptureControl;
