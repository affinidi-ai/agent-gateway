import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import { apiClient } from '../../../api';
import { usePermissions } from '../../../context/PermissionsContext';
import FieldHelp from '../../shared/FieldHelp';
import { useOptionalSurfaceMeta } from '../SurfaceMetaContext';

/** How long switching capture on from the dashboard keeps it on. */
export const POLICY_INPUT_CAPTURE_MINUTES = 30;

interface PolicyInputCaptureControlProps {
  /** The stored surface's `policy_input_capture_until`; absent or `null` while off. */
  initialUntil?: string | null;
  /** Called with the new end time, or `null`, after switching capture on or off. */
  onChange?: (until: string | null) => void;
}

function activeUntil(until: string | null | undefined): string | null {
  if (!until) return null;
  const end = Date.parse(until);
  return Number.isFinite(end) && end > Date.now() ? until : null;
}

function formatUntil(until: string): string {
  return new Date(until).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

const PolicyInputCaptureControl: React.FC<PolicyInputCaptureControlProps> = ({
  initialUntil,
  onChange,
}) => {
  const meta = useOptionalSurfaceMeta();
  const { hasPermission } = usePermissions();
  const [until, setUntil] = useState<string | null>(() => activeUntil(initialUntil));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setUntil(activeUntil(initialUntil));
  }, [initialUntil]);

  useEffect(() => {
    if (!until) return;
    const timer = setTimeout(() => setUntil(null), Math.max(0, Date.parse(until) - Date.now()));
    return () => clearTimeout(timer);
  }, [until]);

  const surfaceId = meta?.surfaceId;
  if (!meta || meta.isCreate || !surfaceId) return null;

  const allowed = hasPermission('surfaces.edit') && hasPermission('policies.edit');
  const disabled = meta.readOnly || !allowed || busy;
  const on = until !== null;

  const toggle = async (next: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const result = next
        ? await apiClient.setSurfacePolicyInputCapture(surfaceId, POLICY_INPUT_CAPTURE_MINUTES)
        : await apiClient.clearSurfacePolicyInputCapture(surfaceId);
      setUntil(activeUntil(result.policy_input_capture_until));
      onChange?.(result.policy_input_capture_until);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      setError(
        next
          ? `Could not turn on policy input capture: ${reason}`
          : `Could not turn off policy input capture: ${reason}`
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="d-flex align-items-center flex-wrap gap-2" data-testid="policy-input-capture">
      <Form.Check
        type="switch"
        id="policy-input-capture-switch"
        data-testid="policy-input-capture-switch"
        label="Capture policy input"
        className="small mb-0"
        checked={on}
        disabled={disabled}
        onChange={e => toggle(e.target.checked)}
      />
      <FieldHelp testId="field-help-policy-input-capture" ariaLabel="About Capture policy input">
        Shows the input and the decision of every policy evaluation on this surface in this Capture
        view. The input holds request data (messages, tool arguments, claims) with credentials
        masked. Only users who may edit surfaces and policies receive it, and nothing is logged or
        stored. Use it only to develop and test policies. It stops by itself after{' '}
        {POLICY_INPUT_CAPTURE_MINUTES} minutes.
      </FieldHelp>
      {on && until ? (
        <span className="text-muted small" data-testid="policy-input-capture-until">
          On until {formatUntil(until)}
        </span>
      ) : (
        <span className="text-muted small" data-testid="policy-input-capture-duration">
          for {POLICY_INPUT_CAPTURE_MINUTES} minutes
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
