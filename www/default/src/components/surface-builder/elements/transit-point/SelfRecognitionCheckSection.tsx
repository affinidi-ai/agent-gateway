import React from 'react';
import { Form } from 'react-bootstrap';
import type { CanvasNode } from '../../SurfaceCanvas';
import FieldHelp from '../../../shared/FieldHelp';
import { identityConfigToWire } from '../identity/definition';
import { readEntries } from '../trust-recorder/definition';

export const SELF_RECOGNITION_NEEDS_RECORDER =
  'Needs a Trust Recorder that records the owned agent on this surface.';
export const SELF_RECOGNITION_NEEDS_IDENTITY =
  'Needs an Identity on this Transit Point, so the gateway knows which agent to check.';

/**
 * Why the Transit Point `transitPointId` cannot run a self recognition check, or `null` when it
 * can: the surface needs a Trust Recorder entry that records the owned agent, and the Transit
 * Point a managed agent identity: an Identity of its own that is not inbound-only, or, without
 * one, the surface's through a stored `identity_injection.inject_vp`.
 */
export function selfRecognitionCheckBlocker(
  transitPointId: string | undefined,
  transitPointConfig: Record<string, any> | undefined,
  allNodes: CanvasNode[] | undefined
): string | null {
  const nodes = allNodes ?? [];
  const recordsOwnedAgent = nodes.some(
    node =>
      node.type === 'trust-recorder' &&
      readEntries(node.config).some(entry => entry.include_owned_agent)
  );
  if (!recordsOwnedAgent) return SELF_RECOGNITION_NEEDS_RECORDER;
  const identity = nodes.find(node => node.type === 'identity' && node.parentId === transitPointId);
  const managedIdentity = identityConfigToWire(identity?.config);
  const inheritsSurfaceIdentity =
    !managedIdentity && transitPointConfig?.identity_injection?.inject_vp === true;
  if (
    !inheritsSurfaceIdentity &&
    (!managedIdentity?.type || managedIdentity.type === 'from_jwt_claim')
  ) {
    return SELF_RECOGNITION_NEEDS_IDENTITY;
  }
  return null;
}

interface SelfRecognitionCheckSectionProps {
  /** Distinguishes several instances on one page, one per Transit Point. */
  instanceKey?: string;
  checked: boolean;
  /** Why the check cannot run here, from `selfRecognitionCheckBlocker`. */
  blocker: string | null;
  onChange: (next: boolean) => void;
}

const SelfRecognitionCheckSection: React.FC<SelfRecognitionCheckSectionProps> = ({
  instanceKey,
  checked,
  blocker,
  onChange,
}) => {
  const id = `transit-point-self-recognition-check${instanceKey ? `-${instanceKey}` : ''}`;
  const noteId = `${id}-note`;
  return (
    <div className="config-section">
      <label htmlFor={id}>Self Recognition Check</label>
      <Form.Check
        type="switch"
        id={id}
        aria-describedby={blocker ? noteId : undefined}
        data-testid="transit-point-self-recognition-check-switch"
        label={
          <span className="d-flex align-items-center gap-1">
            Refuse calls while the agent is not recognised
            <FieldHelp
              testId="field-help-transit-point-self-recognition-check"
              ariaLabel="About the self recognition check"
            >
              <p>
                Before each request leaves the gateway, it asks every trust registry the Trust
                Recorder records the owned agent in whether it still recognises the agent calling
                out. The request is refused unless every one does, including when a registry cannot
                answer. Policy never sees this check.
              </p>
              <p>
                Turning the agent off in the trust registry then stops its calls through this
                Transit Point on the next request.
              </p>
            </FieldHelp>
          </span>
        }
        checked={checked}
        disabled={!checked && blocker !== null}
        onChange={e => onChange(e.target.checked)}
      />
      {blocker && (
        <Form.Text
          id={noteId}
          className={`d-block ${checked ? 'text-danger' : 'text-muted'}`}
          style={{ fontSize: '10px' }}
          data-testid="transit-point-self-recognition-check-note"
        >
          {blocker}
        </Form.Text>
      )}
    </div>
  );
};

export default SelfRecognitionCheckSection;
