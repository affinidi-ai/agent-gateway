import React, { useEffect, useState } from 'react';
import { Form } from 'react-bootstrap';
import type { CanvasNode } from '../../SurfaceCanvas';
import { apiClient } from '../../../../api';
import { identityConfigToWire } from '../identity/definition';
import { readEntries } from '../trust-recorder/definition';

export const SELF_RECOGNITION_REQUIRES_RECORDER =
  'Requires a Trust Recorder that records the owned agent on this surface.';
export const SELF_RECOGNITION_REQUIRES_IDENTITY =
  'Requires an Identity on this Transit Point, so the gateway knows which agent to check.';
export const SELF_RECOGNITION_REQUIRES_REGISTRY =
  'Pick at least one trust registry for the self recognition check.';

/** The stored `self_recognition_check`: the trust registries it asks. */
export interface SelfRecognitionCheck {
  trust_registry_ids: string[];
}

/** The trust registries this surface's Trust Recorder records the owned agent in, in entry order. */
export function ownedAgentRegistryIds(allNodes: CanvasNode[] | undefined): string[] {
  const ids = (allNodes ?? [])
    .filter(node => node.type === 'trust-recorder')
    .flatMap(node => readEntries(node.config))
    .filter(entry => entry.include_owned_agent && entry.trust_registry_id)
    .map(entry => entry.trust_registry_id);
  return Array.from(new Set(ids));
}

/** Why the Transit Point's switch is on with no trust registry picked, or null. */
export function selfRecognitionRegistryProblem(config: Record<string, any>): string | null {
  const check = config.self_recognition_check as SelfRecognitionCheck | null | undefined;
  if (!check || typeof check !== 'object') return null;
  return check.trust_registry_ids?.length ? null : SELF_RECOGNITION_REQUIRES_REGISTRY;
}

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
  if (ownedAgentRegistryIds(nodes).length === 0) return SELF_RECOGNITION_REQUIRES_RECORDER;
  const identity = nodes.find(node => node.type === 'identity' && node.parentId === transitPointId);
  const managedIdentity = identityConfigToWire(identity?.config);
  const inheritsSurfaceIdentity =
    !managedIdentity && transitPointConfig?.identity_injection?.inject_vp === true;
  if (
    !inheritsSurfaceIdentity &&
    (!managedIdentity?.type || managedIdentity.type === 'from_jwt_claim')
  ) {
    return SELF_RECOGNITION_REQUIRES_IDENTITY;
  }
  return null;
}

/** Trust registry names by id, read once; ids stand in for names until then. */
function useRegistryNames(enabled: boolean): Record<string, string> {
  const [names, setNames] = useState<Record<string, string>>({});
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    Promise.resolve(apiClient.listTrustRegistries?.())
      .then(registries => {
        if (cancelled || !Array.isArray(registries)) return;
        setNames(Object.fromEntries(registries.map(registry => [registry.id, registry.name])));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [enabled]);
  return names;
}

interface SelfRecognitionCheckSectionProps {
  /** Distinguishes several instances on one page, one per Transit Point. */
  instanceKey?: string;
  value: SelfRecognitionCheck | null | undefined;
  /** The trust registries the Trust Recorder records the owned agent in, from `ownedAgentRegistryIds`. */
  registryIds: string[];
  /** Why the check cannot run here, from `selfRecognitionCheckBlocker`. */
  blocker: string | null;
  onChange: (next: SelfRecognitionCheck | null) => void;
}

const SelfRecognitionCheckSection: React.FC<SelfRecognitionCheckSectionProps> = ({
  instanceKey,
  value,
  registryIds,
  blocker,
  onChange,
}) => {
  const checked = !!value && typeof value === 'object';
  const picked = checked ? (value.trust_registry_ids ?? []) : [];
  const names = useRegistryNames(checked);
  const id = `transit-point-self-recognition-check${instanceKey ? `-${instanceKey}` : ''}`;
  const helpId = `${id}-help`;
  const noteId = `${id}-note`;

  const toggleRegistry = (registryId: string, on: boolean) => {
    const next = on
      ? [...picked.filter(existing => existing !== registryId), registryId]
      : picked.filter(existing => existing !== registryId);
    onChange({ trust_registry_ids: registryIds.filter(candidate => next.includes(candidate)) });
  };

  return (
    <div className="config-section">
      <Form.Group className="mb-2">
        <Form.Check
          type="switch"
          id={id}
          data-testid="transit-point-self-recognition-check-switch"
          label="Self Recognition Check"
          aria-describedby={blocker ? `${helpId} ${noteId}` : helpId}
          checked={checked}
          disabled={!checked && blocker !== null}
          onChange={e => onChange(e.target.checked ? { trust_registry_ids: [] } : null)}
        />
        <Form.Text
          id={helpId}
          className="text-muted d-block"
          style={{ fontSize: '10px' }}
          data-testid="transit-point-self-recognition-check-help"
        >
          Before each request leaves the gateway, the trust registries you pick from this
          surface&apos;s Trust Recorder must still recognise the agent calling out, or the request
          is refused. Policy never sees this check.
        </Form.Text>
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
        {checked && (
          <div className="mt-2" data-testid="transit-point-self-recognition-check-registries">
            {registryIds.map(registryId => (
              <Form.Check
                key={registryId}
                type="checkbox"
                id={`${id}-registry-${registryId}`}
                data-testid={`transit-point-self-recognition-check-registry-${registryId}`}
                label={names[registryId] ?? registryId}
                checked={picked.includes(registryId)}
                onChange={e => toggleRegistry(registryId, e.target.checked)}
              />
            ))}
            {picked.length === 0 && (
              <Form.Text
                className="d-block text-danger"
                style={{ fontSize: '10px' }}
                data-testid="transit-point-self-recognition-check-registry-required"
              >
                {SELF_RECOGNITION_REQUIRES_REGISTRY}
              </Form.Text>
            )}
          </div>
        )}
      </Form.Group>
    </div>
  );
};

export default SelfRecognitionCheckSection;
