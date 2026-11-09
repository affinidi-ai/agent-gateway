import React, { useState } from 'react';
import { Form, Modal } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import type { NewVtaConnection } from './types';

interface Props {
  onCancel: () => void;
  onCreate: (draft: NewVtaConnection) => Promise<void>;
}

const EMPTY: NewVtaConnection = {
  name: '',
  endpoint: '',
  vta_did: '',
  default_context_id: '',
};

/**
 * Collects the four things needed before a trust agent can be paired.
 *
 * The context is **required** here rather than later: pairing refuses without
 * one, because the grant has to be scoped to a single context. Asking for it
 * up front turns a confusing refusal mid-wizard into an ordinary field.
 *
 * No control key is collected — the gateway mints its own per connection, so
 * key material never travels through a form.
 */
export const NewVtaConnectionForm: React.FC<Props> = ({ onCancel, onCreate }) => {
  const [draft, setDraft] = useState<NewVtaConnection>(EMPTY);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = (field: keyof NewVtaConnection) => (value: string) =>
    setDraft(prev => ({ ...prev, [field]: value }));

  const complete =
    draft.name.trim() !== '' &&
    draft.endpoint.trim() !== '' &&
    draft.vta_did.trim() !== '' &&
    draft.default_context_id.trim() !== '';

  const submit = async () => {
    setSaving(true);
    setError(null);
    try {
      await onCreate(draft);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not create the connection.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show onHide={onCancel} backdrop="static" centered>
      <Modal.Header closeButton>
        <Modal.Title className="h5">
          <i className="fas fa-robot me-2" aria-hidden="true" />
          Connect a Trust Agent
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <div className="alert alert-danger py-2 small" role="alert">
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {error}
          </div>
        )}

        <Form.Group className="mb-3">
          <Form.Label htmlFor="vta-name">Name</Form.Label>
          <Form.Control
            id="vta-name"
            value={draft.name}
            onChange={e => set('name')(e.target.value)}
            placeholder="e.g. Production trust agent"
            disabled={saving}
          />
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label htmlFor="vta-endpoint">Address</Form.Label>
          <Form.Control
            id="vta-endpoint"
            value={draft.endpoint}
            onChange={e => set('endpoint')(e.target.value)}
            placeholder="https://vta.example.com"
            disabled={saving}
          />
          <Form.Text className="text-muted">Where this gateway reaches the agent.</Form.Text>
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label htmlFor="vta-did">Agent DID</Form.Label>
          <Form.Control
            id="vta-did"
            value={draft.vta_did}
            onChange={e => set('vta_did')(e.target.value)}
            placeholder="did:webvh:…"
            disabled={saving}
          />
          <Form.Text className="text-muted">
            Pinned at pairing, so a different agent at the same address is refused.
          </Form.Text>
        </Form.Group>

        <Form.Group className="mb-1">
          <Form.Label htmlFor="vta-context">Context</Form.Label>
          <Form.Control
            id="vta-context"
            value={draft.default_context_id}
            onChange={e => set('default_context_id')(e.target.value)}
            placeholder="e.g. gateway"
            disabled={saving}
          />
          <Form.Text className="text-muted">
            The grant is scoped to this one context — the agent must already have it.
          </Form.Text>
        </Form.Group>
      </Modal.Body>
      <Modal.Footer>
        <AppButton variant="outline-secondary" onClick={onCancel} disabled={saving}>
          Cancel
        </AppButton>
        <AppButton variant="primary" onClick={() => void submit()} disabled={saving || !complete}>
          {saving ? 'Creating…' : 'Create and pair'}
        </AppButton>
      </Modal.Footer>
    </Modal>
  );
};
