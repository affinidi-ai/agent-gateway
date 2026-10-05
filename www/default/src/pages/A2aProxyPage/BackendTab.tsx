import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../components/shared/FieldHelp';
import { DOCS_URL } from '../../config/docs';
import { A2A_PROXY_BACKEND_DESCRIPTIONS, getA2aProxyBackendLabel } from './backendMetadata';
import type { A2aProxyFormData, SecretOption } from './types';

interface BackendTabProps {
  formData: A2aProxyFormData;
  secrets: SecretOption[];
  onBackendChange: (patch: Partial<A2aProxyFormData['backend']>) => void;
}

const BackendTab: React.FC<BackendTabProps> = ({ formData, secrets, onBackendChange }) => (
  <div data-testid="a2a-proxy-backend-tab">
    <div className="card border-left-primary shadow-sm mb-3">
      <div className="card-body">
        <Form.Group className="mb-0">
          <Form.Label>
            Backend type{' '}
            <FieldHelp testId="field-help-a2a-backend-type" ariaLabel="About Backend type">
              This proxy connects to a Microsoft Copilot bot through Direct Line, Microsoft&apos;s
              API for sending and receiving bot messages, and makes it reachable through A2A, the
              protocol AI agents use to call each other.
            </FieldHelp>
          </Form.Label>
          <Form.Select
            data-testid="a2a-proxy-backend-kind-select"
            value={formData.backend.kind}
            disabled
          >
            <option value="copilot_direct_line">
              {getA2aProxyBackendLabel('copilot_direct_line')}
            </option>
          </Form.Select>
          <Form.Text className="text-muted">
            {A2A_PROXY_BACKEND_DESCRIPTIONS[formData.backend.kind]} Currently the only backend type
            supported.
          </Form.Text>
        </Form.Group>
      </div>
    </div>

    <div className="row">
      <div className="col-lg-8">
        <Form.Group className="mb-3">
          <Form.Label>
            Direct Line Secret <span className="text-danger">*</span>{' '}
            <FieldHelp testId="field-help-a2a-backend-secret" ariaLabel="About Direct Line Secret">
              The credential this proxy uses to authenticate with your Copilot bot&apos;s Direct
              Line channel, created in Secrets.
            </FieldHelp>
          </Form.Label>
          <Form.Select
            data-testid="a2a-proxy-secret-select"
            value={formData.backend.secret_id}
            onChange={e => onBackendChange({ secret_id: e.target.value })}
            required
          >
            <option value="">Select a stored secret…</option>
            {secrets.map(secret => (
              <option key={secret.id} value={secret.secret_id || secret.id}>
                {secret.name || secret.secret_id || secret.id}
              </option>
            ))}
            {formData.backend.secret_id &&
              !secrets.some(s => (s.secret_id || s.id) === formData.backend.secret_id) && (
                <option value={formData.backend.secret_id}>
                  {formData.backend.secret_id} (not found)
                </option>
              )}
          </Form.Select>
          <Form.Text className="text-muted d-block">
            Picking the wrong one means the proxy won&apos;t be able to reach your bot.
          </Form.Text>
          <div className="surface-info-panel-doclink">
            <a href={DOCS_URL.secrets} target="_blank" rel="noopener noreferrer">
              Learn more about Secrets <i className="fas fa-arrow-right ms-1" aria-hidden="true" />
            </a>
          </div>
        </Form.Group>
      </div>
      <div className="col-lg-4">
        <Form.Group className="mb-3">
          <Form.Label>
            Credential Mode{' '}
            <FieldHelp
              testId="field-help-a2a-backend-credential-mode"
              ariaLabel="About Credential Mode"
            >
              Generate Direct Line token exchanges your stored secret for a short-lived token first,
              used per request. Switch to Generate Direct Line token only if your bot&apos;s Direct
              Line setup requires it.
            </FieldHelp>
          </Form.Label>
          <Form.Select
            data-testid="a2a-proxy-credential-mode-select"
            value={formData.backend.credential_mode}
            onChange={e =>
              onBackendChange({
                credential_mode: e.target.value as A2aProxyFormData['backend']['credential_mode'],
              })
            }
          >
            <option value="secret">Direct Line secret</option>
            <option value="generate_token">Generate Direct Line token</option>
          </Form.Select>
          <Form.Text className="text-muted">
            Direct Line secret (the default) is the simplest option, start here.
          </Form.Text>
        </Form.Group>
      </div>
    </div>

    <Form.Group className="mb-3">
      <Form.Label>
        Direct Line Base URL{' '}
        <FieldHelp testId="field-help-a2a-backend-base-url" ariaLabel="About Direct Line Base URL">
          The Microsoft Direct Line endpoint your bot channel talks to.
        </FieldHelp>
      </Form.Label>
      <Form.Control
        data-testid="a2a-proxy-base-url-input"
        value={formData.backend.base_url}
        onChange={e => onBackendChange({ base_url: e.target.value })}
      />
      <Form.Text className="text-muted">
        The default shown here works for almost everyone, only change it if Microsoft support told
        you to use a different regional endpoint.
      </Form.Text>
    </Form.Group>

    <div className="row">
      <div className="col-md-4">
        <Form.Group className="mb-3">
          <Form.Label>
            Timeout seconds{' '}
            <FieldHelp testId="field-help-a2a-backend-timeout" ariaLabel="About Timeout seconds">
              How long the gateway waits for a response from Direct Line before giving up.
            </FieldHelp>
          </Form.Label>
          <Form.Control
            data-testid="a2a-proxy-timeout-input"
            type="number"
            min={1}
            max={120}
            value={formData.backend.timeout_secs}
            onChange={e => onBackendChange({ timeout_secs: Number(e.target.value) })}
          />
          <Form.Text className="text-muted">
            30 seconds works for most setups, raise it only if you&apos;re seeing timeout errors.
          </Form.Text>
        </Form.Group>
      </div>
      <div className="col-md-4">
        <Form.Group className="mb-3">
          <Form.Label>
            Poll interval ms{' '}
            <FieldHelp
              testId="field-help-a2a-backend-poll-interval"
              ariaLabel="About Poll interval ms"
            >
              How often the gateway checks Direct Line for the bot&apos;s reply. Lowering it makes
              replies feel faster but increases load on Direct Line.
            </FieldHelp>
          </Form.Label>
          <Form.Control
            data-testid="a2a-proxy-poll-interval-input"
            type="number"
            min={100}
            max={5000}
            value={formData.backend.poll_interval_ms}
            onChange={e => onBackendChange({ poll_interval_ms: Number(e.target.value) })}
          />
          <Form.Text className="text-muted">
            500ms (twice a second) is a reasonable default.
          </Form.Text>
        </Form.Group>
      </div>
      <div className="col-md-4">
        <Form.Group className="mb-3">
          <Form.Label>
            Max poll attempts{' '}
            <FieldHelp
              testId="field-help-a2a-backend-max-poll-attempts"
              ariaLabel="About Max poll attempts"
            >
              How many times the gateway checks for a reply before giving up, combined with the poll
              interval above (at the defaults, that&apos;s up to 30 seconds of polling).
            </FieldHelp>
          </Form.Label>
          <Form.Control
            data-testid="a2a-proxy-max-poll-attempts-input"
            type="number"
            min={1}
            max={240}
            value={formData.backend.max_poll_attempts}
            onChange={e => onBackendChange({ max_poll_attempts: Number(e.target.value) })}
          />
          <Form.Text className="text-muted">
            60 is a reasonable default, raise it only for bots known to respond slowly.
          </Form.Text>
        </Form.Group>
      </div>
    </div>
  </div>
);

export default BackendTab;
