import { describeEntry, eventTone } from '../eventNarrative';
import type { AuditEntry } from '../types';

const at = (event: AuditEntry['event'], extra: Partial<AuditEntry> = {}): AuditEntry => ({
  timestamp: '2026-02-01T10:00:00Z',
  event,
  ...extra,
});

describe('eventNarrative', () => {
  it('describes an allow policy decision with a green tone and HTTP target', () => {
    const n = describeEntry(
      at(
        {
          policy_decision: {
            scope: 'surface',
            flow: 'access_point',
            policy_id: 'p',
            policy_name: 'My Policy',
            decision: 'allow',
            http_method: 'POST',
            http_path: '/v1/message',
            policy_version: 7,
            policy_content_hash:
              'sha256:9f3c9ec7bf76e8617d7f7a2b11ac1990a748ee7445739836b3fd3cd188608f5c',
          },
        },
        { channel_name: 'Weather Surface', protocol: 'a2a' }
      )
    );
    expect(n.tone).toBe('allow');
    expect(n.title).toBe('Allowed POST /v1/message');
    expect(n.summary).toContain('Surface policy');
    expect(n.summary).toContain('Access Point');
  });

  it('describes a deny policy decision with a red tone and the deny reason in the detail', () => {
    const n = describeEntry(
      at({
        policy_decision: {
          scope: 'gateway',
          policy_id: 'g',
          decision: 'deny',
          deny_reason: 'blocked by policy',
          http_method: 'POST',
          http_path: '/v1/message',
        },
      })
    );
    expect(n.tone).toBe('deny');
    expect(n.title).toBe('Denied POST /v1/message');
    expect(n.detail).toContain('blocked by policy');
  });

  it('describes trust checks by outcome', () => {
    const ok = describeEntry(
      at({ trust_check: { leg: 'caller', authority_id: 'auth', entity_id: 'ent', ok: true } })
    );
    expect(ok.tone).toBe('allow');
    expect(ok.title).toBe('Trust check passed');

    const bad = describeEntry(
      at({
        trust_check: {
          leg: 'target',
          authority_id: 'auth',
          entity_id: 'ent',
          ok: false,
          error_code: 'QUERY_TIMEOUT',
        },
      })
    );
    expect(bad.tone).toBe('deny');
    expect(bad.title).toBe('Trust check failed');
    expect(bad.detail).toContain('timed out');
  });

  it('describes a target-leg trust check that could not be evaluated', () => {
    const n = describeEntry(
      at({
        trust_check: {
          leg: 'target',
          ok: false,
          error_code: 'TRUST_REGISTRY_METADATA_UNAVAILABLE',
        },
      })
    );
    expect(n.tone).toBe('deny');
    expect(n.title).toBe('Trust check failed');
    expect(n.summary).toBe('The target leg trust check could not be evaluated.');
    expect(n.detail).toBe(
      "Failed because the target's agent card is missing the trust registry metadata extension."
    );
  });

  it('describes a caller-leg TRUST_REGISTRY_METADATA_UNAVAILABLE with caller-payload wording', () => {
    const n = describeEntry(
      at({
        trust_check: {
          leg: 'caller',
          ok: false,
          error_code: 'TRUST_REGISTRY_METADATA_UNAVAILABLE',
        },
      })
    );
    expect(n.detail).toBe(
      "Failed because the caller's request payload is missing the trust registry metadata extension."
    );
  });

  it('tones unit events semantically', () => {
    expect(eventTone(at('token_injected'))).toBe('allow');
    expect(eventTone(at('consent_required'))).toBe('warn');
    expect(eventTone(at('pre_authorize_blocked'))).toBe('deny');
    expect(eventTone(at('something_unknown'))).toBe('neutral');
  });

  it('names token injection with the provider', () => {
    const n = describeEntry(at('token_injected', { provider_name: 'GitHub', inject_as: 'header' }));
    expect(n.title).toBe('Access token injected');
    expect(n.summary).toContain('GitHub');
    expect(n.summary).toContain('as header');
  });
});
