import { buildTrustChain, type NameResolver } from '../trustChain';
import type { AuditEntry } from '../types';

const at = (event: AuditEntry['event'], extra: Partial<AuditEntry> = {}): AuditEntry => ({
  timestamp: '2026-02-01T10:00:00Z',
  event,
  ...extra,
});

const b64url = (obj: unknown) =>
  Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const makeVp = (iss: string) => `${b64url({ alg: 'none' })}.${b64url({ iss })}.sig`;

const resolve: NameResolver = did => (did ? `name(${did})` : '');

describe('trustChain', () => {
  it('builds a recognition rung from a trust check with resolved names', () => {
    const rungs = buildTrustChain(
      [at({ trust_check: { leg: 'caller', authority_id: 'did:a', entity_id: 'did:e', ok: true } })],
      resolve
    );
    const rec = rungs.find(r => r.kind === 'authority');
    expect(rec?.title).toBe('name(did:a) → name(did:e)');
    expect(rec?.ok).toBe(true);
    expect(rec?.role).toBe('caller trust check');
  });

  it('adds a provider rung and a root-of-trust rung from the signing gateway', () => {
    const rungs = buildTrustChain(
      [
        at('token_injected', { provider_name: 'GitHub' }),
        at('vp_injected', { vp_jwt: makeVp('did:web:gw'), vp_fingerprint: 'sha256:abc' }),
      ],
      resolve
    );
    expect(rungs.some(r => r.kind === 'provider' && r.title === 'GitHub')).toBe(true);
    const root = rungs.find(r => r.kind === 'root');
    expect(root?.title).toBe('name(did:web:gw)');
    expect(root?.detail).toBe('sha256:abc');
  });

  it('returns an empty ladder when there are no trust signals', () => {
    expect(buildTrustChain([at('token_injected')], resolve)).toEqual([]);
  });

  it('skips a trust check event that has no authority or entity id', () => {
    const rungs = buildTrustChain(
      [
        at({
          trust_check: {
            leg: 'target',
            ok: false,
            error_code: 'TRUST_REGISTRY_METADATA_UNAVAILABLE',
          },
        }),
      ],
      resolve
    );
    expect(rungs.filter(r => r.kind === 'authority')).toEqual([]);
  });

  it('keeps a real recognition rung alongside an unavailable target-leg event', () => {
    const rungs = buildTrustChain(
      [
        at({
          trust_check: {
            leg: 'target',
            ok: false,
            error_code: 'AGENT_CARD_UNAVAILABLE',
          },
        }),
        at({
          trust_check: {
            leg: 'target',
            authority_id: 'did:a',
            entity_id: 'did:e',
            ok: true,
          },
        }),
      ],
      resolve
    );
    const authorityRungs = rungs.filter(r => r.kind === 'authority');
    expect(authorityRungs).toHaveLength(1);
    expect(authorityRungs[0].title).toBe('name(did:a) → name(did:e)');
  });
});
