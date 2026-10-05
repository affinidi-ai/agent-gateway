import { fieldGroups } from '../fieldGroups';
import type { AuditEntry, PolicyDecisionData, TrustCheckData } from '../types';

const baseEntry = (extra: Partial<AuditEntry> = {}): AuditEntry => ({
  timestamp: '2026-02-01T10:00:00Z',
  event: 'token_injected',
  ...extra,
});

function groupByLabel(entry: AuditEntry, pd: PolicyDecisionData | null, tc: TrustCheckData | null) {
  return Object.fromEntries(fieldGroups(entry, pd, tc).map(g => [g.label, g.items]));
}

describe('fieldGroups', () => {
  it('places caller identity fields under Identity and links the surface', () => {
    const entry = baseEntry({
      caller: { auth_method: 'jwt_bearer', did: 'did:web:example.com:agent' },
      channel_name: 'Weather Surface',
      surface_id: 'surface-1',
      protocol: 'a2a',
    });
    const groups = groupByLabel(entry, null, null);

    expect(groups['Identity']).toEqual(
      expect.arrayContaining([
        { term: 'Auth method', value: 'jwt_bearer' },
        { term: 'Caller DID', value: 'did:web:example.com:agent', mono: true },
      ])
    );
    const surface = groups['Surface & routing'].find(i => i.term === 'Agent surface');
    expect(surface).toEqual({
      term: 'Agent surface',
      value: 'Weather Surface',
      href: '/surfaces/surface-1',
    });
  });

  it('summarises a policy decision under Policy', () => {
    const pd: PolicyDecisionData = {
      scope: 'surface',
      policy_id: 'p',
      policy_name: 'My Policy',
      policy_definition_id: 'policy-def-1',
      policy_version: 3,
      policy_content_hash:
        'sha256:9f3c9ec7bf76e8617d7f7a2b11ac1990a748ee7445739836b3fd3cd188608f5c',
      decision: 'deny',
      deny_reason: 'blocked',
      http_method: 'POST',
      http_path: '/v1/message',
    };
    const groups = groupByLabel(baseEntry({ event: { policy_decision: pd } }), pd, null);

    expect(groups['Policy']).toEqual(
      expect.arrayContaining([
        { term: 'Policy', value: 'My Policy', mono: true },
        { term: 'Policy definition', value: 'policy-def-1', mono: true },
        { term: 'Policy version', value: 'v3' },
        {
          term: 'Policy SHA',
          value: 'sha256:9f3c9ec7bf76e8617d7f7a2b11ac1990a748ee7445739836b3fd3cd188608f5c',
          mono: true,
        },
        { term: 'Decision', value: 'deny' },
        { term: 'Deny reason', value: 'blocked' },
        { term: 'Request', value: 'POST /v1/message', mono: true },
      ])
    );
  });

  it('omits empty groups and never emits blank values', () => {
    const groups = fieldGroups(baseEntry(), null, null);
    for (const g of groups) {
      for (const item of g.items) {
        expect(item.value).not.toBe('');
      }
    }
    // With almost nothing set, Identity/Credentials collapse to empty.
    const byLabel = groupByLabel(baseEntry(), null, null);
    expect(byLabel['Identity']).toHaveLength(0);
    expect(byLabel['Credentials']).toHaveLength(0);
    // Routing always has the Via fabric row.
    expect(byLabel['Surface & routing']).toEqual([{ term: 'Via fabric', value: 'No' }]);
  });

  it('does not infer Caller DID from agent identity fields', () => {
    const groups = groupByLabel(
      baseEntry({
        event: 'vp_injected',
        agent_did: 'did:web:endpoint',
        agent_identity_did: 'did:web:holder',
      }),
      null,
      null
    );

    expect(groups['Identity']).toEqual(
      expect.arrayContaining([{ term: 'Agent DID', value: 'did:web:endpoint', mono: true }])
    );
    expect(groups['Identity']).toEqual(
      expect.arrayContaining([{ term: 'Agent identity', value: 'did:web:holder', mono: true }])
    );
    expect(groups['Identity'].map(item => item.term)).not.toContain('Caller DID');
  });

  describe('trust check rows', () => {
    it('emits Authority and Entity as monospace rows when the wire carries both', () => {
      const tc: TrustCheckData = {
        leg: 'caller',
        authority_id: 'did:a',
        entity_id: 'did:e',
        ok: true,
      };
      const groups = groupByLabel(baseEntry({ event: { trust_check: tc } }), null, tc);
      expect(groups['Policy']).toEqual(
        expect.arrayContaining([
          { term: 'Trust leg', value: 'caller' },
          { term: 'Authority', value: 'did:a', mono: true },
          { term: 'Entity', value: 'did:e', mono: true },
          { term: 'Result', value: 'Passed' },
        ])
      );
    });

    it('omits Authority and Entity when the wire does not carry them (unavailable paths)', () => {
      const tc: TrustCheckData = {
        leg: 'target',
        ok: false,
        error_code: 'AGENT_CARD_UNAVAILABLE',
      };
      const groups = groupByLabel(baseEntry({ event: { trust_check: tc } }), null, tc);
      const terms = groups['Policy'].map(item => item.term);
      expect(terms).not.toContain('Authority');
      expect(terms).not.toContain('Entity');
      expect(terms).toEqual(expect.arrayContaining(['Trust leg', 'Result', 'Failure']));
      const result = groups['Policy'].find(item => item.term === 'Result');
      expect(result?.value).toBe('Failed');
    });
  });
});
