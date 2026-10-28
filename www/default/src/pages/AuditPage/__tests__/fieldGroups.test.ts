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

  describe('surface variants', () => {
    it('shows the variant of a surface request under Surface & routing', () => {
      const routing = (surface_variant?: string) =>
        groupByLabel(baseEntry({ channel_name: 'Orders', surface_variant }), null, null)[
          'Surface & routing'
        ].find(item => item.term === 'Variant');

      expect(routing('beta')).toEqual({ term: 'Variant', value: 'beta' });
      expect(routing('_base_')).toEqual({ term: 'Variant', value: 'Base surface' });
      expect(routing('_unknown_')).toEqual({ term: 'Variant', value: 'Unknown variant' });
      expect(routing(undefined)).toBeUndefined();
    });

    it('shows a gateway-scope decision as applying to every surface', () => {
      const pd: PolicyDecisionData = { scope: 'gateway', policy_id: 'g', decision: 'allow' };
      const groups = groupByLabel(
        baseEntry({ event: { policy_decision: pd }, surface_variant: 'beta' }),
        pd,
        null
      );

      expect(groups['Policy']).toEqual(
        expect.arrayContaining([{ term: 'Scope', value: 'Gateway (all surfaces)' }])
      );
    });

    it('lays out a refusal with what the caller got and the variant asked for', () => {
      const unknown = groupByLabel(
        baseEntry({
          event: {
            request_rejected: {
              stage: 'routing',
              reason: 'unknown_variant',
              http_status: 404,
              rpc_error_code: -32603,
              requested_variant: 'typo',
            },
          },
          surface_variant: '_unknown_',
        }),
        null,
        null
      );
      expect(unknown['Refusal']).toEqual([
        { term: 'Stage', value: 'routing' },
        { term: 'Reason', value: 'unknown variant' },
        { term: 'HTTP status', value: '404' },
        { term: 'JSON-RPC error', value: '-32603' },
        { term: 'Requested variant', value: 'typo', mono: true },
      ]);

      const fabric = groupByLabel(
        baseEntry({
          event: { request_rejected: { stage: 'routing', reason: 'misconfigured_default' } },
          via_fabric: true,
        }),
        null,
        null
      );
      expect(fabric['Refusal']).toEqual([
        { term: 'Stage', value: 'routing' },
        { term: 'Reason', value: 'misconfigured default' },
      ]);
    });
  });

  describe('policy changes', () => {
    it('shows a base slot change as the base surface', () => {
      const entry = baseEntry({
        event: {
          policy_attached: {
            policy_definition_id: 'deny-pii',
            target: { kind: 'surface', id: 's-1', name: 'Orders' },
            scope: 'surface',
            slot: 'target',
            surface_variant: '_base_',
            actor: { kind: 'user', id: 'u-1' },
            source: 'api',
          },
        },
      });
      const where = groupByLabel(entry, null, null)['Where'];
      expect(where).toEqual(expect.arrayContaining([{ term: 'Variant', value: 'Base surface' }]));
    });

    it('lays out a policy change as Change, Policy and Where, with links', () => {
      const entry = baseEntry({
        event: {
          policy_attached: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            policy_type: 'agent_surface',
            policy_version: 3,
            policy_content_hash: 'sha256:abc',
            target: { kind: 'surface', id: 's-1', name: 'Orders' },
            scope: 'surface',
            slot: 'transit_point',
            transit_point: 'billing',
            surface_variant: 'beta',
            actor: { kind: 'pat', id: 'tok-1', user_id: 'u-1' },
            source: 'api',
          },
        },
        request_id: '0123456789abcdef',
        surface_id: 's-1',
        channel_name: 'Orders',
      });

      const groups = Object.fromEntries(
        fieldGroups(entry, null, null, id => (id === 'u-1' ? 'alice' : undefined)).map(g => [
          g.label,
          g.items,
        ])
      );

      expect(groups['Change']).toEqual([
        { term: 'Action', value: 'Policy attached' },
        { term: 'Actor', value: 'access token tok-1 of alice' },
        { term: 'Request', value: '0123456789abcdef', mono: true },
      ]);
      expect(groups['Policy']).toEqual([
        { term: 'Policy', value: 'Deny PII', href: '/policies?tab=agent_surface' },
        { term: 'Policy definition', value: 'deny-pii', mono: true },
        { term: 'Policy version', value: 'v3' },
        { term: 'Policy SHA', value: 'sha256:abc', mono: true },
      ]);
      expect(groups['Where']).toEqual([
        { term: 'Target', value: 'surface Orders', href: '/surfaces/s-1' },
        { term: 'Slot', value: 'transit point request policy' },
        { term: 'Scope', value: 'Surface' },
        { term: 'Variant', value: 'beta' },
        { term: 'Transit point', value: 'billing', mono: true },
      ]);
      expect(groups['Identity']).toEqual([]);
    });

    it('shows the before and after of an update and a refusal', () => {
      const updated = Object.fromEntries(
        fieldGroups(
          baseEntry({
            event: {
              policy_attachment_changed: {
                policy_definition_id: 'g',
                target: { kind: 'gateway', id: 'gw-1', name: 'Peer' },
                slot: 'target',
                enabled: false,
                previous_enabled: true,
                actor: { kind: 'user', id: 'u-1' },
                source: 'api',
              },
            },
          }),
          null,
          null
        ).map(g => [g.label, g.items])
      );
      expect(updated['Where']).toEqual(
        expect.arrayContaining([
          { term: 'Target', value: 'gateway Peer', href: '/gateways/gw-1' },
          { term: 'Enabled', value: 'Yes → No' },
        ])
      );

      const refused = Object.fromEntries(
        fieldGroups(
          baseEntry({
            event: {
              policy_change_refused: {
                policy_definition_id: 'p',
                action: 'policy_deleted',
                status: 403,
                reason: 'forbidden',
                actor: { kind: 'user', id: 'u-1' },
                source: 'api',
              },
            },
          }),
          null,
          null
        ).map(g => [g.label, g.items])
      );
      expect(refused['Refusal']).toEqual([
        { term: 'Attempted', value: 'Policy deleted' },
        { term: 'Status', value: '403' },
        { term: 'Reason', value: 'forbidden' },
      ]);
    });
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
