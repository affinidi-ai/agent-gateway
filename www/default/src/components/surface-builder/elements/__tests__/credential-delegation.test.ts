import { registry } from '../index';
import { credentialDelegationDefinition } from '../credential-delegation/definition';
import type { PayloadContext, SurfaceContext } from '../types';

/**
 * Unit tests for the Credential Delegation element.
 *
 * Credential Delegation owns only the surface-root `outbound_credentials`
 * slice. Workload Binding is a separate Transit-Point-scoped element and
 * is no longer hydrated, validated, or emitted here. These tests cover:
 *
 *   1. Registry registration + palette metadata.
 *   2. `incompleteReason` for empty vs partial vs valid configs.
 *   3. `buildPayload` emits only `outbound_credentials`.
 *   4. `configFromPayload` hydrates rows and ignores any legacy
 *      `transit.workload_binding` in the surrounding payload.
 *   5. `featureDependencies` raise errors when source auth or agent
 *      identity is missing, and pass when both are present.
 *   6. Registry round-trip via `buildPayload` → `nodesFromPayload`, and
 *      that a legacy WB-only payload does NOT create any node.
 */

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 't', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  } as unknown as PayloadContext;
}

function defaultNodes(extras: any[] = []): any[] {
  return [
    { id: 'ap', type: 'access-point', label: 'AP', configured: true, config: { route: '/api' } },
    {
      id: 'tg',
      type: 'target',
      label: 'T',
      configured: true,
      config: { endpoint: 'http://example.com' },
    },
    ...extras,
  ];
}

const sampleBindingRow = {
  credential_provider_id: 'prov-1',
  scopes: 'read write',
  consent_mode: 'on_demand' as const,
  required_for_mode: 'all' as const,
  inject_as_type: 'bearer_header' as const,
};

describe('credential-delegation definition', () => {
  it('is registered with the global registry', () => {
    const def = registry.get('credential-delegation' as any);
    expect(def).toBeDefined();
    expect(def!.type).toBe('credential-delegation');
    expect(def!.dropMode).toBe('edge');
    expect(def!.cardinality).toBe('singleton');
  });

  describe('incompleteReason', () => {
    it('flags empty configs as incomplete', () => {
      expect(
        credentialDelegationDefinition.incompleteReason({
          outbound_credentials_form: [],
        })
      ).toMatch(/binding/i);
    });

    it('accepts a configuration with bindings', () => {
      expect(
        credentialDelegationDefinition.incompleteReason({
          outbound_credentials_form: [sampleBindingRow],
        })
      ).toBeNull();
    });

    it('flags a binding missing its provider', () => {
      const r = credentialDelegationDefinition.incompleteReason({
        outbound_credentials_form: [{ ...sampleBindingRow, credential_provider_id: '' }],
      });
      expect(r).toMatch(/credential provider/i);
    });

    it('flags a binding with custom header type missing the header name', () => {
      const r = credentialDelegationDefinition.incompleteReason({
        outbound_credentials_form: [
          { ...sampleBindingRow, inject_as_type: 'custom_header', inject_as_custom_name: '' },
        ],
      });
      expect(r).toMatch(/custom header/i);
    });

    it('does not include binding index numbers in user-facing messages', () => {
      const r = credentialDelegationDefinition.incompleteReason({
        outbound_credentials_form: [
          sampleBindingRow,
          { ...sampleBindingRow, credential_provider_id: '' },
        ],
      });
      expect(r).not.toMatch(/#\d/);
    });
  });

  describe('buildPayload', () => {
    it('emits only outbound_credentials', () => {
      const ctx = makeCtx(
        defaultNodes([
          {
            id: 'credential-delegation-target',
            type: 'credential-delegation',
            label: '',
            configured: true,
            config: {
              outbound_credentials_form: [sampleBindingRow],
            },
          },
        ])
      );
      const slices = credentialDelegationDefinition.buildPayload!(ctx);
      expect(slices!.map(s => s.path)).toEqual(['outbound_credentials']);
    });

    it('never emits transit.workload_binding, even if a stale key is present', () => {
      const ctx = makeCtx(
        defaultNodes([
          {
            id: 'credential-delegation-target',
            type: 'credential-delegation',
            label: '',
            configured: true,
            config: {
              outbound_credentials_form: [sampleBindingRow],
              workload_binding: { agent_fields: ['agent_id'], user_fields: [] },
            },
          },
        ])
      );
      const slices = credentialDelegationDefinition.buildPayload!(ctx);
      expect(slices!.map(s => s.path)).toEqual(['outbound_credentials']);
    });

    it('returns undefined when nothing is configured', () => {
      const ctx = makeCtx(
        defaultNodes([
          {
            id: 'credential-delegation-target',
            type: 'credential-delegation',
            label: '',
            configured: false,
            config: { outbound_credentials_form: [] },
          },
        ])
      );
      expect(credentialDelegationDefinition.buildPayload!(ctx)).toBeUndefined();
    });
  });

  describe('configFromPayload', () => {
    it('hydrates form rows from outbound_credentials slice', () => {
      const slice = [
        {
          credential_provider_id: 'prov-1',
          scopes: ['read', 'write'],
          required_for: 'all',
          consent_mode: 'on_demand',
          inject_as: { type: 'bearer_header' },
        },
      ];
      const cfg = credentialDelegationDefinition.configFromPayload!(slice, {
        outbound_credentials: slice,
      });
      expect(cfg.outbound_credentials_form).toHaveLength(1);
      expect(cfg.outbound_credentials_form[0].credential_provider_id).toBe('prov-1');
      expect(cfg.workload_binding).toBeUndefined();
    });

    it('ignores a legacy transit.workload_binding in the surrounding payload', () => {
      const cfg = credentialDelegationDefinition.configFromPayload!([], {
        outbound_credentials: [],
        transit: { workload_binding: { agent_fields: ['a'], user_fields: [{ claim: 'sub' }] } },
      });
      expect(cfg.workload_binding).toBeUndefined();
      expect(cfg.outbound_credentials_form).toEqual([]);
    });
  });

  describe('featureDependencies — channel parity', () => {
    const credNode = {
      id: 'credential-delegation-target',
      type: 'credential-delegation',
      label: '',
      configured: true,
      config: {
        outbound_credentials_form: [sampleBindingRow],
      },
    };
    const callerAuth = {
      id: 'caller-auth',
      type: 'caller-auth',
      label: '',
      configured: true,
      config: { method_type: 'api_key' },
    };
    const identity = {
      id: 'identity-protected',
      type: 'identity',
      label: '',
      configured: true,
      config: { type: 'from_payload' },
    };

    function ctxWith(extra: any[]): SurfaceContext {
      return {
        protocol: 'a2a',
        accessPoint: {},
        target: {},
        transitPoints: [],
        allNodes: defaultNodes([credNode, ...extra]),
      } as any;
    }

    it('has no workload-binding feature dependency', () => {
      const deps = credentialDelegationDefinition.featureDependencies!;
      expect(deps.some(d => /workload/i.test(d.description))).toBe(false);
    });

    it('raises source-auth error when no caller-auth node is configured', () => {
      const deps = credentialDelegationDefinition.featureDependencies!;
      const sourceAuthRule = deps.find(d => /source authentication/i.test(d.description))!;
      const ctx = ctxWith([identity]);
      expect(sourceAuthRule.condition(credNode.config, ctx)).toBe(true);
      expect(sourceAuthRule.check(credNode.config, ctx)).toBe(false);
    });

    it('raises agent-identity error when no identity node is configured', () => {
      const deps = credentialDelegationDefinition.featureDependencies!;
      const identityRule = deps.find(d => /agent identity/i.test(d.description))!;
      const ctx = ctxWith([callerAuth]);
      expect(identityRule.condition(credNode.config, ctx)).toBe(true);
      expect(identityRule.check(credNode.config, ctx)).toBe(false);
    });

    it('passes both bindings rules when caller-auth and identity are present', () => {
      const deps = credentialDelegationDefinition.featureDependencies!;
      const ctx = ctxWith([callerAuth, identity]);
      const failures = deps
        .filter(rule => rule.condition(credNode.config, ctx))
        .filter(rule => !rule.check(credNode.config, ctx))
        .map(rule => rule.description);
      expect(failures).toEqual([]);
    });
  });

  describe('registry round-trip', () => {
    it('recovers a credential-delegation node from outbound_credentials', () => {
      const buildCtx = makeCtx(
        defaultNodes([
          {
            id: 'credential-delegation-target',
            type: 'credential-delegation',
            label: '',
            configured: true,
            config: {
              outbound_credentials_form: [sampleBindingRow],
            },
          },
        ])
      );
      const payload = registry.buildPayload(buildCtx);
      expect(payload.outbound_credentials).toBeDefined();
      expect(payload.transit?.workload_binding).toBeUndefined();

      const recovered = registry.nodesFromPayload(payload);
      const node = recovered.find(n => n.type === 'credential-delegation');
      expect(node).toBeDefined();
      expect(node!.config.outbound_credentials_form).toHaveLength(1);
      expect(node!.config.workload_binding).toBeUndefined();
    });

    it('does not create any node from a legacy WB-only payload', () => {
      // A stored surface that still carries only shared
      // `transit.workload_binding` no longer produces a Credential
      // Delegation node or a Workload Binding node — Workload Binding is
      // now Transit-Point-scoped (`transit.points[*].workload_binding`).
      const payload = {
        access_point: { route: '/api' },
        target: { endpoint: 'http://example.com' },
        transit: { workload_binding: { agent_fields: ['a'], user_fields: [{ claim: 'sub' }] } },
      };
      const recovered = registry.nodesFromPayload(payload);
      expect(recovered.some(n => n.type === 'credential-delegation')).toBe(false);
      expect(recovered.some(n => n.type === 'workload-binding')).toBe(false);
    });
  });
});
