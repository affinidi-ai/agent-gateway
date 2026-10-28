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

  describe('surface variants', () => {
    it('names the variant a surface decision applied to', () => {
      const decision = (surface_variant: string) =>
        describeEntry(
          at(
            {
              policy_decision: {
                scope: 'surface',
                flow: 'access_point',
                policy_id: 'p',
                policy_name: 'My Policy',
                decision: 'allow',
              },
            },
            { channel_name: 'Orders', surface_variant }
          )
        ).summary;

      expect(decision('beta')).toBe(
        'Surface policy “My Policy” on the Access Point leg, on variant beta.'
      );
      expect(decision('_base_')).toBe(
        'Surface policy “My Policy” on the Access Point leg, on the base surface.'
      );
    });

    it('reads a gateway-scope decision as global, applied to a surface and variant', () => {
      const n = describeEntry(
        at(
          {
            policy_decision: {
              scope: 'gateway',
              policy_id: 'g',
              policy_name: 'X',
              decision: 'deny',
            },
          },
          { channel_name: 'Orders', surface_variant: 'beta' }
        )
      );
      expect(n.summary).toBe('Gateway-wide policy “X”, applied to Orders, variant beta.');
    });

    it('describes a refusal for an unknown variant with the alias that was asked for', () => {
      const n = describeEntry(
        at(
          {
            request_rejected: {
              stage: 'routing',
              reason: 'unknown_variant',
              http_status: 404,
              requested_variant: 'typo',
            },
          },
          { channel_name: 'Orders', surface_variant: '_unknown_' }
        )
      );
      expect(n.tone).toBe('deny');
      expect(n.title).toBe('Request refused');
      expect(n.summary).toBe(
        'Refused at routing on Orders, on an unknown variant (“typo” was asked for): unknown variant.'
      );
      expect(n.detail).toBe('The caller got HTTP 404.');
    });

    it('describes a disabled variant, a modern MCP refusal and a Fabric refusal', () => {
      const disabled = describeEntry(
        at(
          {
            request_rejected: {
              stage: 'routing',
              reason: 'variant_disabled',
              http_status: 404,
              rpc_error_code: -32603,
            },
          },
          { channel_name: 'Orders', surface_variant: 'off' }
        )
      );
      expect(disabled.summary).toBe(
        'Refused at routing on Orders, on variant off: variant disabled.'
      );
      expect(disabled.detail).toBe('The caller got HTTP 404 with JSON-RPC error -32603.');

      const fabric = describeEntry(
        at(
          { request_rejected: { stage: 'routing', reason: 'misconfigured_default' } },
          { channel_name: 'Orders', via_fabric: true }
        )
      );
      expect(fabric.summary).toBe('Refused at routing on Orders: misconfigured default.');
      expect(fabric.detail).toBe('Refused over Fabric, so no HTTP status was recorded.');
    });
  });

  it('tones unit events semantically', () => {
    expect(eventTone(at('token_injected'))).toBe('allow');
    expect(eventTone(at('consent_required'))).toBe('warn');
    expect(eventTone(at('refresh_failed'))).toBe('deny');
    expect(eventTone(at('something_unknown'))).toBe('neutral');
  });

  describe('policy changes', () => {
    const user = { kind: 'user' as const, id: 'u-1' };
    const surface = { kind: 'surface' as const, id: 's-1', name: 'Orders' };

    it('says which policy was attached where, by whom', () => {
      const n = describeEntry(
        at({
          policy_attached: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            policy_version: 3,
            target: surface,
            scope: 'surface',
            slot: 'inbound',
            surface_variant: 'beta',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.title).toBe('Policy attached');
      expect(n.tone).toBe('neutral');
      expect(n.summary).toBe(
        '“Deny PII” v3 was added to surface Orders as its inbound policy, on variant beta.'
      );
      expect(n.detail).toBe('By user u-1.');
    });

    it('says a change to a base slot is on the base surface and the variants inheriting it', () => {
      const n = describeEntry(
        at({
          policy_detached: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            target: surface,
            scope: 'surface',
            slot: 'target',
            surface_variant: '_base_',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.summary).toBe(
        '“Deny PII” was removed from surface Orders as its request policy, on the base surface and the variants that inherit it.'
      );
    });

    it('names the actor by username when the resolver knows it', () => {
      const n = describeEntry(
        at({
          policy_created: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            policy_version: 1,
            actor: { kind: 'pat', id: 'tok-1', user_id: 'u-1' },
            source: 'api',
          },
        }),
        id => (id === 'u-1' ? 'alice' : undefined)
      );
      expect(n.title).toBe('Policy created');
      expect(n.summary).toBe('Policy definition “Deny PII” v1 was created.');
      expect(n.detail).toBe('By access token tok-1 of alice.');
    });

    it('lists the parts an update changed and the versions', () => {
      const n = describeEntry(
        at({
          policy_updated: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            policy_version: 3,
            previous_policy_version: 2,
            changed: ['rego', 'name'],
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.title).toBe('Policy updated');
      expect(n.summary).toBe('“Deny PII” changed from v2 to v3: Rego, name.');
    });

    it('marks a detach as a warning and names a pruned assignment as such', () => {
      const n = describeEntry(
        at({
          policy_detached: {
            policy_definition_id: 'deny-pii',
            target: { kind: 'appliance' },
            scope: 'gateway',
            slot: 'plane',
            plane: 'gateway',
            mode: 'enforced',
            actor: user,
            source: 'definition_deleted',
          },
        })
      );
      expect(n.tone).toBe('warn');
      expect(n.summary).toBe('“deny-pii” was removed from the appliance-wide gateway plane.');
      expect(n.detail).toBe('By user u-1, because the policy definition was deleted.');
    });

    it('says what a switch between enforced and monitor-only changed', () => {
      const n = describeEntry(
        at({
          policy_attachment_changed: {
            policy_definition_id: 'deny-pii',
            target: { kind: 'appliance' },
            slot: 'plane',
            plane: 'agent_surface',
            mode: 'monitor_only',
            previous_mode: 'enforced',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.title).toBe('Policy attachment changed');
      expect(n.summary).toBe(
        '“deny-pii” on the appliance-wide agent surface plane switched from enforced to monitor-only.'
      );
    });

    it('describes a refusal as a denial with its status and reason', () => {
      const n = describeEntry(
        at({
          policy_change_refused: {
            policy_definition_id: 'deny-pii',
            action: 'policy_updated',
            status: 403,
            reason: 'forbidden',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.title).toBe('Policy change refused');
      expect(n.tone).toBe('deny');
      expect(n.summary).toBe('Updating “deny-pii” was refused (403, forbidden).');
    });

    it('names a gateway inline policy and a refusal with no policy by their target', () => {
      const inline = describeEntry(
        at({
          policy_updated: {
            policy_name: 'Gateway policy',
            target: { kind: 'gateway', id: 'gw-1', name: 'Peer' },
            changed: ['rego'],
            actor: user,
            source: 'api',
          },
        })
      );
      expect(inline.summary).toBe('“Gateway policy” on gateway Peer changed: Rego.');

      const refused = describeEntry(
        at({
          policy_change_refused: {
            target: { kind: 'gateway', id: 'gw-1' },
            action: 'policy_attached',
            status: 404,
            reason: 'not_found',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(refused.summary).toBe(
        'Attaching a policy to gateway gw-1 was refused (404, not found).'
      );
    });

    it('leaves out the versions of an update that kept the version', () => {
      const n = describeEntry(
        at({
          policy_updated: {
            policy_definition_id: 'deny-pii',
            policy_name: 'Deny PII',
            policy_version: 2,
            previous_policy_version: 2,
            changed: ['owner'],
            actor: user,
            source: 'ownership',
          },
        })
      );
      expect(n.summary).toBe('“Deny PII” changed: owner.');
    });

    it('names the appliance when a refused change names no plane', () => {
      const n = describeEntry(
        at({
          policy_change_refused: {
            target: { kind: 'appliance' },
            action: 'policy_attached',
            status: 403,
            reason: 'forbidden',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.summary).toBe('Attaching a policy to the appliance was refused (403, forbidden).');
    });

    it('places a gate condition on its transit point', () => {
      const n = describeEntry(
        at({
          policy_attached: {
            policy_definition_id: 'office-hours',
            target: surface,
            scope: 'mcp_tool',
            slot: 'mcp_tool_gate',
            transit_point: 'billing',
            gate: 'Office hours',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.summary).toBe(
        '“office-hours” was added to surface Orders as the condition of MCP tool gate Office hours on transit point billing.'
      );
    });

    it('says when an attached policy is monitor-only or disabled', () => {
      const attached = (extra: Record<string, unknown>) =>
        describeEntry(
          at({
            policy_attached: {
              policy_definition_id: 'deny-pii',
              actor: user,
              source: 'api',
              ...extra,
            },
          })
        ).summary;

      expect(
        attached({
          target: { kind: 'appliance' },
          slot: 'plane',
          plane: 'gateway',
          mode: 'monitor_only',
        })
      ).toBe('“deny-pii” was added to the appliance-wide gateway plane, monitor-only.');
      expect(
        attached({
          target: { kind: 'gateway', id: 'gw-1', name: 'Peer' },
          slot: 'target',
          enabled: false,
        })
      ).toBe('“deny-pii” was added to gateway Peer, disabled.');
    });

    it('describes a refusal of an unknown action as a change', () => {
      const n = describeEntry(
        at({
          policy_change_refused: {
            policy_definition_id: 'deny-pii',
            action: 'policy_renamed',
            status: 403,
            reason: 'forbidden',
            actor: user,
            source: 'api',
          },
        })
      );
      expect(n.summary).toBe('Changing “deny-pii” was refused (403, forbidden).');
    });

    it('names the gateway only for a system actor, and an unknown actor by kind and id', () => {
      const created = (actor: unknown) =>
        describeEntry(
          at({ policy_created: { policy_definition_id: 'deny-pii', actor, source: 'api' } })
        ).detail;

      expect(created({ kind: 'system', id: 'gateway' })).toBe('By the gateway.');
      expect(created({ kind: 'service', id: 'svc-1' })).toBe('By service svc-1.');
    });

    it('names a user actor by username when the resolver knows it, else by id', () => {
      const created = (actor: { kind: 'user'; id: string }) =>
        at({
          policy_created: { policy_definition_id: 'deny-pii', actor, source: 'api' },
        });
      const userName = (id: string) => (id === 'u-1' ? 'alice' : undefined);

      expect(describeEntry(created(user), userName).detail).toBe('By user alice.');
      expect(describeEntry(created({ kind: 'user', id: 'u-2' }), userName).detail).toBe(
        'By user u-2.'
      );
    });
  });

  it('names token injection with the provider', () => {
    const n = describeEntry(at('token_injected', { provider_name: 'GitHub', inject_as: 'header' }));
    expect(n.title).toBe('Access token injected');
    expect(n.summary).toContain('GitHub');
    expect(n.summary).toContain('as header');
  });
});
