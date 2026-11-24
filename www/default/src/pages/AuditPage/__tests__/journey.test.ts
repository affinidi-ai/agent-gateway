import { buildJourney } from '../journey';
import type { AuditEntry } from '../types';

const at = (event: AuditEntry['event'], extra: Partial<AuditEntry> = {}): AuditEntry => ({
  occurred_at: '2026-02-01T10:00:00Z',
  event,
  ...extra,
});

describe('journey', () => {
  it('orders events by pipeline stage regardless of input order', () => {
    const response = at(
      { policy_decision: { scope: 'response', policy_id: 'r', decision: 'allow' } },
      { id: 'response' }
    );
    const gateway = at(
      { policy_decision: { scope: 'gateway', policy_id: 'g', decision: 'allow' } },
      { id: 'gw' }
    );
    const callerTc = at(
      { trust_check: { leg: 'caller', authority_id: 'a', entity_id: 'e', ok: true } },
      { id: 'caller' }
    );

    const steps = buildJourney([response, gateway, callerTc]);
    expect(steps.map(s => s.key)).toEqual(['caller', 'gw', 'response']);
  });

  it('orders the events of one stage by when they occurred', () => {
    const later = at('token_injected', { id: 'later', occurred_at: '2026-02-01T10:00:02Z' });
    const earlier = at('token_injected', { id: 'earlier', occurred_at: '2026-02-01T10:00:01Z' });

    const steps = buildJourney([later, earlier]);

    expect(steps.map(s => [s.key, s.occurred_at])).toEqual([
      ['earlier', '2026-02-01T10:00:01Z'],
      ['later', '2026-02-01T10:00:02Z'],
    ]);
  });

  it('places a self recognition check before policy and the target Trust Check', () => {
    const target = at(
      { trust_check: { leg: 'target', authority_id: 'a', entity_id: 'e', ok: true } },
      { id: 'target' }
    );
    const gateway = at(
      { policy_decision: { scope: 'gateway', policy_id: 'g', decision: 'allow' } },
      { id: 'gw' }
    );
    const self = at(
      { trust_check: { leg: 'managed_agent', authority_id: 'a', entity_id: 'e', ok: true } },
      { id: 'self' }
    );

    const steps = buildJourney([target, gateway, self]);
    expect(steps.map(s => s.key)).toEqual(['self', 'gw', 'target']);
  });

  it('carries tone and a human title from the narrative', () => {
    const steps = buildJourney([
      at(
        {
          policy_decision: {
            scope: 'surface',
            policy_id: 'p',
            decision: 'deny',
            http_method: 'POST',
            http_path: '/x',
          },
        },
        { id: 's' }
      ),
    ]);
    expect(steps[0].tone).toBe('deny');
    expect(steps[0].title).toContain('Denied');
  });
});
