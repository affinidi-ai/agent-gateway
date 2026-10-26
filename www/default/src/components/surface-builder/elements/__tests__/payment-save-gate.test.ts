import { renderHook } from '@testing-library/react';
import { useSurfaceBuilder } from '../../hooks/useSurfaceBuilder';
import type { PaymentNodeConfig } from '../payment/types';
import type { CanvasNode } from '../types';

const base: PaymentNodeConfig = {
  payment_gateway_id: 'gw-1',
  payment_surface_id: 'pay-ch',
  mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] },
};

/** The errors the Save button is gated on, as the surface builder computes them. */
function saveBlockers(config: PaymentNodeConfig, protocol = 'mcp') {
  const nodes: CanvasNode[] = [
    { id: 'payment', type: 'payment', label: '', configured: true, config },
  ];
  const { result } = renderHook(() =>
    useSurfaceBuilder({ nodes, selectedNodeId: null }, { getProtocol: () => protocol })
  );
  return result.current.dependencyErrors.map(e => e.message);
}

describe('what blocks Save on a Payment node', () => {
  it('nothing for a complete agent-pay selection', () => {
    expect(saveBlockers(base)).toEqual([]);
  });

  it.each(['(?=lookahead)', '(a)\\1', '(open'])(
    'nothing for the pattern %s, which only the gateway can judge',
    pattern => {
      expect(
        saveBlockers({ ...base, mcp_payment_triggers: { mode: 'match', patterns: [pattern] } })
      ).toEqual([]);
    }
  );

  it('nothing for a pattern in the syntax only the gateway accepts', () => {
    expect(
      saveBlockers({ ...base, mcp_payment_triggers: { mode: 'exclude', patterns: ['(?i)^free_'] } })
    ).toEqual([]);
  });

  it('nothing for A2A message text that would not compile as a regex', () => {
    expect(
      saveBlockers(
        {
          payment_gateway_id: 'gw-1',
          payment_surface_id: 'pay-ch',
          a2a_method_filters: [{ method: 'message/send', message_patterns: ['(not a regex'] }],
        },
        'a2a'
      )
    ).toEqual([]);
  });

  it.each([500, 999, 120001])('the timeout %s', timeout_ms => {
    expect(saveBlockers({ ...base, timeout_ms })).toEqual([
      'Timeout must be a whole number of milliseconds from 1000 to 120000.',
    ]);
  });

  it.each([1000, 15000, 120000])('nothing for the timeout %s', timeout_ms => {
    expect(saveBlockers({ ...base, timeout_ms })).toEqual([]);
  });

  it('still the missing surface', () => {
    expect(saveBlockers({ payment_gateway_id: 'gw-1' })).toEqual([
      'Select a connected payment gateway and its payment surface',
    ]);
  });

  it('a Match trigger without a non-blank pattern, which the gateway refuses', () => {
    const matchMessage =
      'MCP payment triggers: "Charge tools matching regex" needs at least one pattern. Add one, or choose "All tools".';
    for (const patterns of [[], ['  ']]) {
      expect(saveBlockers({ ...base, mcp_payment_triggers: { mode: 'match', patterns } })).toEqual([
        matchMessage,
      ]);
    }
    expect(
      saveBlockers({ ...base, mcp_payment_triggers: { mode: 'match', patterns: ['^a$'] } })
    ).toEqual([]);
  });

  it('nothing when no trigger is set, because the gateway charges every tool call', () => {
    expect(saveBlockers(base)).toEqual([]);
    expect(
      saveBlockers({ ...base, mcp_payment_triggers: { mode: 'exclude', patterns: [] } })
    ).toEqual([]);
  });
});
