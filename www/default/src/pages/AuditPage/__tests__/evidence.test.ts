import { signedVpEntry, traceSiblings } from '../evidence';
import type { AuditEntry } from '../types';

const at = (event: AuditEntry['event'], extra: Partial<AuditEntry> = {}): AuditEntry => ({
  timestamp: '2026-02-01T10:00:00Z',
  event,
  ...extra,
});

describe('evidence', () => {
  it('groups siblings by trace_id and falls back to the lone entry', () => {
    const a = at('token_injected', { trace_id: 't1', id: 'a' });
    const b = at('vp_injected', { trace_id: 't1', id: 'b' });
    const c = at('token_injected', { trace_id: 't2', id: 'c' });
    const lone = at('token_injected', { id: 'd' });

    expect(traceSiblings([a, b, c], a).map(e => e.id)).toEqual(['a', 'b']);
    expect(traceSiblings([a, b, c, lone], lone).map(e => e.id)).toEqual(['d']);
  });

  it('finds the sibling carrying the signed VP', () => {
    const siblings: AuditEntry[] = [
      at('token_injected', { id: 'a' }),
      at('vp_injected', { id: 'b', vp_jwt: 'h.p.s' }),
    ];
    expect(signedVpEntry(siblings)?.id).toBe('b');
    expect(signedVpEntry([at('token_injected', { id: 'x' })])).toBeNull();
  });
});
