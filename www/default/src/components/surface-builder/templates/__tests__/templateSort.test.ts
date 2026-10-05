import {
  sortTemplatesForDisplay,
  templateSortPriority,
  getTemplateProtocol,
  getTemplateProtocolBadge,
  templateMatchesProtocol,
} from '../templateSort';
import type { SurfaceTemplate } from '../../../../api';

const t = (over: Partial<SurfaceTemplate>): SurfaceTemplate => ({
  id: over.id ?? Math.random().toString(36).slice(2),
  name: 'unnamed',
  ...over,
});

describe('templateSortPriority', () => {
  it('defaults missing values to Number.MAX_SAFE_INTEGER', () => {
    expect(templateSortPriority(t({}))).toBe(Number.MAX_SAFE_INTEGER);
    expect(templateSortPriority(t({ sort_priority: 0 }))).toBe(0);
    expect(templateSortPriority(t({ sort_priority: -5 }))).toBe(-5);
  });
});

describe('sortTemplatesForDisplay', () => {
  it('orders by priority ascending then by case-insensitive name', () => {
    const out = sortTemplatesForDisplay([
      t({ id: 'a', name: 'Banana', sort_priority: 20 }),
      t({ id: 'b', name: 'Apple', sort_priority: 20 }),
      t({ id: 'c', name: 'Cherry', sort_priority: 10 }),
      t({ id: 'd', name: 'date' /* no priority */ }),
      t({ id: 'e', name: 'Elderberry', sort_priority: 30 }),
    ]);
    expect(out.map(x => x.id)).toEqual(['c', 'b', 'a', 'e', 'd']);
  });

  it('does not mutate the input list', () => {
    const input = [
      t({ id: 'a', name: 'A', sort_priority: 99 }),
      t({ id: 'b', name: 'B', sort_priority: 1 }),
    ];
    const snapshot = input.map(x => x.id);
    sortTemplatesForDisplay(input);
    expect(input.map(x => x.id)).toEqual(snapshot);
  });
});

describe('getTemplateProtocol', () => {
  it('reads from surface.access_point.protocol first', () => {
    expect(
      getTemplateProtocol(
        t({
          tags: ['mcp'],
          surface: { access_point: { protocol: 'A2A' } },
        })
      )
    ).toBe('a2a');
  });

  it('falls back to known protocol tags when surface is absent', () => {
    expect(getTemplateProtocol(t({ tags: ['identity', 'mcp', 'trust'] }))).toBe('mcp');
  });

  it('returns null when nothing recognisable is found', () => {
    expect(getTemplateProtocol(t({ tags: ['identity', 'trust'] }))).toBeNull();
    expect(getTemplateProtocol(t({}))).toBeNull();
  });
});

describe('getTemplateProtocolBadge', () => {
  it('returns the canonical badge for known protocols', () => {
    const b = getTemplateProtocolBadge(t({ surface: { access_point: { protocol: 'a2a' } } }));
    expect(b?.key).toBe('a2a');
    expect(b?.label).toBe('A2A');
    expect(b?.badgeClass).toBe('text-bg-primary');
  });

  it('returns null for unknown protocols (no synthesised fallback)', () => {
    const b = getTemplateProtocolBadge(
      t({ surface: { access_point: { protocol: 'future-proto' } } })
    );
    expect(b).toBeNull();
  });

  it('returns null when no protocol can be inferred', () => {
    expect(getTemplateProtocolBadge(t({}))).toBeNull();
  });
});

describe('templateMatchesProtocol', () => {
  it('matches an MCP-tagged partial on an MCP surface', () => {
    expect(templateMatchesProtocol(t({ tags: ['mcp', 'security'] }), 'mcp')).toBe(true);
  });

  it('excludes an MCP-tagged partial from an A2A surface', () => {
    expect(templateMatchesProtocol(t({ tags: ['mcp', 'security'] }), 'a2a')).toBe(false);
  });

  it('keeps an A2A-tagged partial off non-A2A surfaces', () => {
    expect(templateMatchesProtocol(t({ tags: ['a2a', 'metadata'] }), 'a2a')).toBe(true);
    expect(templateMatchesProtocol(t({ tags: ['a2a', 'metadata'] }), 'mcp')).toBe(false);
  });

  it('keeps an untagged partial available across protocols', () => {
    expect(templateMatchesProtocol(t({ tags: ['security'] }), 'a2a')).toBe(true);
  });
});
