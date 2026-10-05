/**
 * MCP Tool Gating `default_effect` (allow-by-default vs deny-by-default).
 *
 * Covers the wire projection, hydration, completeness, and summary behaviour
 * of the top-level default policy that frames the gate list.
 */

import {
  mcpToolGatingDefinition as def,
  mcpToolGatingConfigToWire,
} from '../mcp-tool-gating/definition';

const gate = {
  id: 'g1',
  name: 'Only reads',
  action: { effect: 'allow', patterns: ['^read_'] },
};

describe('mcp-tool-gating default_effect', () => {
  it('omits default_effect from the wire when allow-by-default', () => {
    expect(mcpToolGatingConfigToWire({ default_effect: 'allow', gates: [gate] })).toEqual({
      gates: [{ id: 'g1', name: 'Only reads', action: { effect: 'allow', patterns: ['^read_'] } }],
    });
  });

  it('emits default_effect=deny alongside gates when deny-by-default', () => {
    expect(mcpToolGatingConfigToWire({ default_effect: 'deny', gates: [gate] })).toEqual({
      default_effect: 'deny',
      gates: [{ id: 'g1', name: 'Only reads', action: { effect: 'allow', patterns: ['^read_'] } }],
    });
  });

  it('emits a deny-all slice (default_effect only) when deny-by-default with no gates', () => {
    expect(mcpToolGatingConfigToWire({ default_effect: 'deny', gates: [] })).toEqual({
      default_effect: 'deny',
    });
  });

  it('is a no-op (undefined) when allow-by-default with no effective gates', () => {
    expect(mcpToolGatingConfigToWire({ default_effect: 'allow', gates: [] })).toBeUndefined();
  });

  it('hydrates default_effect from the wire, defaulting to allow when absent', () => {
    expect(def.configFromPayload?.({ gates: [] }, {})).toEqual({
      default_effect: 'allow',
      gates: [],
    });
    expect(def.configFromPayload?.({ default_effect: 'deny' }, {})).toEqual({
      default_effect: 'deny',
      gates: [],
    });
  });

  it('treats no-gate configs as complete for both defaults (allow all / deny all)', () => {
    expect(def.incompleteReason({ default_effect: 'deny', gates: [] })).toBeNull();
    expect(def.incompleteReason({ default_effect: 'allow', gates: [] })).toBeNull();
    // A gate with no pattern is still incomplete regardless of default.
    expect(
      def.incompleteReason({
        default_effect: 'allow',
        gates: [{ id: 'x', action: { effect: 'deny', patterns: [] } }],
      })
    ).toBe('Every tool gate needs at least one regex pattern');
  });

  it('summarises the default policy', () => {
    expect(def.summary?.({ default_effect: 'deny', gates: [] })).toBe('Deny all');
    expect(def.summary?.({ default_effect: 'deny', gates: [gate] })).toBe(
      'Deny by default · 1 gate'
    );
    expect(def.summary?.({ default_effect: 'allow', gates: [gate] })).toBe('1 gate');
    expect(def.summary?.({ default_effect: 'allow', gates: [] })).toBeNull();
  });
});
