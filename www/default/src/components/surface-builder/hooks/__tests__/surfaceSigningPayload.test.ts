import { renderHook } from '@testing-library/react';
import { useSurfaceBuilder } from '../useSurfaceBuilder';
import type { SurfaceSigning } from '../../elements/types';

/**
 * A surface's signing choice has to survive the trip to the server.
 *
 * It did not. `buildPayload`'s `meta` type never declared `signing`, while the
 * body that assembles the payload read it. TypeScript would have rejected
 * that, but the dashboard build transpiles rather than type-checks, so it
 * compiled and the value was permanently `undefined`: the choice rendered in
 * the panel, marked the form dirty, and was dropped on save — reappearing as
 * "Inherit the appliance default" after a reload.
 *
 * Asserted here rather than against `registry.buildPayload`, which was never
 * the broken part: it read `surfaceMeta.signing` correctly all along, so a
 * test at that level passes with or without the fix and proves nothing.
 */
const initial = {
  nodes: [
    {
      id: 'access-point',
      type: 'access-point',
      label: 'AP',
      configured: true,
      config: { route: '/api' },
    },
    {
      id: 'target',
      type: 'target',
      label: 'T',
      configured: true,
      config: { endpoint: 'http://example.com' },
    },
  ],
} as never;

const meta = (signing?: SurfaceSigning) => ({
  name: 'signing surface',
  tags: [],
  protocol: 'a2a',
  status: 'active',
  ...(signing ? { signing } : {}),
});

describe('useSurfaceBuilder buildPayload — surface signing', () => {
  it('sends the chosen backend', () => {
    const signing: SurfaceSigning = {
      backend: 'vta',
      connection_id: 'vta-a',
      context_id: 'ctx:_global/surface-1',
      key_id: 'gateway-jwt-1',
    };
    const { result } = renderHook(() => useSurfaceBuilder(initial));
    expect(result.current.buildPayload(meta(signing)).signing).toEqual(signing);
  });

  it('sends an explicit local choice, which is not the same as inheriting', () => {
    const { result } = renderHook(() => useSurfaceBuilder(initial));
    expect(result.current.buildPayload(meta({ backend: 'local' })).signing).toEqual({
      backend: 'local',
    });
  });

  it('omits the block when nothing is chosen', () => {
    // Every field absent means "inherit": the backend's resolver treats a
    // missing block and an empty one as different things.
    const { result } = renderHook(() => useSurfaceBuilder(initial));
    expect(result.current.buildPayload(meta())).not.toHaveProperty('signing');
    expect(result.current.buildPayload(meta({}))).not.toHaveProperty('signing');
  });
});
