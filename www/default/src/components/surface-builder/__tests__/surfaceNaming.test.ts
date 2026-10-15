import { defaultSurfaceName } from '../surfaceNaming';

const surface = (name: string, protocol: string) => ({ name, access_point: { protocol } });

describe('defaultSurfaceName', () => {
  it('names the first surface of a protocol <protocol>_surface_1', () => {
    expect(defaultSurfaceName('a2a', [])).toBe('a2a_surface_1');
    expect(defaultSurfaceName('mcp', [])).toBe('mcp_surface_1');
    expect(defaultSurfaceName('ap2', [])).toBe('ap2_surface_1');
  });

  it('numbers after the existing surfaces of the same protocol', () => {
    const existing = [surface('a2a_surface_1', 'a2a'), surface('Payments agent', 'a2a')];
    expect(defaultSurfaceName('a2a', existing)).toBe('a2a_surface_3');
  });

  it('does not count surfaces of other protocols', () => {
    const existing = [surface('a2a_surface_1', 'a2a'), surface('a2a_surface_2', 'a2a')];
    expect(defaultSurfaceName('mcp', existing)).toBe('mcp_surface_1');
  });

  it('skips a name that is already taken', () => {
    const existing = [surface('a2a_surface_2', 'a2a'), surface('a2a_surface_3', 'mcp')];
    expect(defaultSurfaceName('a2a', existing)).toBe('a2a_surface_4');
  });

  it('treats taken names case-insensitively and ignores surrounding spaces', () => {
    expect(defaultSurfaceName('mcp', [surface('  MCP_Surface_1 ', 'a2a')])).toBe('mcp_surface_2');
  });

  it('tolerates surfaces without a name or access point', () => {
    expect(defaultSurfaceName('a2a', [{}, { name: undefined }])).toBe('a2a_surface_1');
  });

  it('ignores a name that is not a string', () => {
    expect(defaultSurfaceName('a2a', [{ name: 42, access_point: { protocol: 'a2a' } }])).toBe(
      'a2a_surface_2'
    );
  });
});
