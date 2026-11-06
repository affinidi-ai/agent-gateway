import { transitPointProtocol } from '../transit-point/TransitPointPanel';
import { surfaceOptionLabel } from '../_shared/GatewaySurfacePicker';
import {
  parseFabricEndpoint,
  surfaceMatchesProtocol,
  surfacesErrorMessage,
} from '../_shared/useGatewaySurfaces';

describe('transitPointProtocol', () => {
  it('extracts a2a from transit-point-a2a', () => {
    expect(transitPointProtocol('transit-point-a2a')).toBe('a2a');
  });

  it('extracts mcp from transit-point-mcp', () => {
    expect(transitPointProtocol('transit-point-mcp')).toBe('mcp');
  });

  it('extracts ap2 from transit-point-ap2', () => {
    expect(transitPointProtocol('transit-point-ap2')).toBe('ap2');
  });

  it('returns null for non-transit-point node types', () => {
    expect(transitPointProtocol('access-point')).toBeNull();
    expect(transitPointProtocol('target')).toBeNull();
  });

  it('returns null for undefined', () => {
    expect(transitPointProtocol(undefined)).toBeNull();
  });
});

describe('surfaceMatchesProtocol', () => {
  const surfaces = [
    { config_id: 'ch-1', protocol: 'a2a' },
    { config_id: 'ch-2', protocol: 'mcp' },
    { config_id: 'ch-3', protocol: 'A2A' },
    { config_id: 'ch-4' },
  ];
  const ids = (protocol: string | null) =>
    surfaces.filter(s => surfaceMatchesProtocol(s, protocol)).map(s => s.config_id);

  it('keeps the matching protocol, ignoring case, and surfaces with no protocol', () => {
    expect(ids('a2a')).toEqual(['ch-1', 'ch-3', 'ch-4']);
  });

  it('drops every surface of another protocol', () => {
    expect(ids('didcomm')).toEqual(['ch-4']);
  });

  it('keeps every surface without a protocol to match', () => {
    expect(ids(null)).toEqual(['ch-1', 'ch-2', 'ch-3', 'ch-4']);
  });
});

describe('parseFabricEndpoint', () => {
  it('splits the gateway and the surface', () => {
    expect(parseFabricEndpoint('fabric://gw-1/surface-1$eu')).toEqual({
      gatewayId: 'gw-1',
      surfaceId: 'surface-1$eu',
    });
    expect(parseFabricEndpoint('fabric://gw-1')).toEqual({ gatewayId: 'gw-1', surfaceId: '' });
  });

  it('returns null for any other endpoint', () => {
    expect(parseFabricEndpoint('https://example.com/a')).toBeNull();
    expect(parseFabricEndpoint('proxy://p1')).toBeNull();
    expect(parseFabricEndpoint(undefined)).toBeNull();
  });
});

describe('surfacesErrorMessage', () => {
  const failure = (message: string, status?: number) =>
    Object.assign(new Error(message), { status });

  it('says an unconnected gateway cannot be listed', () => {
    expect(surfacesErrorMessage(failure('Service Unavailable', 503))).toMatch(/not connected/);
    expect(surfacesErrorMessage(failure('Gateway not connected'))).toMatch(/not connected/);
  });

  it('says a missing gateway was not found', () => {
    expect(surfacesErrorMessage(failure('Not Found', 404))).toBe(
      'Gateway not found. It may have been removed.'
    );
  });

  it('never shows the raw error text', () => {
    const message = surfacesErrorMessage(failure('stack trace at handler.rs:12', 500));
    expect(message).toBe('Could not load surfaces from this gateway. Try Refresh.');
  });
});

describe('surfaceOptionLabel', () => {
  const surface = (config_id: string, name: string) => ({
    config_id,
    name,
    tags: [],
    is_payment_surface: null,
    has_manifest: false,
  });

  it('adds a short id to a named surface', () => {
    expect(surfaceOptionLabel(surface('0123456789abcdef', 'Weather'))).toBe('Weather (01234567…)');
    expect(surfaceOptionLabel(surface('short', 'Weather'))).toBe('Weather (short)');
  });

  it('shows the id alone when the name is the id', () => {
    expect(surfaceOptionLabel(surface('pay-ch', 'pay-ch'))).toBe('pay-ch');
  });
});
