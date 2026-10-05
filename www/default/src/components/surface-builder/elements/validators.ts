/**
 * Shared field validators for element definitions.
 * Each helper returns either an error object (for `validate()` arrays) or null.
 */

// Accepts ordinary http(s) URLs as well as the gateway-to-gateway
// `fabric://{gateway_id}/{channel_id}` form used when the target is
// another gateway channel, the `proxy://{proxy_id}` form used when
// the target is a managed MCP proxy fronting a REST API, and the
// `a2a-proxy://{proxy_id}` form used for A2A Proxy targets.
const URL_RE = /^(https?|fabric|proxy|a2a-proxy):\/\/\S+$/i;

export function urlError(
  field: string,
  value: unknown,
  label = 'Endpoint'
): { field: string; message: string } | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (!URL_RE.test(value))
    return {
      field,
      message: `${label} must be a valid http(s)://, fabric://, proxy:// or a2a-proxy:// URL`,
    };
  return null;
}

/**
 * Validate "host" or "host:port". Port is optional. Host must be a non-empty
 * sequence of allowed chars (letters, digits, dots, hyphens). When a port is
 * present it must be 1..65535.
 */
const HOST_PORT_RE = /^[A-Za-z0-9._-]+(:\d{1,5})?$/;
export function hostPortError(
  field: string,
  value: unknown,
  label = 'Listen address'
): { field: string; message: string } | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (!HOST_PORT_RE.test(value)) return { field, message: `${label} must be host or host:port` };
  if (value.includes(':')) {
    const [, port] = value.split(':');
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return { field, message: `${label} port must be between 1 and 65535` };
    }
  }
  return null;
}

export function positiveIntError(
  field: string,
  value: unknown,
  label: string
): { field: string; message: string } | null {
  if (value === undefined || value === null || value === '') return null;
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
    return { field, message: `${label} must be a positive integer` };
  }
  return null;
}

/** Normalize a route-like path so it always begins with '/'. Trims whitespace; empty stays empty. */
export function normalizeRoute(value: string | undefined | null): string {
  if (!value) return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}
