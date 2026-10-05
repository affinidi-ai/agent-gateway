/**
 * URL validation utilities used across forms that accept user-provided URLs.
 *
 * Goals:
 *  - Reject malformed input via the WHATWG URL parser instead of weak regexes.
 *  - Restrict allowed schemes per use-case (default: http / https).
 *  - Block embedded credentials (`https://user:pass@host`).
 *  - Optionally block private / loopback / link-local hosts to mitigate SSRF
 *    when the gateway will fetch or forward to the URL server-side.
 *  - Cap length to avoid pathological inputs.
 */

export interface UrlValidationOptions {
  /** Allowed URL schemes (without trailing colon). Defaults to ['http', 'https']. */
  allowedSchemes?: string[];
  /** Require `https:` only (overrides `allowedSchemes` for the http/https case). */
  requireHttps?: boolean;
  /** Block private / loopback / link-local / metadata hosts. Defaults to false. */
  blockPrivateHosts?: boolean;
  /** Maximum length of the URL string. Defaults to 2048. */
  maxLength?: number;
  /** Allow embedded userinfo (`user:pass@host`). Defaults to false. */
  allowCredentials?: boolean;
}

export interface UrlValidationResult {
  valid: boolean;
  /** Human-readable error suitable to show in the UI. Empty when valid. */
  error: string;
  /** Normalized URL (parsed and re-serialized). Present only when valid. */
  normalized?: string;
}

const DEFAULT_MAX_LENGTH = 2048;
const DEFAULT_SCHEMES = ['http', 'https'];

/** IPv4 literal check. */
function isIpv4(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** RFC 1123 DNS label: 1–63 chars, alphanumeric, hyphens allowed but not at edges. */
const HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/**
 * Validate that a host is a syntactically reasonable IP literal or DNS name.
 * The WHATWG URL parser is permissive (e.g. it happily accepts
 * `https://1........1......`), so we apply stricter structural checks here.
 */
function isValidHostname(host: string): boolean {
  if (!host) return false;

  // IPv6 literal — `URL.hostname` strips the surrounding brackets and any
  // valid v6 address contains a colon.
  if (host.includes(':')) {
    return /^[0-9a-f:.]+$/i.test(host);
  }

  if (isIpv4(host)) {
    return host.split('.').every(p => {
      const n = Number(p);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }

  if (host.length > 253) return false;
  // Trailing dot (FQDN root) is allowed; strip before label validation.
  const stripped = host.endsWith('.') ? host.slice(0, -1) : host;
  const labels = stripped.split('.');
  if (labels.some(l => l.length === 0 || !HOSTNAME_LABEL.test(l))) return false;

  // Multi-label DNS names must have a TLD with at least one letter — this
  // rejects numeric-only "domains" that aren't valid IPv4 addresses.
  if (labels.length > 1) {
    const tld = labels[labels.length - 1];
    if (!/[a-z]/i.test(tld)) return false;
  }

  return true;
}

/** Returns true for hosts that should not be reachable from a server-side fetcher. */
function isPrivateHost(host: string): boolean {
  if (!host) return true;
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');

  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === '0.0.0.0') return true;

  // IPv6 loopback / link-local / unique-local.
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return true;
  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  if (h.startsWith('::ffff:')) {
    return isPrivateHost(h.substring(7));
  }

  if (isIpv4(h)) {
    const parts = h.split('.').map(p => parseInt(p, 10));
    if (parts.some(p => Number.isNaN(p) || p < 0 || p > 255)) return true;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
  }

  return false;
}

/**
 * Validate a user-provided URL string.
 *
 * Returns a result object rather than throwing so callers can show the error
 * message inline. On success, `normalized` contains the parsed URL re-serialized
 * via the WHATWG URL parser (trims whitespace, lowercases the scheme/host, etc.).
 */
export function validateUrl(
  input: unknown,
  options: UrlValidationOptions = {}
): UrlValidationResult {
  const {
    requireHttps = false,
    blockPrivateHosts = false,
    maxLength = DEFAULT_MAX_LENGTH,
    allowCredentials = false,
  } = options;

  const allowedSchemes = requireHttps ? ['https'] : (options.allowedSchemes ?? DEFAULT_SCHEMES);

  if (typeof input !== 'string') {
    return { valid: false, error: 'URL is required' };
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return { valid: false, error: 'URL is required' };
  }

  if (trimmed.length > maxLength) {
    return { valid: false, error: `URL must be at most ${maxLength} characters` };
  }

  // Reject control / whitespace inside the URL — the parser is lenient here.
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) {
    return { valid: false, error: 'URL must not contain whitespace or control characters' };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Please enter a valid URL' };
  }

  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
  if (!allowedSchemes.includes(scheme)) {
    const list = allowedSchemes.map(s => `${s}://`).join(', ');
    return { valid: false, error: `URL must use one of: ${list}` };
  }

  // For http(s) URLs, host is mandatory. Schemes like `did:` legitimately have no host.
  const httpLike = scheme === 'http' || scheme === 'https';
  if (httpLike && !parsed.hostname) {
    return { valid: false, error: 'URL must include a host' };
  }

  if (httpLike && !isValidHostname(parsed.hostname)) {
    return { valid: false, error: 'URL must include a valid host name' };
  }

  if (!allowCredentials && (parsed.username || parsed.password)) {
    return { valid: false, error: 'URL must not contain credentials' };
  }

  if (blockPrivateHosts && httpLike && isPrivateHost(parsed.hostname)) {
    return {
      valid: false,
      error:
        'URL must point to a public host (private, loopback, or link-local addresses are not allowed)',
    };
  }

  return { valid: true, error: '', normalized: parsed.toString() };
}

/**
 * Convenience wrapper that returns just the error message (or `null` when valid).
 * Useful for inline form-field validators.
 */
export function getUrlError(input: unknown, options?: UrlValidationOptions): string | null {
  const result = validateUrl(input, options);
  return result.valid ? null : result.error;
}

/**
 * Validate a "target endpoint" string that may also be a `did:` or `fabric://`
 * reference in addition to http(s). Used by channel configuration.
 */
export function validateTargetEndpoint(input: unknown): UrlValidationResult {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    // Lightweight checks for non-URL schemes the WHATWG parser handles loosely.
    if (trimmed.startsWith('did:')) {
      if (!/^did:[a-z0-9]+:[^\s]+$/i.test(trimmed)) {
        return { valid: false, error: 'Invalid did: identifier' };
      }
      return { valid: true, error: '', normalized: trimmed };
    }
    if (trimmed.startsWith('fabric://')) {
      const rest = trimmed.substring('fabric://'.length);
      if (!rest || rest.includes(' ')) {
        return { valid: false, error: 'Invalid fabric:// reference' };
      }
      return { valid: true, error: '', normalized: trimmed };
    }
  }
  return validateUrl(input, { allowedSchemes: ['http', 'https'] });
}
