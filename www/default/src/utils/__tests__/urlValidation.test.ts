import { validateUrl, getUrlError, validateTargetEndpoint } from '../urlValidation';

describe('validateUrl', () => {
  it('rejects empty / whitespace input', () => {
    expect(validateUrl('').valid).toBe(false);
    expect(validateUrl('   ').valid).toBe(false);
    expect(validateUrl(undefined).valid).toBe(false);
    expect(validateUrl(null).valid).toBe(false);
    expect(validateUrl(123 as unknown as string).valid).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(validateUrl('not a url').valid).toBe(false);
    expect(validateUrl('http://').valid).toBe(false);
    expect(validateUrl('://example.com').valid).toBe(false);
  });

  it('rejects structurally invalid hostnames the URL parser would otherwise accept', () => {
    expect(validateUrl('https://1........1......').valid).toBe(false);
    expect(validateUrl('https://example..com').valid).toBe(false);
    expect(validateUrl('https://-example.com').valid).toBe(false);
    expect(validateUrl('https://example-.com').valid).toBe(false);
    expect(validateUrl('https://example.123').valid).toBe(false); // numeric TLD
    expect(validateUrl('https://exa_mple.com').valid).toBe(false); // underscore
    expect(validateUrl('https://' + 'a'.repeat(64) + '.com').valid).toBe(false); // label > 63
    expect(validateUrl('https://999.999.999.999').valid).toBe(false); // IPv4 octet out of range
  });

  it('accepts well-formed hostnames including single-label and trailing dot', () => {
    expect(validateUrl('http://localhost').valid).toBe(true);
    expect(validateUrl('https://example.com.').valid).toBe(true);
    expect(validateUrl('https://sub.example.co.uk').valid).toBe(true);
  });

  it('accepts valid http and https URLs', () => {
    const ok = validateUrl('https://example.com/path?q=1');
    expect(ok.valid).toBe(true);
    expect(ok.normalized).toBe('https://example.com/path?q=1');
    expect(validateUrl('http://example.com').valid).toBe(true);
  });

  it('rejects disallowed schemes by default', () => {
    expect(validateUrl('ftp://example.com').valid).toBe(false);
    // eslint-disable-next-line no-script-url
    expect(validateUrl('javascript:alert(1)').valid).toBe(false);
    expect(validateUrl('file:///etc/passwd').valid).toBe(false);
    expect(validateUrl('data:text/html,<script>').valid).toBe(false);
  });

  it('honors allowedSchemes option', () => {
    expect(validateUrl('ws://example.com/socket', { allowedSchemes: ['ws', 'wss'] }).valid).toBe(
      true
    );
    expect(validateUrl('https://example.com', { allowedSchemes: ['ws', 'wss'] }).valid).toBe(false);
  });

  it('requireHttps forces https only', () => {
    expect(validateUrl('http://example.com', { requireHttps: true }).valid).toBe(false);
    expect(validateUrl('https://example.com', { requireHttps: true }).valid).toBe(true);
  });

  it('rejects embedded credentials by default', () => {
    expect(validateUrl('https://user:pass@example.com').valid).toBe(false);
    expect(validateUrl('https://user@example.com').valid).toBe(false);
  });

  it('allows credentials when explicitly opted in', () => {
    expect(validateUrl('https://user:pass@example.com', { allowCredentials: true }).valid).toBe(
      true
    );
  });

  it('rejects whitespace and control characters embedded in URL', () => {
    expect(validateUrl('https://example.com/\nfoo').valid).toBe(false);
    expect(validateUrl('https://exa mple.com').valid).toBe(false);
  });

  it('enforces max length', () => {
    const long = 'https://example.com/' + 'a'.repeat(3000);
    expect(validateUrl(long).valid).toBe(false);
    expect(validateUrl(long, { maxLength: 5000 }).valid).toBe(true);
  });

  describe('blockPrivateHosts', () => {
    const opts = { blockPrivateHosts: true };

    it('blocks loopback', () => {
      expect(validateUrl('http://localhost', opts).valid).toBe(false);
      expect(validateUrl('http://api.localhost', opts).valid).toBe(false);
      expect(validateUrl('http://127.0.0.1', opts).valid).toBe(false);
      expect(validateUrl('http://127.1.2.3', opts).valid).toBe(false);
      expect(validateUrl('http://[::1]/', opts).valid).toBe(false);
    });

    it('blocks RFC1918 private ranges', () => {
      expect(validateUrl('http://10.0.0.1', opts).valid).toBe(false);
      expect(validateUrl('http://172.16.0.1', opts).valid).toBe(false);
      expect(validateUrl('http://172.31.255.255', opts).valid).toBe(false);
      expect(validateUrl('http://192.168.1.1', opts).valid).toBe(false);
    });

    it('blocks link-local and metadata addresses', () => {
      expect(validateUrl('http://169.254.169.254/latest/meta-data', opts).valid).toBe(false);
      expect(validateUrl('http://[fe80::1]/', opts).valid).toBe(false);
    });

    it('blocks 0.0.0.0 and multicast', () => {
      expect(validateUrl('http://0.0.0.0', opts).valid).toBe(false);
      expect(validateUrl('http://239.0.0.1', opts).valid).toBe(false);
    });

    it('allows public hosts', () => {
      expect(validateUrl('https://example.com', opts).valid).toBe(true);
      expect(validateUrl('https://8.8.8.8', opts).valid).toBe(true);
    });

    it('allows private host outside 172.16/12 boundary', () => {
      expect(validateUrl('http://172.32.0.1', opts).valid).toBe(true);
      expect(validateUrl('http://172.15.0.1', opts).valid).toBe(true);
    });
  });
});

describe('getUrlError', () => {
  it('returns null when valid', () => {
    expect(getUrlError('https://example.com')).toBeNull();
  });

  it('returns the error string when invalid', () => {
    expect(getUrlError('nope')).toMatch(/valid url/i);
  });
});

describe('validateTargetEndpoint', () => {
  it('accepts http(s) URLs', () => {
    expect(validateTargetEndpoint('https://api.example.com').valid).toBe(true);
  });

  it('accepts did: identifiers', () => {
    expect(validateTargetEndpoint('did:web:example.com').valid).toBe(true);
    expect(validateTargetEndpoint('did:webvh:scid:example.com:agent').valid).toBe(true);
  });

  it('rejects malformed did:', () => {
    expect(validateTargetEndpoint('did:').valid).toBe(false);
    expect(validateTargetEndpoint('did:web').valid).toBe(false);
  });

  it('accepts fabric:// references', () => {
    expect(validateTargetEndpoint('fabric://gateway-1/channel-2').valid).toBe(true);
  });

  it('rejects empty fabric://', () => {
    expect(validateTargetEndpoint('fabric://').valid).toBe(false);
  });

  it('rejects other schemes', () => {
    expect(validateTargetEndpoint('ftp://example.com').valid).toBe(false);
    // eslint-disable-next-line no-script-url
    expect(validateTargetEndpoint('javascript:alert(1)').valid).toBe(false);
  });
});
