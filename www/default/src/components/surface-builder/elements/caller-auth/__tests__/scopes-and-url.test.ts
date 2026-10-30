import {
  MAX_REQUIRED_SCOPES,
  readRequiredScopes,
  requiredScopesProblem,
  validateScopeToken,
} from '../scopes';

describe('validateScopeToken', () => {
  it('accepts RFC 6749 scope tokens', () => {
    expect(validateScopeToken('agent:invoke', [])).toBeNull();
    expect(validateScopeToken('https://api.example.com/read', [])).toBeNull();
    expect(validateScopeToken('x'.repeat(128), [])).toBeNull();
  });

  it('rejects empty, spaced, quoted, backslashed, long, duplicate and surplus entries', () => {
    expect(validateScopeToken('', [])).toMatch(/Enter a scope/);
    expect(validateScopeToken('a b', [])).toMatch(/cannot contain/);
    expect(validateScopeToken('a"b', [])).toMatch(/cannot contain/);
    expect(validateScopeToken('a\\b', [])).toMatch(/cannot contain/);
    expect(validateScopeToken('x'.repeat(129), [])).toMatch(/128/);
    expect(validateScopeToken('read', ['read'])).toBe('read is already required.');
    const full = Array.from({ length: MAX_REQUIRED_SCOPES }, (_, i) => `s${i}`);
    expect(validateScopeToken('extra', full)).toMatch(/At most 32/);
  });
});

describe('readRequiredScopes', () => {
  it('reads the string entries of the config', () => {
    expect(readRequiredScopes({ required_scopes: ['a', 'b'] })).toEqual(['a', 'b']);
    expect(readRequiredScopes({ required_scopes: ['a', 3, null] })).toEqual(['a']);
  });

  it('reads nothing when the field is absent or not a list', () => {
    expect(readRequiredScopes({})).toEqual([]);
    expect(readRequiredScopes({ required_scopes: 'a' })).toEqual([]);
  });
});

describe('requiredScopesProblem', () => {
  it('accepts a list the gateway accepts', () => {
    expect(requiredScopesProblem([])).toBeNull();
    expect(requiredScopesProblem(['agent:invoke', 'read'])).toBeNull();
    expect(
      requiredScopesProblem(Array.from({ length: MAX_REQUIRED_SCOPES }, (_, i) => `s${i}`))
    ).toBeNull();
  });

  it('flags a list the gateway refuses', () => {
    expect(
      requiredScopesProblem(Array.from({ length: MAX_REQUIRED_SCOPES + 1 }, (_, i) => `s${i}`))
    ).toBe('At most 32 scopes can be required.');
    expect(requiredScopesProblem(['read', 'read'])).toBe('read is already required.');
    expect(requiredScopesProblem(['ok', 'not ok'])).toMatch(/cannot contain/);
    expect(requiredScopesProblem([''])).toBe('Enter a scope.');
  });
});
