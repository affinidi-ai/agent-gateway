const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export const MAX_REQUIRED_SCOPES = 32;
export const MAX_SCOPE_LENGTH = 128;

export function validateScopeToken(token: string, existing: readonly string[]): string | null {
  if (!token) return 'Enter a scope.';
  if (token.length > MAX_SCOPE_LENGTH) {
    return `A scope can be at most ${MAX_SCOPE_LENGTH} characters.`;
  }
  if (!SCOPE_TOKEN.test(token)) {
    return 'A scope cannot contain spaces, double quotes or backslashes.';
  }
  if (existing.includes(token)) return `${token} is already required.`;
  if (existing.length >= MAX_REQUIRED_SCOPES) {
    return `At most ${MAX_REQUIRED_SCOPES} scopes can be required.`;
  }
  return null;
}

/** The scopes a caller-auth config requires, as `buildPayload` sends them. */
export function readRequiredScopes(config: Record<string, unknown>): string[] {
  return Array.isArray(config.required_scopes)
    ? config.required_scopes.filter((s): s is string => typeof s === 'string')
    : [];
}

/** Why a stored list of required scopes would be refused by the gateway, or null. */
export function requiredScopesProblem(scopes: readonly string[]): string | null {
  if (scopes.length > MAX_REQUIRED_SCOPES) {
    return `At most ${MAX_REQUIRED_SCOPES} scopes can be required.`;
  }
  for (let i = 0; i < scopes.length; i++) {
    const problem = validateScopeToken(scopes[i], scopes.slice(0, i));
    if (problem) return problem;
  }
  return null;
}
