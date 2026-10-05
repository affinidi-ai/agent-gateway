import type { RequiredHeader } from '../../types';

export {
  accessTokenExpiryBounds,
  toLocalDateTimeInput,
  validateAccessTokenExpiry,
} from '../EditAccessTokenPage/accessTokenExpiry';

export const ACCESS_TOKEN_RESOURCE_KINDS = [
  'secrets',
  'certificates',
  'api-keys',
  'surfaces',
  'gateways',
  'connection-points',
  'mediators',
  'mcp-proxies',
  'a2a-proxies',
  'trust-registries',
  'issuers',
  'authorities',
  'integrations',
  'policy-definitions',
  'surface-templates',
  'credential-providers',
  'jwt-verification-strategies',
  'sts-clients',
] as const;

export type AccessTokenResourceKind = (typeof ACCESS_TOKEN_RESOURCE_KINDS)[number];

export type TenantInference =
  | { mode: 'appliance' }
  | { mode: 'tenant'; headerName: string }
  | { mode: 'invalid'; headerNames: string[] };

export interface ScopePreview {
  allowed: boolean;
  target: string;
  effectivePattern?: string;
  tenantId?: string;
  errors: string[];
}

const PLACEHOLDER_RE = /\$\{([A-Za-z0-9_-]+)\}/g;
const TENANT_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const CANONICAL_PATTERN_EXAMPLE = [
  'TENANT:',
  '$',
  '{header}:<resource-kind>:<resource-id-pattern>',
].join('');
const CANONICAL_PATTERN_ERROR = `A non-empty resource pattern must use ${CANONICAL_PATTERN_EXAMPLE}.`;

const anchored = (source: string): RegExp | null => {
  try {
    return new RegExp(`^(?:${source})$`, 's');
  } catch {
    return null;
  }
};

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function placeholderNames(pattern: string): string[] {
  const names = new Set<string>();
  for (const match of pattern.matchAll(PLACEHOLDER_RE)) {
    names.add(match[1].toLowerCase());
  }
  return [...names];
}

export function inferTenantSelection(pattern: string): TenantInference {
  if (!pattern.trim()) return { mode: 'appliance' };
  const matches = [...pattern.matchAll(PLACEHOLDER_RE)];
  const names = placeholderNames(pattern);
  if (matches.length === 1 && names.length === 1) {
    return { mode: 'tenant', headerName: names[0] };
  }
  return { mode: 'invalid', headerNames: names };
}

export function canonicalResourceTarget(
  tenantId: string,
  resourceKind: AccessTokenResourceKind,
  resourceId: string
): string {
  return `TENANT:${tenantId}:${resourceKind}:${resourceId}`;
}

const splitTopLevelAlternatives = (selector: string): string[] => {
  const alternatives: string[] = [];
  let start = 0;
  let depth = 0;
  let inClass = false;
  let escaped = false;

  for (let index = 0; index < selector.length; index += 1) {
    const character = selector[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') escaped = true;
    else if (character === '[' && !inClass) inClass = true;
    else if (character === ']' && inClass) inClass = false;
    else if (character === '(' && !inClass) depth += 1;
    else if (character === ')' && !inClass) depth = Math.max(0, depth - 1);
    else if (character === '|' && !inClass && depth === 0) {
      alternatives.push(selector.slice(start, index));
      start = index + 1;
    }
  }
  alternatives.push(selector.slice(start));
  return alternatives;
};

const outerNoncapturingGroup = (selector: string): string | undefined => {
  if (!selector.startsWith('(?:')) return undefined;
  let depth = 0;
  let inClass = false;
  let escaped = false;

  for (let index = 0; index < selector.length; index += 1) {
    const character = selector[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') escaped = true;
    else if (character === '[' && !inClass) inClass = true;
    else if (character === ']' && inClass) inClass = false;
    else if (character === '(' && !inClass) depth += 1;
    else if (character === ')' && !inClass) {
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        return index === selector.length - 1 ? selector.slice(3, index) : undefined;
      }
    }
  }
  return undefined;
};

const canonicalResourcePatternError = (pattern: string): string | undefined => {
  const matches = [...pattern.matchAll(PLACEHOLDER_RE)];
  if (matches.length !== 1 || matches[0].index !== 'TENANT:'.length) {
    return CANONICAL_PATTERN_ERROR;
  }
  const placeholder = matches[0][0];
  const selectorStart = 'TENANT:'.length + placeholder.length;
  if (!pattern.startsWith('TENANT:') || pattern[selectorStart] !== ':') {
    return CANONICAL_PATTERN_ERROR;
  }

  const selector = pattern.slice(selectorStart + 1);
  const groupBody = outerNoncapturingGroup(selector);
  const alternatives = splitTopLevelAlternatives(groupBody ?? selector);
  if (!groupBody && alternatives.length !== 1) {
    return 'Multiple resource selectors must be wrapped in a single noncapturing group.';
  }
  if (
    alternatives.some(branch => {
      const separator = branch.indexOf(':');
      return (
        separator <= 0 ||
        !ACCESS_TOKEN_RESOURCE_KINDS.includes(branch.slice(0, separator) as AccessTokenResourceKind)
      );
    })
  ) {
    return "Every resource selector must start with a known resource kind followed by ':'.";
  }
  return undefined;
};

export function validateScopeConfig(pattern: string, headers: RequiredHeader[]): string[] {
  const errors: string[] = [];
  const declared = new Set<string>();

  if (headers.length > 8) errors.push('A token can require at most 8 headers.');

  headers.forEach((header, index) => {
    const name = header.name.trim();
    const normalized = name.toLowerCase();
    if (!name || name.length > 64 || !/^[A-Za-z0-9-]+$/.test(name)) {
      errors.push(`Header ${index + 1} has an invalid name.`);
    } else if (declared.has(normalized)) {
      errors.push(`Required header '${name}' is duplicated.`);
    } else {
      declared.add(normalized);
    }

    if (!header.pattern || header.pattern.length > 256 || !anchored(header.pattern)) {
      errors.push(`Required header '${name || index + 1}' has an invalid pattern.`);
    }
  });

  const trimmed = pattern.trim();
  if (!trimmed) return errors;
  if (trimmed.length > 512) errors.push('Resource pattern must be 512 characters or fewer.');

  const placeholders = placeholderNames(trimmed);
  const undeclared = placeholders.filter(name => !declared.has(name));
  if (undeclared.length > 0) {
    errors.push(`Resource pattern references undeclared header(s): ${undeclared.join(', ')}.`);
  }
  if (placeholders.length > 1) {
    errors.push('Resource pattern may select a tenant from only one distinct header.');
  }
  if (!anchored(trimmed.replace(PLACEHOLDER_RE, 'x'))) {
    errors.push('Resource pattern is not a valid regular expression.');
  }
  const canonicalError = canonicalResourcePatternError(trimmed);
  if (canonicalError) errors.push(canonicalError);

  return errors;
}

export function evaluateScopePreview(
  pattern: string,
  headers: RequiredHeader[],
  sampleHeaders: Record<string, string>,
  resourceKind: AccessTokenResourceKind,
  resourceId: string
): ScopePreview {
  const errors = validateScopeConfig(pattern, headers);
  const values: Record<string, string> = {};

  for (const header of headers) {
    const name = header.name.trim().toLowerCase();
    const value = sampleHeaders[name] ?? '';
    const validator = anchored(header.pattern);
    if (name && (!validator || value.length > 512 || !validator.test(value))) {
      errors.push(`Sample value for '${header.name.trim()}' is missing or invalid.`);
    }
    values[name] = value;
  }

  const inference = inferTenantSelection(pattern);
  let tenantId: string | undefined;
  if (inference.mode === 'tenant') {
    tenantId = values[inference.headerName];
    if (!tenantId || !TENANT_ID_RE.test(tenantId)) {
      errors.push(
        'The selected tenant ID must use 1-128 letters, digits, dot, underscore, colon, or dash.'
      );
    }
  }

  const target = tenantId
    ? canonicalResourceTarget(tenantId, resourceKind, resourceId)
    : resourceId;
  const effectivePattern = pattern.trim()
    ? pattern.replace(PLACEHOLDER_RE, (_whole, name: string) =>
        escapeRegExp(values[name.toLowerCase()] ?? '')
      )
    : undefined;
  const effectiveRegex = effectivePattern ? anchored(effectivePattern) : null;
  const allowed =
    errors.length === 0 && (!effectivePattern || Boolean(effectiveRegex?.test(target)));

  return { allowed, target, effectivePattern, tenantId, errors };
}
