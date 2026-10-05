import type { AccessTokenMeta, RequiredHeader, UpdateAccessTokenRequest } from '../../types';
import { toLocalDateTimeInput } from './accessTokenExpiry';

export const ACCESS_TOKEN_LIST_ROUTE = '/secrets?tab=access-tokens';

export interface AccessTokenFormState {
  name: string;
  description: string;
  scopes: string[];
  neverExpires: boolean;
  expiresAt: string;
  resourcePattern: string;
  requiredHeaders: RequiredHeader[];
}

export function newAccessTokenForm(now: Date): AccessTokenFormState {
  return {
    name: '',
    description: '',
    scopes: [],
    neverExpires: true,
    expiresAt: toLocalDateTimeInput(new Date(now.getTime() + 24 * 60 * 60 * 1000)),
    resourcePattern: '',
    requiredHeaders: [],
  };
}

export function accessTokenFormFor(token: AccessTokenMeta): AccessTokenFormState {
  return {
    name: token.name,
    description: token.description ?? '',
    scopes: token.scopes,
    neverExpires: true,
    expiresAt: '',
    resourcePattern: token.resource_pattern ?? '',
    requiredHeaders: token.required_headers ?? [],
  };
}

export function accessTokenPayload(form: AccessTokenFormState): UpdateAccessTokenRequest {
  return {
    name: form.name.trim(),
    description: form.description.trim(),
    scopes: form.scopes,
    resource_pattern: form.resourcePattern.trim() || undefined,
    required_headers: form.requiredHeaders.map(header => ({
      name: header.name.trim(),
      pattern: header.pattern,
    })),
  };
}
