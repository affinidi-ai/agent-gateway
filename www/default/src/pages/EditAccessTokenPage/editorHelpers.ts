import type { AccessTokenMeta, RequiredHeader, UpdateAccessTokenRequest } from '../../types';
import { toLocalDateTimeInput } from './accessTokenExpiry';

export const ACCESS_TOKEN_LIST_ROUTE = '/secrets?tab=access-tokens';
export const ACCESS_TOKEN_NEW_ROUTE = '/access-tokens/new';

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

export function accessTokenFormFromQuery(search: string, now: Date): AccessTokenFormState {
  const params = new URLSearchParams(search);
  const form = newAccessTokenForm(now);
  const scopes = [
    ...params.getAll('scope'),
    ...params.getAll('scopes').flatMap(value => value.split(',')),
  ]
    .map(scope => scope.trim())
    .filter(Boolean);
  const expiresAt = params.get('expires_at');
  const expiry = expiresAt ? new Date(expiresAt) : null;
  const requiredHeaders = params.getAll('header').flatMap(value => {
    const separator = value.indexOf(':');
    if (separator <= 0) return [];
    return [{ name: value.slice(0, separator).trim(), pattern: value.slice(separator + 1) }];
  });

  return {
    ...form,
    name: params.get('name') ?? form.name,
    description: params.get('description') ?? form.description,
    scopes: Array.from(new Set(scopes)),
    ...(expiry && !Number.isNaN(expiry.getTime())
      ? { neverExpires: false, expiresAt: toLocalDateTimeInput(expiry) }
      : {}),
    resourcePattern: params.get('resource_pattern') ?? form.resourcePattern,
    requiredHeaders,
  };
}

export function accessTokenFormQuery(form: AccessTokenFormState): string {
  const params = new URLSearchParams();
  const name = form.name.trim();
  const description = form.description.trim();
  const resourcePattern = form.resourcePattern.trim();
  const expiry = form.neverExpires ? null : new Date(form.expiresAt);

  if (name) params.set('name', name);
  if (description) params.set('description', description);
  if (form.scopes.length > 0) params.set('scopes', form.scopes.join(','));
  if (expiry && !Number.isNaN(expiry.getTime())) params.set('expires_at', expiry.toISOString());
  if (resourcePattern) params.set('resource_pattern', resourcePattern);
  form.requiredHeaders.forEach(header => {
    const headerName = header.name.trim();
    if (headerName) params.append('header', `${headerName}:${header.pattern}`);
  });

  const query = params.toString();
  return query ? `?${query}` : '';
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
