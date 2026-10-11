import type { AccessTokenCreated, AccessTokenMeta } from '../../types';

export const accessToken: AccessTokenMeta = {
  id: 'agat_token1',
  name: 'Automation',
  description: 'CI token',
  user_id: 'admin-1',
  scopes: ['gateways.view'],
  resource_pattern: null,
  required_headers: [],
  created_by: 'admin-1',
  created_at: '2026-09-08T10:00:00Z',
  rotation_generation: 0,
  active: true,
};

export const createdAccessToken: AccessTokenCreated = {
  ...accessToken,
  id: 'agat_created',
  name: 'Deploy token',
  description: '',
  token: 'agpat_once-only',
};
