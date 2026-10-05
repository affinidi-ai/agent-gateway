export type CallerAuthMethodType =
  | 'jwt_bearer'
  | 'api_key'
  | 'api_key_provider'
  | 'did_auth'
  | 'mtls';

export const CALLER_AUTH_METHOD_OPTIONS: Array<{
  value: CallerAuthMethodType;
  label: string;
  disabled?: boolean;
}> = [
  { value: 'jwt_bearer', label: 'JWT Bearer' },
  { value: 'api_key', label: 'API Key (secret store)' },
  { value: 'api_key_provider', label: 'API Key (provider)' },
  { value: 'did_auth', label: 'DID Auth' },
  { value: 'mtls', label: 'mTLS (Mutual TLS)', disabled: true },
];

export const isSelectableCallerAuthMethod = (method: CallerAuthMethodType) =>
  !CALLER_AUTH_METHOD_OPTIONS.some(option => option.value === method && option.disabled);
