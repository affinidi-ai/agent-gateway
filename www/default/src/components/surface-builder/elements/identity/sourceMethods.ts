import {
  CALLER_AUTH_METHOD_SHORT_LABEL,
  credentialLocation,
  type CallerAuthMethodConfig,
} from '../caller-auth/methods';

export interface SourceMethodChoice {
  id: string;
  label: string;
}

const API_KEY_METHODS = new Set<unknown>(['api_key', 'api_key_provider']);

/** Whether an identity of this type can be derived from the credential of `method`. */
export function readsMethod(identityType: unknown, method: CallerAuthMethodConfig): boolean {
  if (identityType === 'from_jwt_claim') return method.method_type === 'jwt_bearer';
  if (identityType === 'from_api_key') return API_KEY_METHODS.has(method.method_type);
  return false;
}

/** The Caller Context methods an inbound identity of this type can read, in list order. */
export function sourceMethodChoices(
  identityType: unknown,
  methods: CallerAuthMethodConfig[]
): SourceMethodChoice[] {
  return methods.flatMap((method, position) =>
    method.id && readsMethod(identityType, method)
      ? [
          {
            id: method.id,
            label: `Method ${position + 1}: ${CALLER_AUTH_METHOD_SHORT_LABEL[method.method_type!]}, reads ${credentialLocation(method)}`,
          },
        ]
      : []
  );
}

export const NO_SOURCE_METHOD =
  'No Caller Context method can supply this identity. Add a JWT Bearer method, or choose another extraction type.';
export const NO_SOURCE_METHOD_API_KEY =
  'No Caller Context method can supply this identity. Add an API Key or API Key Provider method, or choose another extraction type.';
