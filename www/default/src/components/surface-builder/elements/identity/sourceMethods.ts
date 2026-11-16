import {
  CALLER_AUTH_METHOD_SHORT_LABEL,
  credentialLocation,
  type CallerAuthMethodConfig,
} from '../caller-auth/methods';

export interface SourceMethodChoice {
  id: string;
  label: string;
}

/** Identity types that read the credential the caller presented, so they can name the method. */
export const SOURCE_METHOD_TYPES: ReadonlySet<unknown> = new Set([
  'from_jwt_claim',
  'from_api_key',
]);

/** Caller Context method types whose credential an inbound From API Key identity can read. */
export const API_KEY_METHOD_TYPES: ReadonlySet<unknown> = new Set(['api_key', 'api_key_provider']);

/** Whether an identity of this type can be derived from the credential of `method`. */
export function readsMethod(identityType: unknown, method: CallerAuthMethodConfig): boolean {
  if (identityType === 'from_jwt_claim') return method.method_type === 'jwt_bearer';
  if (identityType === 'from_api_key') return API_KEY_METHOD_TYPES.has(method.method_type);
  return false;
}

/** Whether every method is one an identity of this type can read. */
export function readsEveryMethod(
  identityType: unknown,
  methods: CallerAuthMethodConfig[]
): boolean {
  return methods.length > 0 && methods.every(method => readsMethod(identityType, method));
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

/**
 * The method id an inbound identity is derived from, or `undefined` for none.
 * Only a surface with several methods names one. The stored choice wins; with
 * none, an identity beside methods it cannot all read takes the first it can,
 * and beside methods it can all read it takes any of them.
 */
export function effectiveSourceMethod(
  config: Record<string, any> | undefined,
  methods: CallerAuthMethodConfig[]
): string | undefined {
  if (!config || !SOURCE_METHOD_TYPES.has(config.type) || methods.length < 2) return undefined;
  if (typeof config.source_method === 'string' && config.source_method) return config.source_method;
  if (readsEveryMethod(config.type, methods)) return undefined;
  return sourceMethodChoices(config.type, methods)[0]?.id;
}

/** What the select shows for a stored method id that is no longer a choice. */
export function unlistedMethodLabel(id: string, methods: CallerAuthMethodConfig[]): string {
  const position = methods.findIndex(method => method.id === id);
  if (position < 0) return 'Method no longer available';
  const type = methods[position].method_type;
  const kind = type ? CALLER_AUTH_METHOD_SHORT_LABEL[type] : 'another kind';
  return `Method ${position + 1} is now ${kind}`;
}

export const ANY_JWT_METHOD = 'Any JWT Bearer method';
export const ANY_API_KEY_METHOD = 'Any API key method';

export const NO_SOURCE_METHOD =
  'No Caller Context method can supply this identity. Add a JWT Bearer method, or choose another extraction type.';
export const NO_SOURCE_METHOD_API_KEY =
  'No Caller Context method can supply this identity. Add an API Key or API Key Provider method, or choose another extraction type.';
