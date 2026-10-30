import type { Protocol } from '../components/surface-builder/elements/types';

export type DeclarationOutcome = 'declare' | 'strip' | 'pass_through' | 'unservable';

export interface SurfaceDeclaration {
  variant: string | null;
  outcome: DeclarationOutcome;
  reason: string | null;
  resource: string | null;
}

export interface SurfaceWarning {
  code: string;
  message: string;
  path: string | null;
  variant: string | null;
}

export interface SurfaceDeclarations {
  declarations: SurfaceDeclaration[];
  warnings: SurfaceWarning[];
}

const OUTCOMES: DeclarationOutcome[] = ['declare', 'strip', 'pass_through', 'unservable'];
const asString = (v: unknown): string | null => (typeof v === 'string' ? v : null);

export function parseSurfaceDeclarations(body: unknown): SurfaceDeclarations {
  const obj = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const declarations: SurfaceDeclaration[] = [];
  for (const raw of Array.isArray(obj.declarations) ? obj.declarations : []) {
    const d = raw as Record<string, unknown> | null;
    if (!d || !OUTCOMES.includes(d.outcome as DeclarationOutcome)) continue;
    declarations.push({
      variant: asString(d.variant),
      outcome: d.outcome as DeclarationOutcome,
      reason: asString(d.reason),
      resource: asString(d.resource),
    });
  }
  const warnings: SurfaceWarning[] = [];
  for (const raw of Array.isArray(obj.warnings) ? obj.warnings : []) {
    const w = raw as Record<string, unknown> | null;
    if (!w || typeof w.code !== 'string' || typeof w.message !== 'string') continue;
    warnings.push({
      code: w.code,
      message: w.message,
      path: asString(w.path),
      variant: asString(w.variant),
    });
  }
  return { declarations, warnings };
}

export const FAIL_OPEN_WARNING_CODES = ['fail_open_policy', 'fail_open_undetermined'];

export const GATEWAY_DENY_WARNING_CODES = ['payment_before_policy'];

export const STRIP_REASON_TEXT: Record<string, string> = {
  not_declared: 'Authorization server discovery is off for this route.',
  fabric_target: 'The Target is a Fabric peer and this surface has no caller authentication.',
  transit_point: 'Transit Point cards never declare authentication.',
};

export const UNSERVABLE_REASON_TEXT: Record<string, string> = {
  unsupported_protocol:
    'Authorization server discovery is set but this Access Point’s protocol cannot publish it. Remove protected_resource.',
  root_variant_resource:
    'A variant of an Access Point on the root route has no resource of its own. Give the surface a route.',
  resource_mismatch:
    'This Access Point’s listener no longer serves the resource URL, so callers are refused. Set the resource to a URL the listener serves.',
  invalid_protected_resource:
    'The authorization server discovery settings are not valid. Check the resource URL and any stored authorization server or scopes.',
  incompatible_caller_authentication:
    'Authorization server discovery needs JWT Bearer reading the Authorization header with the Bearer scheme, no Accepted Audiences and token forwarding off. Fix the method or turn authorization server discovery off.',
  strategy_unavailable:
    'The JWT verification strategy is missing or not available to this tenant, so no authorization server can be published. Callers are refused until it is fixed.',
  issuer_not_advertisable:
    'The JWT verification strategy’s issuer is not a URL protected resource metadata can name, so no authorization server can be published. Callers are refused until it is fixed.',
  strategy_store_unavailable:
    'The gateway could not read the JWT verification strategy. Callers get 503 until it can; check the gateway log.',
  network_unavailable:
    'The gateway could not read its listener settings. Callers are refused until it can; check the gateway log.',
};

const UNSERVABLE_FALLBACK =
  'The discovery setting cannot be served on this route, so callers are refused until it is fixed.';

const CARD_KEEPS_SECURITY = 'The agent card keeps the managed agent’s own security.';

export const CARD_SCHEME_UNAVAILABLE_CODE = 'card_scheme_unavailable';

export function cardCarriesScheme(
  warnings: readonly SurfaceWarning[],
  variant: string | null
): boolean {
  return !warnings.some(w => w.code === CARD_SCHEME_UNAVAILABLE_CODE && w.variant === variant);
}

export function describeDeclaration(
  d: SurfaceDeclaration,
  protocol?: Protocol,
  cardScheme: boolean | null = true
): { label: string; detail: string } {
  const mcp = protocol === 'mcp';
  if (d.outcome === 'declare') {
    const named =
      'the authorization server of the selected strategy and the required scopes, and callers without a valid token are challenged.';
    let detail = `The agent card and the protected resource metadata name ${named}`;
    if (mcp || cardScheme === null) detail = `The protected resource metadata names ${named}`;
    else if (!cardScheme) {
      detail = `Only the protected resource metadata names ${named} The agent card names no security scheme.`;
    }
    return { label: 'Declares OAuth', detail };
  }
  if (d.outcome === 'unservable') {
    return {
      label: 'Cannot be served',
      detail: (d.reason && UNSERVABLE_REASON_TEXT[d.reason]) || UNSERVABLE_FALLBACK,
    };
  }
  if (d.outcome === 'pass_through') {
    return mcp
      ? {
          label: 'No metadata published',
          detail:
            'No caller authentication is configured, so no protected resource metadata is published.',
        }
      : {
          label: 'Upstream card unchanged',
          detail:
            'No caller authentication is configured, so the upstream card’s security is kept.',
        };
  }
  const reasonText = d.reason ? STRIP_REASON_TEXT[d.reason] : undefined;
  let detail: string;
  if (mcp) {
    detail = reasonText ?? 'No protected resource metadata is published.';
  } else {
    detail = reasonText ? `${reasonText} ${CARD_KEEPS_SECURITY}` : CARD_KEEPS_SECURITY;
  }
  return { label: 'Not declared', detail };
}

export function surfacePathAfterCreate(created: {
  surface_id?: string;
  warnings?: SurfaceWarning[];
}): string {
  return created.warnings?.length && created.surface_id
    ? `/surfaces/${encodeURIComponent(created.surface_id)}`
    : '/surfaces';
}

export async function fetchSurfaceDeclarations(
  fetcher: (url: string, init?: RequestInit) => Promise<Response>,
  surfaceId: string
): Promise<SurfaceDeclarations | null> {
  try {
    const response = await fetcher(
      `/api/v1/surfaces/${encodeURIComponent(surfaceId)}/declarations`
    );
    if (!response.ok) return null;
    return parseSurfaceDeclarations(await response.json());
  } catch {
    return null;
  }
}
