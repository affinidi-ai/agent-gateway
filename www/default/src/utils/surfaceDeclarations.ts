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
  transit_point: 'Transit Point cards never declare authentication.',
  fabric_target: 'The Target is a Fabric peer and this surface has no caller authentication.',
  multiple_methods: 'More than one caller authentication method is configured.',
  method_not_declarable: 'Only JWT bearer caller authentication can be declared.',
  strategy_unavailable: 'The JWT verification strategy is missing or not available to this tenant.',
  static_jwks: 'The strategy uses static keys, so it has no authorization server to declare.',
  not_pinned: 'The strategy has no pinned authorization server. Run Discover on the strategy.',
  pin_mismatch: 'The pinned authorization server no longer matches the strategy. Discover again.',
  custom_token_header: 'The token header is not Authorization with the Bearer scheme.',
  forwards_caller_token:
    'Forward token header to managed agent is on, so the caller’s token would reach the managed agent. No authorization server is declared.',
  no_access_point_url: 'The gateway reports no https URL for this Access Point.',
  audience_missing: 'The Access Point URL is not in Accepted Audiences.',
  no_required_scopes: 'No required scopes are set.',
  root_variant:
    'A variant of an Access Point on the root route has no resource of its own to declare.',
};

export const UNSERVABLE_REASON_TEXT: Record<string, string> = {
  not_mcp:
    'Protected resource metadata is set but this is not an MCP Access Point. Remove protected_resource.',
  root_variant_resource:
    'A variant of an Access Point on the root route has no resource of its own. Give the surface a route.',
  resource_mismatch: 'The resource must be this Access Point URL. Set it to the URL shown.',
  invalid_protected_resource:
    'The protected resource metadata settings are not valid. Check the authorization servers, scopes and resource.',
  incompatible_caller_authentication:
    'Protected resource metadata needs the first caller authentication method to be JWT Bearer reading the Authorization header with the Bearer scheme, with no audiences and forward_header off. Fix the method or remove protected_resource.',
  strategy_store_unavailable:
    'The gateway could not read the JWT verification strategy. Callers get 503 until it can; check the gateway log.',
};

const UNSERVABLE_FALLBACK =
  'The discovery setting cannot be served on this route, so callers are refused until it is fixed.';

export function describeDeclaration(
  d: SurfaceDeclaration,
  protocol?: Protocol
): { label: string; detail: string } {
  const mcp = protocol === 'mcp';
  if (d.outcome === 'declare') {
    return {
      label: 'Declares OAuth',
      detail: mcp
        ? 'The protected resource metadata names this gateway’s authorization server and scopes.'
        : 'The agent card advertises this gateway’s authorization server and scopes.',
    };
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
  const fallback = mcp
    ? 'No protected resource metadata is published.'
    : 'The card declares no security scheme.';
  return {
    label: mcp ? 'Not declared' : 'Security removed from card',
    detail: (d.reason && STRIP_REASON_TEXT[d.reason]) || fallback,
  };
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
