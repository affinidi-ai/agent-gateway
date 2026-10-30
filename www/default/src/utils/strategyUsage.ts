export interface SurfaceRef {
  id: string;
  name: string;
}

export type ProviderRef = SurfaceRef;

interface CallerAuthHolder {
  caller_authentication?: { methods?: Array<{ jwt_verification_strategy_id?: string }> };
}

interface ProviderBinding {
  credential_provider_id?: string;
}

interface CredentialHolder {
  transit?: { points?: Array<{ transit_credentials?: ProviderBinding | null }> };
  outbound_credentials?: ProviderBinding[];
}

interface RawSurface extends CredentialHolder {
  surface_id?: string;
  name?: string;
  access_point?: CallerAuthHolder;
  variants?: Array<{ overrides?: CredentialHolder & { access_point?: CallerAuthHolder } }>;
}

interface RawProvider {
  id?: string;
  name?: string;
  consent_identity_strategy_id?: string;
}

function referencesStrategy(holder: CallerAuthHolder | undefined, strategyId: string): boolean {
  const methods = holder?.caller_authentication?.methods;
  return (
    Array.isArray(methods) && methods.some(m => m?.jwt_verification_strategy_id === strategyId)
  );
}

function bindsProvider(holder: CredentialHolder | undefined, providerIds: string[]): boolean {
  if (!holder || providerIds.length === 0) return false;
  const named = (binding: ProviderBinding | null | undefined) =>
    typeof binding?.credential_provider_id === 'string' &&
    providerIds.includes(binding.credential_provider_id);
  const points = holder.transit?.points;
  const outbound = holder.outbound_credentials;
  return (
    (Array.isArray(points) && points.some(p => named(p?.transit_credentials))) ||
    (Array.isArray(outbound) && outbound.some(named))
  );
}

export function providersUsingStrategy(providers: unknown, strategyId: string): ProviderRef[] {
  if (!Array.isArray(providers)) return [];
  return (providers as RawProvider[])
    .filter(p => p && typeof p.id === 'string' && p.consent_identity_strategy_id === strategyId)
    .map(p => ({ id: p.id as string, name: p.name || (p.id as string) }));
}

export function surfacesUsingStrategy(
  surfaces: unknown,
  strategyId: string,
  consentProviderIds: string[] = []
): SurfaceRef[] {
  if (!Array.isArray(surfaces)) return [];
  const used: SurfaceRef[] = [];
  for (const raw of surfaces as RawSurface[]) {
    if (!raw || typeof raw.surface_id !== 'string') continue;
    const viaVariant = (raw.variants ?? []).some(
      v =>
        referencesStrategy(v?.overrides?.access_point, strategyId) ||
        bindsProvider(v?.overrides, consentProviderIds)
    );
    if (
      referencesStrategy(raw.access_point, strategyId) ||
      bindsProvider(raw, consentProviderIds) ||
      viaVariant
    ) {
      used.push({ id: raw.surface_id, name: raw.name || raw.surface_id });
    }
  }
  return used;
}
