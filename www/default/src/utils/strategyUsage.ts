export interface SurfaceRef {
  id: string;
  name: string;
}

interface CallerAuthHolder {
  caller_authentication?: { methods?: Array<{ jwt_verification_strategy_id?: string }> };
}

interface RawSurface {
  surface_id?: string;
  name?: string;
  access_point?: CallerAuthHolder;
  variants?: Array<{ overrides?: { access_point?: CallerAuthHolder } }>;
}

function referencesStrategy(holder: CallerAuthHolder | undefined, strategyId: string): boolean {
  const methods = holder?.caller_authentication?.methods;
  return (
    Array.isArray(methods) && methods.some(m => m?.jwt_verification_strategy_id === strategyId)
  );
}

export function surfacesUsingStrategy(surfaces: unknown, strategyId: string): SurfaceRef[] {
  if (!Array.isArray(surfaces)) return [];
  const used: SurfaceRef[] = [];
  for (const raw of surfaces as RawSurface[]) {
    if (!raw || typeof raw.surface_id !== 'string') continue;
    const viaVariant = (raw.variants ?? []).some(v =>
      referencesStrategy(v?.overrides?.access_point, strategyId)
    );
    if (referencesStrategy(raw.access_point, strategyId) || viaVariant) {
      used.push({ id: raw.surface_id, name: raw.name || raw.surface_id });
    }
  }
  return used;
}
