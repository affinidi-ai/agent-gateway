/**
 * The Target authentication rules that need the whole surface: a header another credential on
 * the same leg already sends, and a Target credential on a leg that does not check its callers.
 * The gateway refuses a new or changed header clash on save, and keeps one the stored surface
 * already had on the same leg, with the same setting and endpoint; so does this. A leg that
 * checks no callers is refused only while `target_source_auth` is `enforce`, so it is reported
 * as an advisory.
 */
import {
  MA_CALLER_CHECK_PROBLEM,
  TP_CALLER_CHECK_PROBLEM,
  targetAuthHeader,
} from './_shared/providerTargetAuth';

interface Leg {
  nodeId: string;
  transitPointId: string | null;
  endpoint: string;
  auth: unknown;
  field: string;
  checksCallers: boolean;
  callerCheckProblem: string;
  otherHeaders: Array<{ name: string; usedBy: string }>;
}

interface Breach {
  nodeId: string;
  transitPointId: string | null;
  endpoint: string;
  auth: string;
  rule: 'duplicate' | 'callers';
  message: string;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function injectionHeader(injection: unknown): string | null {
  const inject = record(injection);
  if (inject?.type === 'bearer_header') return 'Authorization';
  if (inject?.type === 'custom_header' && typeof inject.name === 'string') return inject.name;
  return null;
}

function mappedHeaders(mapping: unknown): Array<{ name: string; usedBy: string }> {
  return array(record(mapping)?.headers).flatMap(entry => {
    const header = record(entry)?.header;
    return typeof header === 'string' && header.trim()
      ? [{ name: header.trim(), usedBy: 'header metadata mapping' }]
      : [];
  });
}

function supportsMetadataMapping(protocol: unknown): boolean {
  return protocol === 'a2a' || protocol === 'ap2';
}

function legs(surface: unknown): Leg[] {
  const payload = record(surface);
  if (!payload) return [];
  const accessPoint = record(payload.access_point);
  const target = record(payload.target);
  const found: Leg[] = [];
  const bindings = array(payload.outbound_credentials)
    .map(binding => injectionHeader(record(binding)?.inject_as))
    .filter((name): name is string => name !== null)
    .map(name => ({ name, usedBy: 'a credential binding' }));
  const resource = record(payload.mcp_http)?.authorization != null;
  if (target?.auth) {
    const methods = array(record(accessPoint?.caller_authentication)?.methods);
    const first = record(methods[0]);
    const forwarded =
      first?.type === 'jwt_bearer' && first.forward_header === true ? first : undefined;
    const otherHeaders = [...bindings];
    if (forwarded && !resource) {
      otherHeaders.push({
        name: typeof forwarded.token_header === 'string' ? forwarded.token_header : 'Authorization',
        usedBy: 'source authentication',
      });
    }
    if (supportsMetadataMapping(accessPoint?.protocol ?? payload.protocol)) {
      otherHeaders.push(...mappedHeaders(accessPoint?.header_metadata_mapping));
    }
    found.push({
      nodeId: 'target',
      transitPointId: null,
      endpoint: typeof target?.endpoint === 'string' ? target.endpoint : '',
      auth: target.auth,
      field: 'target.auth',
      checksCallers: methods.length > 0 || resource,
      callerCheckProblem: MA_CALLER_CHECK_PROBLEM,
      otherHeaders,
    });
  }
  array(record(payload.transit)?.points).forEach((entry, index) => {
    const point = record(entry);
    if (!point?.target_auth) return;
    const endpoint = typeof point.target_endpoint === 'string' ? point.target_endpoint : '';
    const withholds =
      endpoint.startsWith('fabric://') && point.fabric_delegated_credentials !== true;
    const otherHeaders = withholds ? [] : [...bindings];
    const own = injectionHeader(record(point.transit_credentials)?.inject_as);
    if (own) otherHeaders.push({ name: own, usedBy: 'a credential binding' });
    if (supportsMetadataMapping(point.protocol)) {
      otherHeaders.push(...mappedHeaders(point.header_metadata_mapping));
    }
    const pointResource = record(point.mcp_http)?.authorization != null;
    found.push({
      nodeId: `transit-point-${index + 1}`,
      transitPointId: typeof point.id === 'string' ? point.id : null,
      endpoint,
      auth: point.target_auth,
      field: `transit.points['${String(point.alias)}'].target_auth`,
      checksCallers:
        point.require_transit_token !== false || pointResource || point.source_auth != null,
      callerCheckProblem: TP_CALLER_CHECK_PROBLEM,
      otherHeaders,
    });
  });
  return found;
}

function breaches(surface: unknown): Breach[] {
  return legs(surface).flatMap(leg => {
    const header = targetAuthHeader(leg.auth);
    if (!header) return [];
    const base = {
      nodeId: leg.nodeId,
      transitPointId: leg.transitPointId,
      endpoint: leg.endpoint,
      auth: JSON.stringify(leg.auth),
    };
    const found: Breach[] = [];
    const used = leg.otherHeaders.find(
      other => other.name.toLowerCase() === header.headerName.toLowerCase()
    );
    if (used && header.headerName) {
      const message = `${leg.field}.header_name ${header.headerName} is already sent by ${used.usedBy}`;
      found.push({ ...base, rule: 'duplicate', message });
    }
    if (!leg.checksCallers) {
      found.push({ ...base, rule: 'callers', message: `${leg.field}: ${leg.callerCheckProblem}` });
    }
    return found;
  });
}

const sameBreach = (a: Breach, b: Breach) =>
  a.transitPointId === b.transitPointId &&
  a.endpoint === b.endpoint &&
  a.auth === b.auth &&
  a.rule === b.rule;

export interface TargetAuthBreach {
  nodeId: string;
  rule: 'duplicate' | 'callers';
  message: string;
}

/** Every breach `surface` has that `stored` did not already have. */
export function targetAuthBreaches(surface: unknown, stored: unknown): TargetAuthBreach[] {
  const kept = breaches(stored);
  return breaches(surface)
    .filter(breach => !kept.some(old => sameBreach(old, breach)))
    .map(({ nodeId, rule, message }) => ({ nodeId, rule, message }));
}
