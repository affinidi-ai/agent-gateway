/**
 * The Target authentication rules that need the whole surface: a header another credential on
 * the same leg already sends, and a Target credential on a leg that does not check its callers.
 * The gateway refuses a header clash on every save, one the stored surface already had
 * included; so does this. Header names are compared as the gateway compares them: any letter
 * case, `_` read as `-`. A leg that checks no callers is refused only while `target_source_auth`
 * is `enforce`, so it is reported as an advisory, and not again when the stored surface already
 * had it on the same leg, with the same setting and endpoint.
 */
import { registry } from './registry';
import {
  MA_CALLER_CHECK_PROBLEM,
  TP_CALLER_CHECK_PROBLEM,
  record,
  sameHeaderName,
  stableJson,
  targetAuthHeader,
} from './_shared/providerTargetAuth';

interface Leg {
  nodeId: string | undefined;
  transitPointId: string | null;
  endpoint: string;
  auth: unknown;
  field: string;
  checksCallers: boolean;
  callerCheckProblem: string;
  otherHeaders: Array<{ name: string; usedBy: string }>;
}

interface Breach {
  nodeId: string | undefined;
  transitPointId: string | null;
  endpoint: string;
  auth: string;
  rule: 'duplicate' | 'callers';
  message: string;
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

/**
 * The token header of every JWT Bearer method that forwards it. A request forwards only the
 * method it was verified by, and any of them can be that method, so each one counts.
 */
function forwardedTokenHeaders(methods: unknown[]): Array<{ name: string; usedBy: string }> {
  return methods.flatMap(entry => {
    const method = record(entry);
    if (method?.type !== 'jwt_bearer' || method.forward_header !== true) return [];
    const name = typeof method.token_header === 'string' ? method.token_header : 'Authorization';
    return [{ name, usedBy: 'source authentication' }];
  });
}

function supportsMetadataMapping(protocol: unknown): boolean {
  return protocol === 'a2a' || protocol === 'ap2';
}

/**
 * The canvas node of each Transit Point, in the order of `transit.points`: the payload builder
 * writes both lists from the same nodes, so a point and its node share a position. Canvas data
 * that does not list `count` Transit Points names none, since no node beats the wrong one.
 */
function transitPointNodeIds(canvas: unknown, count: number): string[] {
  const ids = array(record(canvas)?.nodes).flatMap(entry => {
    const node = record(entry);
    return typeof node?.id === 'string' &&
      typeof node.type === 'string' &&
      registry.isTransitPointType(node.type)
      ? [node.id]
      : [];
  });
  return ids.length === count ? ids : [];
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
    const otherHeaders = [...bindings];
    if (!resource) otherHeaders.push(...forwardedTokenHeaders(methods));
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
  const points = array(record(payload.transit)?.points);
  const pointNodeIds = transitPointNodeIds(payload.canvas, points.length);
  points.forEach((entry, index) => {
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
      nodeId: pointNodeIds[index],
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
      auth: stableJson(leg.auth),
    };
    const found: Breach[] = [];
    const used = header.headerName
      ? leg.otherHeaders.find(other => sameHeaderName(other.name, header.headerName))
      : undefined;
    if (used) {
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
  nodeId?: string;
  rule: 'duplicate' | 'callers';
  message: string;
}

/** Every header clash `surface` has, and every missing caller check `stored` did not have. */
export function targetAuthBreaches(surface: unknown, stored: unknown): TargetAuthBreach[] {
  const kept = breaches(stored);
  return breaches(surface)
    .filter(breach => breach.rule !== 'callers' || !kept.some(old => sameBreach(old, breach)))
    .map(({ nodeId, rule, message }) => ({ nodeId, rule, message }));
}
