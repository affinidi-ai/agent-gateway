import { formatDID } from '../../utils/stringUtils';

/**
 * A single row in the human-friendly VP view. A row is either a leaf (`value`
 * set) or a group (`children` set). Groups nest arbitrarily deep so the decoded
 * VP reads as a labelled outline instead of raw JSON.
 */
export interface ReadableRow {
  label: string;
  value?: string;
  /** Untruncated value, surfaced as a tooltip (e.g. the full DID behind a short one). */
  fullValue?: string;
  /** Render the value in a monospace face (DIDs, hashes). */
  mono?: boolean;
  children?: ReadableRow[];
}

/** Well-known JWT / VC / VP keys mapped to plain-English labels. */
const KNOWN_LABELS: Record<string, string> = {
  iss: 'Issuer',
  sub: 'Subject',
  aud: 'Audience',
  jti: 'ID',
  iat: 'Issued at',
  nbf: 'Not valid before',
  exp: 'Expires',
  vp: 'Verifiable Presentation',
  vc: 'Verifiable Credential',
  verifiableCredential: 'Credentials',
  credentialSubject: 'Subject claims',
  '@context': 'Context',
  type: 'Type',
  issuer: 'Issuer',
  holder: 'Holder',
  issuanceDate: 'Issued',
  expirationDate: 'Expires',
  id: 'ID',
  workloadBinding: 'Workload binding',
  policyDecisions: 'Policy decisions',
  policy_name: 'Policy name',
  policy_id: 'Policy package',
  policy_definition_id: 'Policy definition ID',
  intent: 'Intent',
  proof: 'Proof',
};

/** JWT numeric-date claims (unix seconds). */
const UNIX_DATE_KEYS = new Set(['iat', 'nbf', 'exp']);

/** Turns a raw object key into a plain-English label. Pure. */
export function humanizeLabel(key: string): string {
  const known = KNOWN_LABELS[key];
  if (known) return known;
  const spaced = key
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/\s+/g, ' ')
    .trim();
  if (!spaced) return key;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

interface ScalarDisplay {
  value: string;
  fullValue?: string;
  mono?: boolean;
}

/** Formats a scalar for display: DIDs shortened, dates humanized, booleans as Yes/No. Pure. */
function formatScalar(key: string, value: string | number | boolean): ScalarDisplay {
  if (typeof value === 'boolean') return { value: value ? 'Yes' : 'No' };

  if (typeof value === 'number') {
    if (UNIX_DATE_KEYS.has(key) && Number.isFinite(value)) {
      const d = new Date(value * 1000);
      if (!Number.isNaN(d.getTime()))
        return { value: d.toLocaleString(), fullValue: String(value) };
    }
    return { value: String(value) };
  }

  if (value.startsWith('did:')) {
    return { value: formatDID(value), fullValue: value, mono: true };
  }
  if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return { value: d.toLocaleString(), fullValue: value };
  }
  if (/^(sha256:)?[0-9a-f]{32,}$/i.test(value)) {
    return { value, mono: true };
  }
  return { value };
}

function isScalar(value: unknown): value is string | number | boolean {
  return value === null || typeof value !== 'object';
}

function rowForEntry(key: string, value: unknown): ReadableRow {
  const label = humanizeLabel(key);

  if (value === null || value === undefined) {
    return { label, value: '—' };
  }

  if (Array.isArray(value)) {
    // Arrays of plain scalars read better as one comma-joined line.
    if (value.every(isScalar)) {
      return {
        label,
        value: value.map(v => (v == null ? '—' : String(v))).join(', ') || '—',
      };
    }
    return {
      label,
      children: value.map((item, i) =>
        isScalar(item)
          ? rowForEntry(`#${i + 1}`, item)
          : { label: `#${i + 1}`, children: buildReadableRows(item) }
      ),
    };
  }

  if (typeof value === 'object') {
    return { label, children: buildReadableRows(value) };
  }

  const f = formatScalar(key, value);
  return { label, value: f.value, fullValue: f.fullValue, mono: f.mono };
}

/**
 * Transforms a decoded VP (any JWT/JSON-LD shape) into a labelled outline of
 * {@link ReadableRow}s for the human-friendly view. Pure; safe on arbitrary input.
 */
export function buildReadableRows(obj: unknown): ReadableRow[] {
  if (obj === null || obj === undefined) return [];
  if (isScalar(obj)) {
    const f = formatScalar('', obj);
    return [{ label: 'Value', value: f.value, fullValue: f.fullValue, mono: f.mono }];
  }
  if (Array.isArray(obj)) {
    return obj.map((item, i) =>
      isScalar(item)
        ? rowForEntry(`#${i + 1}`, item)
        : { label: `#${i + 1}`, children: buildReadableRows(item) }
    );
  }
  return Object.entries(obj as Record<string, unknown>).map(([k, v]) => rowForEntry(k, v));
}
