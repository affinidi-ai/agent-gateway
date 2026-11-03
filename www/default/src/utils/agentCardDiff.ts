export type ItemStatus = 'same' | 'changed' | 'added' | 'removed';
export type RowStatus = 'same' | 'changed' | 'removed' | 'absent';
export type RowKey = 'signin' | 'scope' | 'signature' | 'endpoint' | 'other';
export type CardEra = '1.0' | '0.3' | 'both' | 'unknown';

export interface DiffItem {
  path: string;
  label: string;
  status: ItemStatus;
  before: string | null;
  after: string | null;
  primary?: boolean;
}

export interface DiffRow {
  key: RowKey;
  label: string;
  status: RowStatus;
  items: DiffItem[];
}

export interface CardDiff {
  rows: DiffRow[];
  changeCount: number;
  changedCount: number;
  removedCount: number;
  addedCount: number;
  modifiedCount: number;
}

type Obj = Record<string, unknown>;

const MAX_DEPTH = 64;
const VALUE_TEXT_LIMIT = 200;

const isObj = (v: unknown): v is Obj => v !== null && typeof v === 'object' && !Array.isArray(v);
const asObj = (v: unknown): Obj => (isObj(v) ? v : {});
const has = (o: Obj, key: string) => Object.prototype.hasOwnProperty.call(o, key);

function read(o: Obj, camel: string, snake: string): unknown {
  if (has(o, camel)) return o[camel];
  return has(o, snake) ? o[snake] : undefined;
}

function deepEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (a === b) return true;
  if (depth >= MAX_DEPTH) {
    try {
      return JSON.stringify(a) === JSON.stringify(b);
    } catch {
      return false;
    }
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i], depth + 1));
  }
  if (isObj(a) && isObj(b)) {
    const keys = Object.keys(a);
    if (keys.length !== Object.keys(b).length) return false;
    return keys.every(k => has(b, k) && deepEqual(a[k], b[k], depth + 1));
  }
  return false;
}

function canonical(v: unknown, depth = 0): unknown {
  if (depth >= MAX_DEPTH) return v;
  if (Array.isArray(v)) return v.map(x => canonical(x, depth + 1));
  if (isObj(v)) {
    const out: Obj = {};
    for (const k of Object.keys(v).sort()) out[k] = canonical(v[k], depth + 1);
    return out;
  }
  return v;
}

function valueText(v: unknown): string {
  let text: string;
  if (typeof v === 'string') {
    text = v;
  } else {
    try {
      text = JSON.stringify(canonical(v)) ?? String(v);
    } catch {
      text = String(v);
    }
  }
  return text.length > VALUE_TEXT_LIMIT ? `${text.slice(0, VALUE_TEXT_LIMIT)}…` : text;
}

function compareValues(
  path: string,
  label: string,
  before: unknown,
  after: unknown,
  beforeText?: string,
  afterText?: string
): DiffItem {
  const inBefore = before !== undefined;
  const inAfter = after !== undefined;
  let status: ItemStatus;
  if (inBefore && inAfter) status = deepEqual(before, after) ? 'same' : 'changed';
  else status = inAfter ? 'added' : 'removed';
  return {
    path,
    label,
    status,
    before: inBefore ? (beforeText ?? valueText(before)) : null,
    after: inAfter ? (afterText ?? valueText(after)) : null,
  };
}

function compareMaps(
  before: Obj,
  after: Obj,
  pathOf: (name: string) => string,
  labelOf: (name: string) => string
): DiffItem[] {
  const names = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return names.map(name =>
    compareValues(
      pathOf(name),
      labelOf(name),
      has(before, name) ? before[name] : undefined,
      has(after, name) ? after[name] : undefined
    )
  );
}

const SKILL_SECURITY_KEYS: ReadonlyArray<readonly [string, string]> = [
  ['security', 'security'],
  ['securityRequirements', 'security_requirements'],
  ['securitySchemes', 'security_schemes'],
];

function skillList(card: Obj): Obj[] {
  const skills = card.skills;
  return Array.isArray(skills) ? skills.filter(isObj) : [];
}

function skillHasSecurity(skill: Obj): boolean {
  return SKILL_SECURITY_KEYS.some(([c, s]) => read(skill, c, s) !== undefined);
}

function withoutSkillSecurity(skill: Obj): Obj {
  const out: Obj = {};
  const dropped = new Set(SKILL_SECURITY_KEYS.flat());
  for (const k of Object.keys(skill)) if (!dropped.has(k)) out[k] = skill[k];
  return out;
}

function requiredSchemeNames(card: Obj): string[] {
  const names = new Set<string>();
  const v03 = card.security;
  if (Array.isArray(v03)) {
    for (const req of v03) if (isObj(req)) Object.keys(req).forEach(n => names.add(n));
  }
  const v10 = read(card, 'securityRequirements', 'security_requirements');
  if (Array.isArray(v10)) {
    for (const req of v10) {
      if (isObj(req)) Object.keys(asObj(req.schemes)).forEach(n => names.add(n));
    }
  }
  return [...names].sort();
}

function signinItems(before: Obj, after: Obj): DiffItem[] {
  const items = compareMaps(
    asObj(read(before, 'securitySchemes', 'security_schemes')),
    asObj(read(after, 'securitySchemes', 'security_schemes')),
    name => `securitySchemes.${name}`,
    name => name
  );

  const requiredBefore = requiredSchemeNames(before);
  const requiredAfter = requiredSchemeNames(after);
  if (requiredBefore.length > 0 || requiredAfter.length > 0) {
    const item = compareValues(
      'security',
      'Required sign-in',
      requiredBefore.length > 0 ? requiredBefore : undefined,
      requiredAfter.length > 0 ? requiredAfter : undefined,
      requiredBefore.join(', '),
      requiredAfter.join(', ')
    );
    items.push(item);
  }

  const skillsBefore = skillList(before).filter(skillHasSecurity).length;
  const skillsAfter = skillList(after).filter(skillHasSecurity).length;
  if (skillsBefore > 0 || skillsAfter > 0) {
    const countText = (n: number) => `${n} skill${n === 1 ? '' : 's'}`;
    let status: ItemStatus = 'changed';
    if (skillsBefore === skillsAfter) status = 'same';
    else if (skillsAfter === 0) status = 'removed';
    else if (skillsBefore === 0) status = 'added';
    items.push({
      path: 'skills.security',
      label: 'Skill-level security',
      status,
      before: skillsBefore > 0 ? countText(skillsBefore) : null,
      after: skillsAfter > 0 ? countText(skillsAfter) : null,
    });
  }
  return items;
}

function schemeScopes(scheme: unknown, into: Set<string>) {
  let value = asObj(scheme);
  const wrapped = read(value, 'oauth2SecurityScheme', 'oauth2_security_scheme');
  if (isObj(wrapped)) value = wrapped;
  for (const flow of Object.values(asObj(value.flows))) {
    Object.keys(asObj(asObj(flow).scopes)).forEach(s => into.add(s));
  }
}

function collectScopes(card: Obj): Set<string> {
  const scopes = new Set<string>();
  const v03 = card.security;
  if (Array.isArray(v03)) {
    for (const req of v03) {
      if (!isObj(req)) continue;
      for (const list of Object.values(req)) {
        if (Array.isArray(list)) list.forEach(s => typeof s === 'string' && scopes.add(s));
      }
    }
  }
  const v10 = read(card, 'securityRequirements', 'security_requirements');
  if (Array.isArray(v10)) {
    for (const req of v10) {
      if (!isObj(req)) continue;
      for (const entry of Object.values(asObj(req.schemes))) {
        const list = asObj(entry).list;
        if (Array.isArray(list)) list.forEach(s => typeof s === 'string' && scopes.add(s));
      }
    }
  }
  for (const scheme of Object.values(asObj(read(card, 'securitySchemes', 'security_schemes')))) {
    schemeScopes(scheme, scopes);
  }
  return scopes;
}

function scopeItems(before: Obj, after: Obj): DiffItem[] {
  const b = collectScopes(before);
  const a = collectScopes(after);
  return [...new Set([...b, ...a])].sort().map(scope => {
    const status: ItemStatus =
      b.has(scope) && a.has(scope) ? 'same' : a.has(scope) ? 'added' : 'removed';
    return {
      path: `scope.${scope}`,
      label: scope,
      status,
      before: b.has(scope) ? scope : null,
      after: a.has(scope) ? scope : null,
    };
  });
}

function signatureItems(before: Obj, after: Obj): DiffItem[] {
  const count = (card: Obj) => (Array.isArray(card.signatures) ? card.signatures.length : 0);
  const nb = count(before);
  const na = count(after);
  if (nb === 0 && na === 0) return [];
  const text = (n: number) => (n === 0 ? null : `${n} signature${n === 1 ? '' : 's'}`);
  let status: ItemStatus = 'changed';
  if (nb > 0 && na === 0) status = 'removed';
  else if (nb === na) status = 'same';
  return [{ path: 'signatures', label: 'Signatures', status, before: text(nb), after: text(na) }];
}

const INTERFACE_LISTS: ReadonlyArray<readonly [string, string]> = [
  ['supportedInterfaces', 'supported_interfaces'],
  ['additionalInterfaces', 'additional_interfaces'],
];

function collectUrls(card: Obj): { urls: Map<string, string>; primary: string | null } {
  const urls = new Map<string, string>();
  const take = (path: string, value: unknown) => {
    if (typeof value === 'string' && value !== '') urls.set(path, value);
  };
  take('url', card.url);
  take('endpoint', card.endpoint);
  const endpoints = card.endpoints;
  if (Array.isArray(endpoints)) {
    endpoints.forEach((e, i) => take(`endpoints[${i}].url`, asObj(e).url));
  }
  for (const [camel, snake] of INTERFACE_LISTS) {
    const list = read(card, camel, snake);
    if (Array.isArray(list)) list.forEach((e, i) => take(`${camel}[${i}].url`, asObj(e).url));
  }
  const primary =
    ['supportedInterfaces[0].url', 'url', 'endpoint', 'endpoints[0].url'].find(p => urls.has(p)) ??
    null;
  return { urls, primary };
}

const URL_GROUP_RANK = [
  'url',
  'endpoint',
  'endpoints',
  'supportedInterfaces',
  'additionalInterfaces',
];

function urlPathRank(path: string): [number, number] {
  const group = path.split(/[.[]/)[0];
  const index = /\[(\d+)\]/.exec(path);
  return [URL_GROUP_RANK.indexOf(group), index ? Number(index[1]) : 0];
}

function endpointItems(before: Obj, after: Obj): DiffItem[] {
  const b = collectUrls(before);
  const a = collectUrls(after);
  const paths = [...new Set([...b.urls.keys(), ...a.urls.keys()])].sort((x, y) => {
    const [gx, ix] = urlPathRank(x);
    const [gy, iy] = urlPathRank(y);
    return gx - gy || ix - iy;
  });
  return paths.map(path => {
    const item = compareValues(path, path, b.urls.get(path), a.urls.get(path));
    return path === b.primary || path === a.primary ? { ...item, primary: true } : item;
  });
}

const HANDLED_KEYS: ReadonlySet<string> = new Set([
  'securitySchemes',
  'security_schemes',
  'security',
  'securityRequirements',
  'security_requirements',
  'signatures',
  'url',
  'endpoint',
  'endpoints',
  'supportedInterfaces',
  'supported_interfaces',
  'additionalInterfaces',
  'additional_interfaces',
]);

function skillItems(before: Obj, after: Obj): DiffItem[] {
  const index = (card: Obj) => {
    const out = new Map<string, Obj>();
    skillList(card).forEach((skill, i) => {
      const id = typeof skill.id === 'string' && skill.id !== '' ? skill.id : `#${i + 1}`;
      out.set(id, withoutSkillSecurity(skill));
    });
    return out;
  };
  const b = index(before);
  const a = index(after);
  return [...new Set([...b.keys(), ...a.keys()])]
    .sort()
    .map(id => compareValues(`skills[${id}]`, `skills[${id}]`, b.get(id), a.get(id)));
}

function otherItems(before: Obj, after: Obj): DiffItem[] {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter(k => !HANDLED_KEYS.has(k))
    .sort();
  const items: DiffItem[] = [];
  for (const key of keys) {
    const b = has(before, key) ? before[key] : undefined;
    const a = has(after, key) ? after[key] : undefined;
    if (
      key === 'skills' &&
      (b === undefined || Array.isArray(b)) &&
      (a === undefined || Array.isArray(a))
    ) {
      items.push(...skillItems(before, after));
    } else if ((b === undefined || isObj(b)) && (a === undefined || isObj(a))) {
      items.push(
        ...compareMaps(
          asObj(b),
          asObj(a),
          name => `${key}.${name}`,
          name => `${key}.${name}`
        )
      );
    } else {
      items.push(compareValues(key, key, b, a));
    }
  }
  return items;
}

function rowStatus(items: DiffItem[]): RowStatus {
  if (items.length === 0) return 'absent';
  const differing = items.filter(i => i.status !== 'same');
  if (differing.length === 0) return 'same';
  if (differing.every(i => i.status === 'removed')) return 'removed';
  return 'changed';
}

const ROW_LABELS: Record<RowKey, string> = {
  signin: 'Sign-in',
  scope: 'Scope',
  signature: 'Signature',
  endpoint: 'Endpoint URL',
  other: 'Name, skills, capabilities',
};

export function diffAgentCards(beforeCard: unknown, afterCard: unknown): CardDiff {
  const before = asObj(beforeCard);
  const after = asObj(afterCard);
  const itemsByRow: Record<RowKey, DiffItem[]> = {
    signin: signinItems(before, after),
    scope: scopeItems(before, after),
    signature: signatureItems(before, after),
    endpoint: endpointItems(before, after),
    other: otherItems(before, after),
  };
  const rows = (Object.keys(ROW_LABELS) as RowKey[]).map(key => ({
    key,
    label: ROW_LABELS[key],
    status: rowStatus(itemsByRow[key]),
    items: itemsByRow[key],
  }));
  const all = rows.flatMap(r => r.items);
  const removedCount = all.filter(i => i.status === 'removed').length;
  const addedCount = all.filter(i => i.status === 'added').length;
  const modifiedCount = all.filter(i => i.status === 'changed').length;
  const changedCount = addedCount + modifiedCount;
  return {
    rows,
    changeCount: removedCount + changedCount,
    changedCount,
    removedCount,
    addedCount,
    modifiedCount,
  };
}

export function cardEra(card: unknown): CardEra {
  const o = asObj(card);
  const interfaces = read(o, 'supportedInterfaces', 'supported_interfaces');
  const requirements = read(o, 'securityRequirements', 'security_requirements');
  const version = typeof o.protocolVersion === 'string' ? o.protocolVersion : null;
  const is10 =
    Array.isArray(interfaces) ||
    Array.isArray(requirements) ||
    (version?.startsWith('1.') ?? false);
  const is03 =
    typeof o.url === 'string' ||
    Array.isArray(o.security) ||
    read(o, 'additionalInterfaces', 'additional_interfaces') !== undefined ||
    read(o, 'preferredTransport', 'preferred_transport') !== undefined ||
    (version !== null && !version.startsWith('1.'));
  if (is10 && is03) return 'both';
  if (is10) return '1.0';
  return is03 ? '0.3' : 'unknown';
}
