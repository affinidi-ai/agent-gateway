/** The extension the gateway adds to a card it serves: the agent's DID with a signed presentation. */
export const IDENTITY_CREDENTIAL_EXTENSION =
  'https://fabric.affinidi.io/extensions/agent-identity-credential/v1';

type Fields = Record<string, unknown>;

const isObject = (value: unknown): value is Fields =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const text = (value: unknown): string | null =>
  typeof value === 'string' && value.trim() ? value.trim() : null;

export interface AddedExtension {
  uri: string;
  /** `params.did`, when the extension names one. */
  did: string | null;
  /** `params.verifiablePresentation`, a JWT or JSON string, when present. */
  presentation: string | null;
}

/** What the gateway changed in the card it serves, compared with the card it started from. */
export interface GatewayChanges {
  /** The served URL, and the agent's own when the gateway rewrote it. */
  url: { served: string; upstream: string | null } | null;
  /** Extensions on the served card that the upstream card doesn't carry, or carries differently. */
  added: AddedExtension[];
  /** Extension URIs of the upstream card the served card no longer carries. */
  replaced: string[];
  /** Other top-level fields whose value differs. */
  otherFields: string[];
}

const extensionsOf = (card: Fields): Fields[] => {
  const extensions = isObject(card.capabilities) ? card.capabilities.extensions : undefined;
  return Array.isArray(extensions) ? extensions.filter(isObject) : [];
};

const addedExtension = (extension: Fields, uri: string): AddedExtension => {
  const params = isObject(extension.params) ? extension.params : {};
  return { uri, did: text(params.did), presentation: text(params.verifiablePresentation) };
};

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

const withoutExtensions = (card: Fields): unknown =>
  isObject(card.capabilities) ? { ...card.capabilities, extensions: undefined } : card.capabilities;

/**
 * The gateway's changes to `served`. With no `upstream` card (a card the A2A proxy generates),
 * only the identity credential extension is known to be the gateway's. `null` when nothing changed.
 */
export function gatewayChanges(served: unknown, upstream: unknown): GatewayChanges | null {
  if (!isObject(served)) return null;
  const servedExtensions = extensionsOf(served);

  if (!isObject(upstream)) {
    const credential = servedExtensions.find(e => e.uri === IDENTITY_CREDENTIAL_EXTENSION);
    return credential
      ? {
          url: null,
          added: [addedExtension(credential, IDENTITY_CREDENTIAL_EXTENSION)],
          replaced: [],
          otherFields: [],
        }
      : null;
  }

  const servedUrl = text(served.url);
  const upstreamUrl = text(upstream.url);
  const url =
    servedUrl && servedUrl !== upstreamUrl ? { served: servedUrl, upstream: upstreamUrl } : null;

  const upstreamExtensions = extensionsOf(upstream);
  const upstreamByUri = new Map(
    upstreamExtensions.flatMap(e => {
      const uri = text(e.uri);
      return uri ? [[uri, e] as const] : [];
    })
  );
  const servedUris = new Set(servedExtensions.map(e => text(e.uri)));

  const added = servedExtensions.flatMap(extension => {
    const uri = text(extension.uri);
    if (!uri) return [];
    const before = upstreamByUri.get(uri);
    return before && same(before, extension) ? [] : [addedExtension(extension, uri)];
  });
  const replaced = [...upstreamByUri.keys()].filter(uri => !servedUris.has(uri));

  const keys = new Set([...Object.keys(served), ...Object.keys(upstream)]);
  keys.delete('url');
  keys.delete('capabilities');
  const otherFields = [...keys].filter(key => !same(served[key], upstream[key]));
  if (!same(withoutExtensions(served), withoutExtensions(upstream))) {
    otherFields.push('capabilities');
  }

  return url || added.length || replaced.length || otherFields.length
    ? { url, added, replaced, otherFields }
    : null;
}
