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
  /**
   * The upstream extension URI it rewrites: its own URI when the upstream card carries it
   * differently, else an upstream extension the served card dropped, else `null`.
   */
  original: string | null;
  /** `params.did`, when the extension names one. */
  did: string | null;
  /** `params.did` of the upstream extension named by `original`, when it names one. */
  originalDid: string | null;
  /** `params.verifiablePresentation` as text (a JWT, or JSON for an object), when it has one. */
  vp: string | null;
  /** Whether the upstream extension named by `original` carries a presentation. */
  originalHasVp: boolean;
}

/** A top-level field whose value differs, each side as text; `null` when not set. */
export interface ChangedField {
  field: string;
  original: string | null;
  rewritten: string | null;
}

/** What the gateway changed in the card it serves, compared with the card it started from. */
export interface GatewayChanges {
  /** The served URL, and the agent's own when the gateway rewrote it. */
  url: { served: string; upstream: string | null } | null;
  /** Extensions on the served card that the upstream card doesn't carry, or carries differently. */
  added: AddedExtension[];
  /** Extension URIs of the upstream card the served card dropped and no added extension rewrites. */
  removed: string[];
  /** Other top-level fields whose value differs. */
  otherFields: ChangedField[];
}

const extensionsOf = (card: Fields): Fields[] => {
  const extensions = isObject(card.capabilities) ? card.capabilities.extensions : undefined;
  return Array.isArray(extensions) ? extensions.filter(isObject) : [];
};

const didOf = (extension: Fields | undefined): string | null =>
  extension && isObject(extension.params) ? text(extension.params.did) : null;

const vpOf = (extension: Fields | undefined): string | null => {
  const vp =
    extension && isObject(extension.params) ? extension.params.verifiablePresentation : null;
  if (isObject(vp)) return JSON.stringify(vp);
  return text(vp);
};

const addedExtension = (
  extension: Fields,
  uri: string,
  original: string | null,
  originalExtension?: Fields
): AddedExtension => ({
  uri,
  original,
  did: didOf(extension),
  originalDid: didOf(originalExtension),
  vp: vpOf(extension),
  originalHasVp: vpOf(originalExtension) !== null,
});

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/** A field value as text: a string as is, anything else as JSON; `null` when not set. */
const display = (value: unknown): string | null => {
  if (value === undefined) return null;
  return typeof value === 'string' ? value : (JSON.stringify(value) ?? null);
};

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
          added: [addedExtension(credential, IDENTITY_CREDENTIAL_EXTENSION, null)],
          removed: [],
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
  // Dropped upstream extensions, paired in order with the new extensions that take their place.
  const removed = [...upstreamByUri.keys()].filter(uri => !servedUris.has(uri));

  const added = servedExtensions.flatMap(extension => {
    const uri = text(extension.uri);
    if (!uri) return [];
    const before = upstreamByUri.get(uri);
    if (before) {
      return same(before, extension) ? [] : [addedExtension(extension, uri, uri, before)];
    }
    const original = removed.shift() ?? null;
    return [
      addedExtension(
        extension,
        uri,
        original,
        original === null ? undefined : upstreamByUri.get(original)
      ),
    ];
  });

  const keys = new Set([...Object.keys(served), ...Object.keys(upstream)]);
  keys.delete('url');
  keys.delete('capabilities');
  const otherFields: ChangedField[] = [...keys]
    .filter(key => !same(served[key], upstream[key]))
    .map(key => ({
      field: key,
      original: display(upstream[key]),
      rewritten: display(served[key]),
    }));
  const servedCapabilities = withoutExtensions(served);
  const upstreamCapabilities = withoutExtensions(upstream);
  if (!same(servedCapabilities, upstreamCapabilities)) {
    otherFields.push({
      field: 'capabilities',
      original: display(upstreamCapabilities),
      rewritten: display(servedCapabilities),
    });
  }

  return url || added.length || removed.length || otherFields.length
    ? { url, added, removed, otherFields }
    : null;
}
