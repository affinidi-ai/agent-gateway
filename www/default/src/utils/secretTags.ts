/**
 * Registry of secret tags the dashboard filters on when picking a secret from a
 * dropdown. Tagging a secret with one of these makes it appear (by default) in
 * the matching picker, so surfacing them as click-to-add suggestions in the
 * secret editor helps operators tag secrets consistently.
 *
 * Add an entry here whenever a new UI introduces a tag-based secret filter.
 */
export interface KnownSecretTag {
  /** The tag value stored on the secret. */
  tag: string;
  /** What tagging a secret this way does — shown as the suggestion's tooltip. */
  description: string;
}

export const KNOWN_SECRET_TAGS: KnownSecretTag[] = [
  {
    tag: 'sts',
    description: 'Appears by default in the STS Client secret picker (Credentials → STS Clients).',
  },
];

/** The tag the STS Client secret picker filters on by default. */
export const STS_SECRET_TAG = 'sts';
