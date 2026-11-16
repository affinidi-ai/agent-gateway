import {
  MISSING_AUTHORITY_CANVAS_REASON,
  type AuthorityDids,
  type MissingAuthority,
} from './_shared/authorityReference';
import { missingTrustCheckAuthorities, readQueries } from './trust-check/definition';
import { missingTrustRecorderAuthorities, readEntries } from './trust-recorder/definition';

type AnchorNodeLike = { type: string; config?: any };

interface AnchorElement {
  missing: (config: any, authorityDids: AuthorityDids) => MissingAuthority[];
  count: (config: any) => number;
  item: string;
  warning: (did: string) => string;
}

const ELEMENTS: Record<string, AnchorElement> = {
  'trust-check': {
    missing: missingTrustCheckAuthorities,
    count: config => readQueries(config).length,
    item: 'Query',
    warning: did =>
      `The Authority this Trust Check uses (${did}) no longer exists, so the check fails with AUTHORITY_NOT_FOUND. Pick another Authority, add an Authority with that DID, or remove the Trust Check.`,
  },
  'trust-recorder': {
    missing: missingTrustRecorderAuthorities,
    count: config => readEntries(config).length,
    item: 'Entry',
    warning: did =>
      `The Authority this Trust Recorder entry uses (${did}) no longer exists, so the entry writes no records. Pick another Authority, add an Authority with that DID, or remove the entry.`,
  },
};

/** The queries or entries of a Trust Check or Trust Recorder node whose Authority was deleted. */
export function missingAuthoritiesOf(
  node: AnchorNodeLike,
  authorityDids: AuthorityDids
): MissingAuthority[] {
  return ELEMENTS[node.type]?.missing(node.config, authorityDids) ?? [];
}

/** Full Save-blocking warning for the node's first Authority that was deleted, else null. */
export function missingAuthorityWarning(
  node: AnchorNodeLike,
  authorityDids: AuthorityDids
): string | null {
  const element = ELEMENTS[node.type];
  const first = element?.missing(node.config, authorityDids)[0];
  if (!element || !first) return null;
  const prefix = element.count(node.config) > 1 ? `${element.item} ${first.index + 1}: ` : '';
  return `${prefix}${element.warning(first.did)}`;
}

/** Short reason shown under the node on the canvas while it names a deleted Authority. */
export function missingAuthorityCanvasReason(
  node: AnchorNodeLike,
  authorityDids: AuthorityDids
): string | null {
  return missingAuthoritiesOf(node, authorityDids).length > 0
    ? MISSING_AUTHORITY_CANVAS_REASON
    : null;
}

/** The first Trust Check or Trust Recorder node that names a deleted Authority, with its warning. */
export function firstMissingAuthorityNode<T extends AnchorNodeLike>(
  nodes: readonly T[],
  authorityDids: AuthorityDids
): { node: T; warning: string } | null {
  for (const node of nodes) {
    const warning = missingAuthorityWarning(node, authorityDids);
    if (warning) return { node, warning };
  }
  return null;
}
