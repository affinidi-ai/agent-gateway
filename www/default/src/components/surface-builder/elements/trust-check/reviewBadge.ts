import { trustCheckReviewBadge } from './definition';

const SVG_NS = 'http://www.w3.org/2000/svg';
const BADGE_CLASS = 'node-migrated-badge';

/**
 * Adds or removes the review badge on a canvas node group so it matches the
 * node's config: drawn when the node needs review and missing, removed when
 * it no longer does. Used by the full canvas rebuild and by the lightweight
 * config update, so the badge follows Keep and its undo.
 */
export function syncTrustCheckReviewBadge(
  group: Element | null,
  node: { type: string; config?: any } | undefined,
  radius: number
): void {
  if (!group) return;
  const existing = Array.from(group.children).find(c => c.classList.contains(BADGE_CLASS));
  const badge = trustCheckReviewBadge(node);
  if (!badge) {
    existing?.remove();
    return;
  }
  if (existing) return;
  const g = document.createElementNS(SVG_NS, 'g');
  g.setAttribute('class', BADGE_CLASS);
  g.setAttribute('data-testid', badge.testid);
  g.setAttribute('transform', `translate(${radius * 0.75}, ${-radius * 0.75})`);
  const title = document.createElementNS(SVG_NS, 'title');
  title.textContent = badge.title;
  const circle = document.createElementNS(SVG_NS, 'circle');
  circle.setAttribute('r', '7');
  const text = document.createElementNS(SVG_NS, 'text');
  text.setAttribute('text-anchor', 'middle');
  text.setAttribute('dominant-baseline', 'central');
  text.setAttribute('font-size', '10px');
  text.setAttribute('font-weight', '700');
  text.setAttribute('pointer-events', 'none');
  text.textContent = '!';
  g.append(title, circle, text);
  group.appendChild(g);
}
