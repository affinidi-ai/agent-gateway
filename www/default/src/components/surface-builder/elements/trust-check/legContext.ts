import type { TrustCheckLeg } from './definition';

/**
 * What a Trust Check on a leg checks. Both the sidebar and the fullscreen editor open with the
 * intro; the sidebar adds the subject and summary.
 */
export interface TrustCheckLegContext {
  /** One line on what the leg checks. */
  intro: string;
  /** Who the empty state says a query verifies. */
  subject: string;
  summary: string;
}

export function describeTrustCheckLeg(leg: TrustCheckLeg): TrustCheckLegContext {
  if (leg === 'caller') {
    return {
      intro: 'Checks the caller against a trust registry before the request reaches the agent.',
      subject: 'the caller',
      summary:
        'Verify the CALLER identity against a trust registry before the request reaches the agent.',
    };
  }
  return {
    intro:
      'Checks the target agent against a trust registry before the request leaves the gateway.',
    subject: 'the upstream agent',
    summary: 'Verify the TARGET identity (upstream agent) before the request leaves the gateway.',
  };
}
