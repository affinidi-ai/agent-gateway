import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { endingConsentsOf, shortensConsentLimit } from './credentialProviderForm';

/** How long the limit must stay unchanged before the gateway is asked what saving it ends. */
const ASK_AFTER_MS = 400;

/** `encodeURIComponent` keeps `.` and `..`, which as a path segment would leave the provider. */
const isProviderSegment = (id: string) => id !== '.' && id !== '..';

/**
 * How many active consents of a stored provider saving `limitSecs` ends at once, from
 * `GET /credential-providers/{id}/consent-impact`. `null` for a new provider, for a limit that
 * shortens nothing, while the limit is still changing, and when the gateway cannot say.
 */
export function useConsentImpact(
  providerId: string | undefined,
  limitSecs: number | null,
  storedSecs: number | undefined
): number | null {
  const [ending, setEnding] = useState<number | null>(null);
  const asks =
    providerId !== undefined &&
    isProviderSegment(providerId) &&
    shortensConsentLimit(limitSecs, storedSecs);

  useEffect(() => {
    setEnding(null);
    if (!asks || providerId === undefined) return;
    let current = true;
    const timer = setTimeout(async () => {
      try {
        const response = await apiClient.fetch(
          `/api/v1/credential-providers/${encodeURIComponent(providerId)}/consent-impact?max_consent_age_secs=${limitSecs}`
        );
        const answer = response.ok ? await response.json() : null;
        if (current) setEnding(endingConsentsOf(answer));
      } catch {
        if (current) setEnding(null);
      }
    }, ASK_AFTER_MS);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [asks, providerId, limitSecs]);

  return ending;
}
