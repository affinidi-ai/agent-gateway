const MAX_EXPIRY_DAYS = 3650;

export interface AccessTokenExpiryValidation {
  expiresAt?: string;
  error?: string;
}

export function toLocalDateTimeInput(date: Date): string {
  const localTime = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return localTime.toISOString().slice(0, 16);
}

export function validateAccessTokenExpiry(
  neverExpires: boolean,
  value: string,
  now = new Date()
): AccessTokenExpiryValidation {
  if (neverExpires) return {};
  if (!value) return { error: 'Choose an expiration date and time.' };

  const expiry = new Date(value);
  if (Number.isNaN(expiry.getTime())) return { error: 'Enter a valid expiration date and time.' };
  if (expiry <= now) return { error: 'Expiration must be in the future.' };

  const latest = new Date(now.getTime() + MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
  if (expiry > latest) return { error: `Expiration must be within ${MAX_EXPIRY_DAYS} days.` };

  return { expiresAt: expiry.toISOString() };
}

export function accessTokenExpiryBounds(now: Date): { min: string; max: string } {
  return {
    min: toLocalDateTimeInput(now),
    max: toLocalDateTimeInput(new Date(now.getTime() + MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000)),
  };
}
