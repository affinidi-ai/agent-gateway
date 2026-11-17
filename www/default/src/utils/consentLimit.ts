export type ConsentLimitUnit = 'seconds' | 'minutes' | 'hours' | 'days';

/** The seconds in each unit a consent time limit is given in, the largest first. */
const UNIT_SECONDS: [ConsentLimitUnit, number][] = [
  ['days', 86_400],
  ['hours', 3_600],
  ['minutes', 60],
  ['seconds', 1],
];

/**
 * The units offered for a consent time limit, the smallest first: minutes, hours and days, and
 * seconds too while the stored limit is not a whole number of minutes, so it loads and saves as is.
 */
export function consentLimitUnitsFor(storedSecs: number | undefined): ConsentLimitUnit[] {
  const units: ConsentLimitUnit[] = ['minutes', 'hours', 'days'];
  return storedSecs !== undefined && storedSecs % 60 !== 0 ? ['seconds', ...units] : units;
}

/** The gateway's bounds on `max_consent_age_secs`: one minute to 365 days. */
export const MIN_CONSENT_LIMIT_SECS = 60;
export const MAX_CONSENT_LIMIT_SECS = 31_536_000;
/** Those bounds as a person reads them. */
export const CONSENT_LIMIT_RANGE = '1 minute to 365 days';

/** Whether a person consents to a provider of this type: only an Authorization Code provider. */
export function takesConsent(providerType: string | undefined): boolean {
  return providerType === 'oauth2_authorization_code';
}

export function secondsIn(unit: ConsentLimitUnit): number {
  return UNIT_SECONDS.find(([name]) => name === unit)![1];
}

/**
 * The seconds of `amount` in `unit` when that is a limit the gateway takes, a whole number from
 * one minute to 365 days; `null` otherwise.
 */
export function consentLimitSecondsOf(amount: string, unit: ConsentLimitUnit): number | null {
  const typed = amount.trim();
  if (!/^\d+$/.test(typed)) return null;
  const secs = Number(typed) * secondsIn(unit);
  return secs >= MIN_CONSENT_LIMIT_SECS && secs <= MAX_CONSENT_LIMIT_SECS ? secs : null;
}

/** A stored `max_consent_age_secs` when it is a limit: a positive whole number of seconds. */
export function storedConsentLimit(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : undefined;
}

/** A stored binding's `max_consent_age_secs` as the form field that keeps it; none without a limit. */
export function consentLimitFieldOf(api: { max_consent_age_secs?: unknown }): {
  max_consent_age_secs?: number;
} {
  const secs = storedConsentLimit(api.max_consent_age_secs);
  return secs === undefined ? {} : { max_consent_age_secs: secs };
}

/** `secs` as a count of its largest whole unit: 21600 is 6 hours. */
export function largestWholeUnit(secs: number): { count: number; unit: ConsentLimitUnit } {
  const [unit, size] = UNIT_SECONDS.find(([, size]) => secs % size === 0)!;
  return { count: secs / size, unit };
}

/**
 * A limit as the amount and unit a field starts from: its largest whole unit, or an empty amount
 * in hours when there is none.
 */
export function limitFieldsOf(secs: number | null | undefined): {
  amount: string;
  unit: ConsentLimitUnit;
} {
  if (!secs) return { amount: '', unit: 'hours' };
  const { count, unit } = largestWholeUnit(secs);
  return { amount: String(count), unit };
}

/** A consent time limit as a person reads it: "6 hours", "1 day". */
export function describeConsentLimit(secs: number): string {
  const { count, unit } = largestWholeUnit(secs);
  return `${count} ${count === 1 ? unit.slice(0, -1) : unit}`;
}

/** A consent time limit named as a span: "6-hour limit", "30-day limit". */
export function consentLimitLabel(secs: number): string {
  const { count, unit } = largestWholeUnit(secs);
  return `${count}-${unit.slice(0, -1)} limit`;
}
