export type ConsentLimitUnit = 'seconds' | 'minutes' | 'hours' | 'days';

/** The seconds in each unit a consent time limit is given in, the largest first. */
const UNIT_SECONDS: [ConsentLimitUnit, number][] = [
  ['days', 86_400],
  ['hours', 3_600],
  ['minutes', 60],
  ['seconds', 1],
];

/** The units offered for a consent time limit, the smallest first. */
export const CONSENT_LIMIT_UNITS: ConsentLimitUnit[] = ['seconds', 'minutes', 'hours', 'days'];

/** The gateway's bounds on `max_consent_age_secs`: one minute to 365 days. */
export const MIN_CONSENT_LIMIT_SECS = 60;
export const MAX_CONSENT_LIMIT_SECS = 31_536_000;

export function secondsIn(unit: ConsentLimitUnit): number {
  return UNIT_SECONDS.find(([name]) => name === unit)![1];
}

/** A stored `max_consent_age_secs` when it is a limit: a positive whole number of seconds. */
export function storedConsentLimit(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : undefined;
}

/** `secs` as a count of its largest whole unit: 21600 is 6 hours. */
export function largestWholeUnit(secs: number): { count: number; unit: ConsentLimitUnit } {
  const [unit, size] = UNIT_SECONDS.find(([, size]) => secs % size === 0)!;
  return { count: secs / size, unit };
}

/** A consent time limit as a person reads it: "6 hours", "1 day". */
export function describeConsentLimit(secs: number): string {
  const { count, unit } = largestWholeUnit(secs);
  return `${count} ${count === 1 ? unit.slice(0, -1) : unit}`;
}
