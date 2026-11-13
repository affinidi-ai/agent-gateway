import {
  describeConsentLimit,
  largestWholeUnit,
  secondsIn,
  storedConsentLimit,
} from '../consentLimit';

describe('consent time limit', () => {
  it('describes a limit in its largest whole unit', () => {
    expect(describeConsentLimit(21_600)).toBe('6 hours');
    expect(describeConsentLimit(86_400)).toBe('1 day');
    expect(describeConsentLimit(2_592_000)).toBe('30 days');
    expect(describeConsentLimit(5_400)).toBe('90 minutes');
    expect(describeConsentLimit(60)).toBe('1 minute');
    expect(describeConsentLimit(61)).toBe('61 seconds');
    expect(largestWholeUnit(3_600)).toEqual({ count: 1, unit: 'hours' });
  });

  it('knows the seconds in each unit', () => {
    expect(secondsIn('seconds')).toBe(1);
    expect(secondsIn('minutes')).toBe(60);
    expect(secondsIn('hours')).toBe(3_600);
    expect(secondsIn('days')).toBe(86_400);
  });

  it('takes only a positive whole number of seconds for a stored limit', () => {
    expect(storedConsentLimit(3_600)).toBe(3_600);
    expect(storedConsentLimit(0)).toBeUndefined();
    expect(storedConsentLimit(-60)).toBeUndefined();
    expect(storedConsentLimit(1.5)).toBeUndefined();
    expect(storedConsentLimit('3600')).toBeUndefined();
    expect(storedConsentLimit(null)).toBeUndefined();
    expect(storedConsentLimit(undefined)).toBeUndefined();
  });
});
