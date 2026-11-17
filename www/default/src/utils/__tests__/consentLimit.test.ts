import {
  consentLimitLabel,
  consentLimitSecondsOf,
  consentLimitUnitsFor,
  limitFieldsOf,
  takesConsent,
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

  it('reads a typed limit as seconds only when the gateway takes it', () => {
    expect(consentLimitSecondsOf('6', 'hours')).toBe(21_600);
    expect(consentLimitSecondsOf(' 30 ', 'days')).toBe(2_592_000);
    expect(consentLimitSecondsOf('1', 'minutes')).toBe(60);
    expect(consentLimitSecondsOf('365', 'days')).toBe(31_536_000);
    for (const [amount, unit] of [
      ['', 'hours'],
      ['0', 'minutes'],
      ['59', 'seconds'],
      ['366', 'days'],
      ['1.5', 'hours'],
      ['-2', 'hours'],
      ['two', 'hours'],
    ] as const) {
      expect(consentLimitSecondsOf(amount, unit)).toBeNull();
    }
  });

  it('starts a limit field from the largest whole unit, or empty in hours', () => {
    expect(limitFieldsOf(21_600)).toEqual({ amount: '6', unit: 'hours' });
    expect(limitFieldsOf(2_592_000)).toEqual({ amount: '30', unit: 'days' });
    expect(limitFieldsOf(900)).toEqual({ amount: '15', unit: 'minutes' });
    expect(limitFieldsOf(null)).toEqual({ amount: '', unit: 'hours' });
    expect(limitFieldsOf(undefined)).toEqual({ amount: '', unit: 'hours' });
  });

  it('says a person consents only to an Authorization Code provider', () => {
    expect(takesConsent('oauth2_authorization_code')).toBe(true);
    expect(takesConsent('oauth2_client_credentials')).toBe(false);
    expect(takesConsent(undefined)).toBe(false);
  });

  it('names a limit as a span: "6-hour limit"', () => {
    expect(consentLimitLabel(21_600)).toBe('6-hour limit');
    expect(consentLimitLabel(2_592_000)).toBe('30-day limit');
    expect(consentLimitLabel(86_400)).toBe('1-day limit');
    expect(consentLimitLabel(5_400)).toBe('90-minute limit');
    expect(consentLimitLabel(90)).toBe('90-second limit');
  });

  it('offers seconds only for a stored limit that is not a whole number of minutes', () => {
    expect(consentLimitUnitsFor(undefined)).toEqual(['minutes', 'hours', 'days']);
    expect(consentLimitUnitsFor(60)).toEqual(['minutes', 'hours', 'days']);
    expect(consentLimitUnitsFor(21_600)).toEqual(['minutes', 'hours', 'days']);
    expect(consentLimitUnitsFor(90)).toEqual(['seconds', 'minutes', 'hours', 'days']);
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
