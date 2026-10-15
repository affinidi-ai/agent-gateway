import {
  auditDeliveryLimitsError,
  auditDeliveryLimitsOf,
  auditDeliveryLimitsPayload,
  auditLimitError,
} from '../auditIntegrations';

describe('auditLimitError', () => {
  it('accepts an empty value and whole numbers of 1 or more', () => {
    expect(auditLimitError('')).toBeNull();
    expect(auditLimitError('  ')).toBeNull();
    expect(auditLimitError('1')).toBeNull();
    expect(auditLimitError(' 20 ')).toBeNull();
  });

  it('rejects zero, negative, fractional and non-numeric values', () => {
    for (const value of ['0', '-1', '1.5', 'ten', '1e3']) {
      expect(auditLimitError(value)).toBe('Enter a whole number of 1 or more, or leave it empty.');
    }
  });
});

describe('auditDeliveryLimitsOf', () => {
  it('reads the stored limits, empty when unset', () => {
    expect(auditDeliveryLimitsOf({ audit_max_attempts: 10, audit_drop_after_secs: 3600 })).toEqual({
      maxAttempts: '10',
      dropAfterSecs: '3600',
    });
    expect(auditDeliveryLimitsOf({ audit_max_attempts: null })).toEqual({
      maxAttempts: '',
      dropAfterSecs: '',
    });
  });
});

describe('auditDeliveryLimitsError', () => {
  it('names the first field that is not a valid limit', () => {
    expect(auditDeliveryLimitsError({ maxAttempts: '10', dropAfterSecs: '' })).toBeNull();
    expect(auditDeliveryLimitsError({ maxAttempts: '0', dropAfterSecs: '' })).toBe(
      'Give up on a record after N attempts: enter a whole number of 1 or more, or leave it empty.'
    );
    expect(auditDeliveryLimitsError({ maxAttempts: '', dropAfterSecs: '-5' })).toBe(
      'Skip records older than N seconds: enter a whole number of 1 or more, or leave it empty.'
    );
  });
});

describe('auditDeliveryLimitsPayload', () => {
  it('sends each limit that is set as a number', () => {
    expect(auditDeliveryLimitsPayload({ maxAttempts: '10', dropAfterSecs: '3600' }, false)).toEqual(
      { audit_max_attempts: 10, audit_drop_after_secs: 3600 }
    );
  });

  it('leaves out empty limits on create and clears them with null on edit', () => {
    const empty = { maxAttempts: '', dropAfterSecs: '' };
    expect(auditDeliveryLimitsPayload(empty, false)).toEqual({});
    expect(auditDeliveryLimitsPayload(empty, true)).toEqual({
      audit_max_attempts: null,
      audit_drop_after_secs: null,
    });
  });
});
