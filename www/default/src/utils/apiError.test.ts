import { extractErrorMessage, formatApiError, getErrorMessage } from './apiError';

describe('extractErrorMessage', () => {
  it('pulls the message from common JSON shapes', () => {
    expect(extractErrorMessage('{"message":"Limit reached"}')).toBe('Limit reached');
    expect(extractErrorMessage('{"error":"Bad request"}')).toBe('Bad request');
    expect(extractErrorMessage('{"error":{"message":"Nested"}}')).toBe('Nested');
    expect(extractErrorMessage('{"detail":"Not found"}')).toBe('Not found');
  });

  it('prefers the surface API `details` over the short `error` label', () => {
    expect(
      extractErrorMessage(
        '{"error":"Forbidden","details":"Appliance limit reached for \'surfaces\'."}'
      )
    ).toBe("Appliance limit reached for 'surfaces'.");
  });

  it('falls back to the raw text when the body is not JSON', () => {
    expect(extractErrorMessage('plain text error')).toBe('plain text error');
  });

  it('returns null for empty/whitespace bodies', () => {
    expect(extractErrorMessage('')).toBeNull();
    expect(extractErrorMessage('   ')).toBeNull();
    expect(extractErrorMessage(null)).toBeNull();
    expect(extractErrorMessage(undefined)).toBeNull();
  });

  it('returns the raw JSON when no known message field is present', () => {
    expect(extractErrorMessage('{"code":42}')).toBe('{"code":42}');
  });
});

describe('formatApiError', () => {
  it('shows the message with the status in parentheses', () => {
    expect(
      formatApiError(
        403,
        '{"message":"Appliance limit reached for \'secrets.secret\': 5 of 5 in use."}',
        'Forbidden'
      )
    ).toBe("Appliance limit reached for 'secrets.secret': 5 of 5 in use. (403)");
  });

  it('extracts the surface limit message from the `details` field', () => {
    expect(
      formatApiError(
        403,
        '{"error":"Forbidden","details":"Appliance limit reached for \'surfaces.agent\': 5 of 5 in use. Upgrade your appliance tier to add more."}',
        'Forbidden'
      )
    ).toBe(
      "Appliance limit reached for 'surfaces.agent': 5 of 5 in use. Upgrade your appliance tier to add more. (403)"
    );
  });

  it('falls back to the status text when there is no body', () => {
    expect(formatApiError(500, '', 'Internal Server Error')).toBe('Internal Server Error (500)');
  });

  it('falls back to a generic label when nothing is available', () => {
    expect(formatApiError(502, '', '')).toBe('Request failed (502)');
  });

  it('omits the parenthetical when no status is provided', () => {
    expect(formatApiError(undefined, '{"error":"boom"}')).toBe('boom');
  });
});

describe('getErrorMessage', () => {
  it('reads the message from a thrown Error (as the api client throws)', () => {
    expect(getErrorMessage(new Error("Appliance limit reached for 'secrets.secret'. (403)"))).toBe(
      "Appliance limit reached for 'secrets.secret'. (403)"
    );
  });

  it('falls back when the value carries no usable message', () => {
    expect(getErrorMessage(null, 'Failed to save secret')).toBe('Failed to save secret');
    expect(getErrorMessage({}, 'Failed to save secret')).toBe('Failed to save secret');
  });

  it('extracts from an axios-style response body', () => {
    expect(getErrorMessage({ response: { data: { message: 'Nope' } } })).toBe('Nope');
    expect(
      getErrorMessage({
        response: { data: '{"error":"Forbidden","details":"Limit reached"}' },
      })
    ).toBe('Limit reached');
  });
});
