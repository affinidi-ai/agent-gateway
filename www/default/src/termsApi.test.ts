import { apiClient } from './api';
import {
  acceptTerms,
  loadApplicableTerms,
  termsRequirementKey,
  TermsApiError,
  TermsRequirement,
} from './termsApi';

jest.mock('./api', () => ({
  apiClient: { fetch: jest.fn() },
}));

const requirement: TermsRequirement = {
  terms_type: 'affinidi',
  document_id: 'affinidi-terms',
  version_id: 'v1',
  version: '1',
  title: 'Affinidi Terms',
  url: 'https://example.com/terms',
};

const fetchMock = apiClient.fetch as jest.Mock;

beforeEach(() => fetchMock.mockReset());

test('builds one stable key for a Terms requirement', () => {
  expect(termsRequirementKey(requirement)).toBe('affinidi:affinidi-terms:v1');
});

test.each([
  ['TERMS_INVALID', 'Version has already been published', 'Version has already been published'],
  ['TERMS_OPERATIONAL_FAILURE', 'private storage details', 'TERMS_OPERATIONAL_FAILURE'],
])('exposes only validation messages for %s', async (code, message, expected) => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ code, message }), { status: 400 }));
  await expect(acceptTerms([requirement])).rejects.toMatchObject({ code, message: expected });
});

test('loads public registration metadata', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ terms: [requirement] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  await expect(loadApplicableTerms()).resolves.toEqual([requirement]);
  expect(fetchMock).toHaveBeenCalledWith('/api/v1/terms/applicable');
});

test('submits exact version ids with explicit acceptance', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ accepted: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  await acceptTerms([requirement]);

  expect(fetchMock).toHaveBeenCalledWith('/api/v1/terms/acceptances', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accepted_terms: [{ terms_type: 'affinidi', version_id: 'v1', accepted: true }],
    }),
  });
});

test('preserves current requirements from a stale response', async () => {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify({ code: 'TERMS_VERSION_STALE', required_terms: [requirement] }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' },
    })
  );

  await expect(acceptTerms([requirement])).rejects.toMatchObject<TermsApiError>({
    code: 'TERMS_VERSION_STALE',
    requiredTerms: [requirement],
  });
});

test('rejects a successful response with a malformed JSON body', async () => {
  fetchMock.mockResolvedValue(new Response('<html>unexpected</html>', { status: 200 }));

  await expect(loadApplicableTerms()).rejects.toThrow(
    'Expected a JSON response but received: <html>unexpected</html>'
  );
});

test('maps a malformed error response to an operational failure', async () => {
  fetchMock.mockResolvedValue(new Response('<html>unavailable</html>', { status: 502 }));

  await expect(loadApplicableTerms()).rejects.toMatchObject<TermsApiError>({
    code: 'TERMS_OPERATIONAL_FAILURE',
    status: 502,
  });
});
