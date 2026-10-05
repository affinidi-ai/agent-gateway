import { act, renderHook, waitFor } from '@testing-library/react';
import {
  loadTermsDefinitions,
  publishCustomerTerms,
  saveCustomerTermsDraft,
  TermsApiError,
} from '../../termsApi';
import { useTermsManager } from './useTermsManager';

jest.mock('../../termsApi', () => ({
  ...jest.requireActual('../../termsApi'),
  deactivateCustomerTerms: jest.fn(),
  loadTermsDefinitions: jest.fn(),
  publishCustomerTerms: jest.fn(),
  saveCustomerTermsDraft: jest.fn(),
}));

const loadTerms = loadTermsDefinitions as jest.MockedFunction<typeof loadTermsDefinitions>;
const saveDraft = saveCustomerTermsDraft as jest.MockedFunction<typeof saveCustomerTermsDraft>;
const publishTerms = publishCustomerTerms as jest.MockedFunction<typeof publishCustomerTerms>;

beforeEach(() => {
  jest.resetAllMocks();
});

test.each([
  [
    new TermsApiError(
      'TERMS_INVALID',
      400,
      [],
      'Customer Terms version has already been published'
    ),
    'Customer Terms version has already been published',
  ],
  [
    new TermsApiError('TERMS_OPERATIONAL_FAILURE', 503),
    'The Terms configuration could not be updated.',
  ],
])('reports safe publication errors', async (error, expected) => {
  loadTerms.mockResolvedValue({ customer: { id: 'customer', versions: [] } });
  saveDraft.mockRejectedValue(error);
  const { result } = renderHook(() => useTermsManager());
  await waitFor(() => expect(result.current.definitions).not.toBeNull());
  await act(async () => {
    await result.current.publish();
  });
  expect(result.current.error).toBe(expected);
  expect(publishTerms).not.toHaveBeenCalled();
});

test('clears the form after publishing', async () => {
  loadTerms
    .mockResolvedValueOnce({ customer: { id: 'customer', versions: [] } })
    .mockResolvedValueOnce({
      customer: {
        id: 'customer',
        current_version_id: 'customer-v1',
        versions: [
          {
            terms_type: 'customer',
            document_id: 'customer',
            version_id: 'customer-v1',
            version: '1',
            title: 'Customer T&C',
            url: 'https://example.com/terms',
            requires_reconsent: true,
            published_at: '2026-09-01T00:00:00Z',
          },
        ],
      },
    });
  saveDraft.mockResolvedValue({ id: 'customer', versions: [] });
  publishTerms.mockResolvedValue({
    terms_type: 'customer',
    document_id: 'customer',
    version_id: 'customer-v1',
    version: '1',
    title: 'Customer T&C',
    url: 'https://example.com/terms',
    requires_reconsent: true,
    published_at: '2026-09-01T00:00:00Z',
  });
  const { result } = renderHook(() => useTermsManager());
  await waitFor(() => expect(result.current.definitions).not.toBeNull());

  act(() => {
    result.current.setDraft({
      title: 'Customer T&C',
      version: '1',
      url: 'https://example.com/terms',
      requires_reconsent: true,
    });
  });
  await act(async () => {
    await result.current.publish();
  });

  expect(result.current.draft).toEqual({
    title: '',
    version: '',
    url: '',
    requires_reconsent: true,
  });
  expect(result.current.versionAlreadyPublished).toBe(false);
});
