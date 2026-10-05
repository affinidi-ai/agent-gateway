import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { acceptTerms, loadTermsStatus } from '../../termsApi';
import TermsConsentPage from '.';

jest.mock('../../termsApi', () => ({
  ...jest.requireActual('../../termsApi'),
  acceptTerms: jest.fn(),
  loadTermsStatus: jest.fn(),
}));

const requirement = {
  terms_type: 'affinidi' as const,
  document_id: 'affinidi-terms',
  version_id: 'v1',
  version: '1',
  title: 'Affinidi Terms',
  url: 'https://example.com/terms',
};

beforeEach(() => {
  jest.resetAllMocks();
  (loadTermsStatus as jest.Mock).mockResolvedValue({
    consent_required: true,
    required_terms: [requirement],
  });
  (acceptTerms as jest.Mock).mockResolvedValue({ accepted: true });
});

test('requires every displayed term before recording acceptance', async () => {
  const onAccepted = jest.fn();
  render(<TermsConsentPage onAccepted={onAccepted} onLogout={jest.fn()} />);

  const checkbox = await screen.findByTestId('terms-consent-affinidi');
  const submit = screen.getByTestId('terms-consent-submit-button');
  expect(submit).toBeDisabled();

  fireEvent.click(checkbox);
  expect(submit).toBeEnabled();
  fireEvent.click(submit);

  await waitFor(() => expect(acceptTerms).toHaveBeenCalledWith([requirement]));
  await waitFor(() => expect(onAccepted).toHaveBeenCalledTimes(1));
});
