import { CustomerTermsSection } from './CustomerTermsSection';
import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { AffinidiTermsSection } from './sections';

const draft = {
  title: 'Customer T&C',
  version: '1',
  url: 'https://example.com/terms',
  requires_reconsent: true,
};

const current = {
  terms_type: 'customer' as const,
  document_id: 'customer-terms',
  version_id: 'customer:1',
  version: '1',
  title: 'Customer T&C',
  url: 'https://example.com/terms',
  requires_reconsent: true,
  published_at: '2026-09-10T12:00:00Z',
};

const mountSection = (versionAlreadyPublished = false, onPublish = jest.fn()) => {
  render(
    <CustomerTermsSection
      draft={draft}
      setDraft={jest.fn()}
      versionAlreadyPublished={versionAlreadyPublished}
      canEdit
      saving={false}
      onPublish={onPublish}
      onDeactivate={jest.fn()}
    />
  );
  return onPublish;
};

test('shows degraded Affinidi metadata status to administrators', () => {
  render(
    <AffinidiTermsSection
      affinidi={undefined}
      affinidiProvider={{
        state: 'degraded',
        last_successful_refresh: '2026-09-02T10:00:00Z',
      }}
    />
  );

  expect(screen.getByText(/latest metadata could not be refreshed/i)).toBeInTheDocument();
  expect(screen.getByText(/last successful refresh/i)).toHaveAttribute('title');
});

test('publishes Customer T&C in one action', () => {
  const onPublish = mountSection();

  fireEvent.click(screen.getByTestId('terms-publish-button'));

  expect(onPublish).toHaveBeenCalledTimes(1);
  expect(screen.queryByTestId('terms-save-draft-button')).not.toBeInTheDocument();
});

test('prevents publishing a reused version', () => {
  mountSection(true);

  expect(screen.getByTestId('terms-publish-button')).toBeDisabled();
});

test('explains and confirms Customer T&C deactivation', () => {
  const onDeactivate = jest.fn();
  render(
    <CustomerTermsSection
      current={current}
      draft={draft}
      setDraft={jest.fn()}
      versionAlreadyPublished={false}
      canEdit
      saving={false}
      onPublish={jest.fn()}
      onDeactivate={onDeactivate}
    />
  );

  const deactivate = screen.getByTestId('terms-deactivate-button');
  expect(deactivate).toHaveAttribute('title', 'Deactivate Customer T&C');
  expect(screen.queryByTestId('terms-deactivate-confirmation')).not.toBeInTheDocument();

  fireEvent.click(deactivate);

  expect(onDeactivate).not.toHaveBeenCalled();
  expect(
    screen.getByText(/published versions and acceptance records will be retained/i)
  ).toBeInTheDocument();
  expect(screen.getByText(/publish a new version/i)).toBeInTheDocument();
  expect(screen.getByTestId('terms-cancel-deactivation-button')).toBeInTheDocument();

  fireEvent.click(screen.getByTestId('terms-confirm-deactivate-button'));
  expect(onDeactivate).toHaveBeenCalledTimes(1);
});
