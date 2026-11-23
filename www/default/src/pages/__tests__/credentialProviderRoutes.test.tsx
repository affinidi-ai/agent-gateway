import React, { Suspense } from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { credentialProviderRoutes } from '../credentialProviderRoutes';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    loading: false,
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));
jest.mock('../EditCredentialProviderPage', () => () => <div>provider editor</div>);

const Where: React.FC = () => {
  const location = useLocation();
  return <div data-testid="where">{`${location.pathname}${location.search}`}</div>;
};

function visit(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/" element={<div>dashboard</div>} />
          {credentialProviderRoutes()}
          <Route path="*" element={<Where />} />
        </Routes>
      </Suspense>
    </MemoryRouter>
  );
}

beforeEach(() => {
  mockPermissions = {};
});

test.each(['/oidc-providers', '/oidc-providers/abc', '/oidc-providers/new'])(
  '%s lands on the Credential providers tab',
  async path => {
    visit(path);
    expect(await screen.findByTestId('where')).toHaveTextContent(
      '/credentials?tab=credential-providers'
    );
  }
);

test('credential_providers.view opens a provider', async () => {
  mockPermissions = { 'credential_providers.view': true };
  visit('/credential-providers/p1');
  expect(await screen.findByText('provider editor')).toBeInTheDocument();
});

test('a viewer is sent to the dashboard from the new-provider page', async () => {
  mockPermissions = { 'credential_providers.view': true };
  visit('/credential-providers/new');
  expect(await screen.findByText('dashboard')).toBeInTheDocument();
});

test('credential_providers.edit opens the new-provider page', async () => {
  mockPermissions = { 'credential_providers.edit': true };
  visit('/credential-providers/new');
  expect(await screen.findByText('provider editor')).toBeInTheDocument();
});

test('settings.edit alone no longer opens a provider', async () => {
  mockPermissions = { 'settings.edit': true, 'settings.view': true };
  visit('/credential-providers/p1');
  expect(await screen.findByText('dashboard')).toBeInTheDocument();
});
