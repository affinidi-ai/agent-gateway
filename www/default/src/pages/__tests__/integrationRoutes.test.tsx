import React, { Suspense } from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { integrationRoutes } from '../integrationRoutes';
import { endpointPath, integrationPath, ROUTES } from '../../routes';

let mockPermissions: Record<string, boolean> = {};

jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({
    loading: false,
    hasPermission: (feature: string) => mockPermissions[feature] === true,
  }),
}));

jest.mock('../IntegrationsPage', () => () => <div>integrations list</div>);
jest.mock('../AddIntegrationWizardPage', () => () => <div>new integration</div>);
jest.mock('../EditIntegrationPage', () => () => <div>integration editor</div>);
jest.mock('../EndpointEditorPage', () => () => <div>endpoint editor</div>);

async function visit(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Suspense fallback={null}>
        <Routes>
          <Route path={ROUTES.DASHBOARD} element={<div>dashboard</div>} />
          {integrationRoutes()}
          <Route path="*" element={<div>no route</div>} />
        </Routes>
      </Suspense>
    </MemoryRouter>
  );
}

beforeEach(() => {
  mockPermissions = {};
});

test('integrations.view opens the integrations page', async () => {
  mockPermissions = { 'integrations.view': true };

  await visit(ROUTES.INTEGRATIONS);

  expect(await screen.findByText('integrations list')).toBeInTheDocument();
});

test('MCP proxy permissions no longer open the integrations page', async () => {
  mockPermissions = { 'mcp_proxies.view': true, 'mcp_proxies.edit': true };

  await visit(ROUTES.INTEGRATIONS);

  expect(await screen.findByText('dashboard')).toBeInTheDocument();
});

test.each([
  ['a new integration', ROUTES.INTEGRATION_NEW, 'new integration'],
  ['an integration', integrationPath('int-1'), 'integration editor'],
  ['a new endpoint', ROUTES.ENDPOINT_NEW, 'endpoint editor'],
  ['an endpoint', endpointPath('e1'), 'endpoint editor'],
])('integrations.edit opens %s', async (_, path, page) => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };

  await visit(path);

  expect(await screen.findByText(page)).toBeInTheDocument();
});

test.each([
  ROUTES.INTEGRATION_NEW,
  integrationPath('int-1'),
  ROUTES.ENDPOINT_NEW,
  endpointPath('e1'),
])('a viewer is sent to the dashboard from %s', async path => {
  mockPermissions = { 'integrations.view': true };

  await visit(path);

  expect(await screen.findByText('dashboard')).toBeInTheDocument();
});

test('the old doubled paths are gone', async () => {
  mockPermissions = { 'integrations.view': true, 'integrations.edit': true };

  await visit('/integrations/integrations/wizard');

  expect(await screen.findByText('no route')).toBeInTheDocument();
});

test('integration paths encode the id', () => {
  expect(integrationPath('a/b')).toBe('/integrations/a%2Fb');
});
