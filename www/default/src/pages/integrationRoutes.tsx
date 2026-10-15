import React, { lazy } from 'react';
import { Route } from 'react-router-dom';
import ProtectedRoute from '../components/ProtectedRoute';
import { ROUTES } from '../routes';

const IntegrationsPage = lazy(() => import('./IntegrationsPage'));
const AddIntegrationWizardPage = lazy(() => import('./AddIntegrationWizardPage'));
const EditIntegrationPage = lazy(() => import('./EditIntegrationPage'));

/**
 * The Integrations area, guarded by the `integrations.*` permissions. MCP proxies keep their
 * own routes under `/integrations/mcp-proxies/*`.
 */
export function integrationRoutes(): React.ReactElement[] {
  return [
    <Route
      key="integrations"
      path={ROUTES.INTEGRATIONS}
      element={
        <ProtectedRoute permission="integrations.view">
          <IntegrationsPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="integration-new"
      path={ROUTES.INTEGRATION_NEW}
      element={
        <ProtectedRoute permission="integrations.edit">
          <AddIntegrationWizardPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="integration"
      path={`${ROUTES.INTEGRATIONS}/:id`}
      element={
        <ProtectedRoute permission="integrations.edit">
          <EditIntegrationPage />
        </ProtectedRoute>
      }
    />,
  ];
}
