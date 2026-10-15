import React, { lazy } from 'react';
import { Route } from 'react-router-dom';
import ProtectedRoute from '../components/ProtectedRoute';
import { ROUTES } from '../routes';

const IntegrationsPage = lazy(() => import('./IntegrationsPage'));
const IntegrationEditorPage = lazy(() => import('./IntegrationEditorPage'));
const EndpointEditorPage = lazy(() => import('./EndpointEditorPage'));
const EventSetEditorPage = lazy(() => import('./EventSetEditorPage'));

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
          <IntegrationEditorPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="integration"
      path={`${ROUTES.INTEGRATIONS}/:id`}
      element={
        <ProtectedRoute permission="integrations.edit">
          <IntegrationEditorPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="endpoint-new"
      path={ROUTES.ENDPOINT_NEW}
      element={
        <ProtectedRoute permission="integrations.edit">
          <EndpointEditorPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="endpoint"
      path={`${ROUTES.INTEGRATIONS}/endpoints/:id`}
      element={
        <ProtectedRoute permission="integrations.edit">
          <EndpointEditorPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="event-set-new"
      path={ROUTES.EVENT_SET_NEW}
      element={
        <ProtectedRoute permission="integrations.edit">
          <EventSetEditorPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="event-set"
      path={`${ROUTES.INTEGRATIONS}/event-sets/:id`}
      element={
        <ProtectedRoute permission="integrations.edit">
          <EventSetEditorPage />
        </ProtectedRoute>
      }
    />,
  ];
}
