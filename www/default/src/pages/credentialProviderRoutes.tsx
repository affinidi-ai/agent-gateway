import React, { lazy } from 'react';
import { Navigate, Route } from 'react-router-dom';
import ProtectedRoute from '../components/ProtectedRoute';

const EditCredentialProviderPage = lazy(() => import('./EditCredentialProviderPage'));

const PROVIDERS_TAB = '/credentials?tab=credential-providers';

/**
 * Credential provider pages, guarded by the `credential_providers.*` permissions. The list is a
 * tab of the Credentials page; the retired `/oidc-providers` pages redirect to it.
 */
export function credentialProviderRoutes(): React.ReactElement[] {
  return [
    <Route
      key="credential-providers"
      path="/credential-providers"
      element={<Navigate to={PROVIDERS_TAB} replace />}
    />,
    <Route
      key="credential-provider-new"
      path="/credential-providers/new"
      element={
        <ProtectedRoute permission="credential_providers.edit">
          <EditCredentialProviderPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="credential-provider"
      path="/credential-providers/:id"
      element={
        <ProtectedRoute permission="credential_providers.view">
          <EditCredentialProviderPage />
        </ProtectedRoute>
      }
    />,
    <Route
      key="oidc-providers"
      path="/oidc-providers/*"
      element={<Navigate to={PROVIDERS_TAB} replace />}
    />,
  ];
}
