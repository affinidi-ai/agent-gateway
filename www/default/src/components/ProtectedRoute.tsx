import React from 'react';
import { Navigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { ROUTES } from '../routes';

interface ProtectedRouteProps {
  children: React.ReactElement;
  /** One permission, or several of which any one is enough. */
  permission: string | readonly string[];
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, permission }) => {
  const { hasPermission, loading } = usePermissions();

  // While loading permissions, show nothing (or could show a loader)
  if (loading) {
    return null;
  }

  const permissions = typeof permission === 'string' ? [permission] : permission;
  if (!permissions.some(p => hasPermission(p))) {
    return <Navigate to={ROUTES.DASHBOARD} replace />;
  }

  return children;
};

export default ProtectedRoute;
