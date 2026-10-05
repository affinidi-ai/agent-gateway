import React from 'react';
import { Navigate } from 'react-router-dom';
import { usePermissions } from '../context/PermissionsContext';
import { ROUTES } from '../routes';

interface ProtectedRouteProps {
  children: React.ReactElement;
  permission: string;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, permission }) => {
  const { hasPermission, loading } = usePermissions();

  // While loading permissions, show nothing (or could show a loader)
  if (loading) {
    return null;
  }

  // Check if user has the required permission
  if (!hasPermission(permission)) {
    return <Navigate to={ROUTES.DASHBOARD} replace />;
  }

  return children;
};

export default ProtectedRoute;
