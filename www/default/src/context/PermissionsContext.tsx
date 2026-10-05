import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { apiClient } from '../api';

export type Permissions = Record<string, boolean>;

interface PermissionsContextType {
  permissions: Permissions | null;
  loading: boolean;
  error: string | null;
  refetchPermissions: () => Promise<void>;
  hasPermission: (feature: string) => boolean;
}

const PermissionsContext = createContext<PermissionsContextType | undefined>(undefined);
PermissionsContext.displayName = 'PermissionsContext';

// Default permissions (all restricted until loaded)
const defaultPermissions: Permissions = {
  'users.view': false,
  'users.edit': false,
  'users.approve': false,
  'users.delete': false,
  'gateways.view': false,
  'gateways.edit': false,
  'gateways.delete': false,
  'mediators.view': false,
  'mediators.edit': false,
  'mediators.delete': false,
  'mcp_proxies.view': false,
  'mcp_proxies.edit': false,
  'mcp_proxies.delete': false,
  'a2a_proxies.view': false,
  'a2a_proxies.edit': false,
  'a2a_proxies.delete': false,
  'trust_registries.view': false,
  'trust_registries.edit': false,
  'trust_registries.delete': false,
  'secrets.view': false,
  'secrets.edit': false,
  'secrets.delete': false,
  'api_keys.view': false,
  'api_keys.edit': false,
  'api_keys.delete': false,
  'access_tokens.view': false,
  'access_tokens.edit': false,
  'access_tokens.delete': false,
  'tenant_ownership.manage': false,
  'notifications.view': false,
  'notifications.edit': false,
  'notifications.delete': false,
  'surfaces.view': false,
  'surfaces.edit': false,
  'surfaces.delete': false,
  'surfaces.capture': false,
  'jwt_verification_strategies.view': false,
  'jwt_verification_strategies.edit': false,
  'jwt_verification_strategies.delete': false,
  'issuers.view': false,
  'issuers.edit': false,
  'issuers.delete': false,
  'authorities.view': false,
  'authorities.edit': false,
  'authorities.delete': false,
  'settings.view': false,
  'settings.edit': false,
  'terms.view': false,
  'terms.edit': false,
  'metrics.view': false,
  'dashboard.view': false,
  'logs.view': false,
  'audit.view': false,
};

export function PermissionsProvider({ children }: { children: ReactNode }) {
  const [permissions, setPermissions] = useState<Permissions | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPermissions = async () => {
    try {
      setLoading(true);
      setError(null);
      const perms = await apiClient.getPermissions();
      setPermissions(perms);
    } catch (err) {
      console.error('Failed to fetch permissions:', err);
      setError('Failed to load permissions');
      // Set default restricted permissions on error
      setPermissions(defaultPermissions);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPermissions();
  }, []);

  const hasPermission = (feature: string): boolean => {
    if (!permissions) {
      console.debug(`[PERMISSIONS] hasPermission('${feature}'): false (permissions not loaded)`);
      return false;
    }
    const result = permissions[feature] === true;
    if (!result) {
      console.debug(
        `[PERMISSIONS] hasPermission('${feature}'): false (value: ${permissions[feature]})`
      );
    }
    return result;
  };

  const value: PermissionsContextType = {
    permissions,
    loading,
    error,
    refetchPermissions: fetchPermissions,
    hasPermission,
  };

  return <PermissionsContext.Provider value={value}>{children}</PermissionsContext.Provider>;
}

export function usePermissions(): PermissionsContextType {
  const context = useContext(PermissionsContext);
  if (context === undefined) {
    throw new Error('usePermissions must be used within a PermissionsProvider');
  }
  return context;
}
