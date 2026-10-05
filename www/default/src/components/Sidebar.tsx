import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { usePermissions } from '../context/PermissionsContext';
import { runNavGuard } from '../utils/navGuard';
const Sidebar: React.FC = () => {
  const { state, actions } = useApp();
  const { hasPermission } = usePermissions();
  const location = useLocation();
  const navigate = useNavigate();

  const menuItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: 'fa-tachometer-alt',
      path: '/',
      permission: 'dashboard.view' as const,
    },
    {
      id: 'agent',
      label: 'Agent',
      isHeading: true,
    },
    {
      id: 'surfaces',
      label: 'Surfaces',
      icon: 'fa-layer-group',
      path: '/surfaces',
      permission: 'surfaces.view' as const,
    },
    {
      id: 'proxies',
      label: 'Proxies',
      icon: 'fa-network-wired',
      path: '/proxies',
      permissionsAny: ['mcp_proxies.view', 'a2a_proxies.view'] as const,
    },
    {
      id: 'management',
      label: 'Management',
      isHeading: true,
    },
    {
      id: 'credentials',
      label: 'Credentials',
      icon: 'fa-id-card',
      path: '/credentials',
      permission: 'settings.view' as const,
    },
    {
      id: 'policies',
      label: 'Policies',
      icon: 'fa-shield-alt',
      path: '/policies',
      permission: 'settings.view' as const,
    },
    {
      id: 'secrets',
      label: 'Secrets',
      icon: 'fa-key',
      path: '/secrets',
      permission: 'secrets.view' as const,
    },
    {
      id: 'identities',
      label: 'Identity',
      icon: 'fa-users',
      path: '/identities',
    },

    {
      id: 'payments',
      label: 'Payments',
      icon: 'fa-dollar-sign',
      path: '/x402payments',
      permission: 'payments.view' as const,
    },
    {
      id: 'configuration',
      label: 'Configuration',
      isHeading: true,
    },
    {
      id: 'connections',
      label: 'Connections',
      icon: 'fa-link',
      path: '/connections',
      permission: 'gateways.view' as const,
    },
    {
      id: 'integrations',
      label: 'Integrations',
      icon: 'fa-puzzle-piece',
      path: '/integrations',
    },

    {
      id: 'settings',
      label: 'Settings',
      icon: 'fa-sliders-h',
      path: '/settings',
    },
    {
      id: 'monitoring',
      label: 'Monitoring',
      isHeading: true,
    },
    {
      id: 'metrics',
      label: 'Metrics',
      icon: 'fa-chart-bar',
      path: '/metrics',
      permission: 'metrics.view' as const,
      featureFlag: 'metrics',
      featureFlagDefaultOn: true,
    },
    {
      id: 'logs',
      label: 'Logs',
      icon: 'fa-file-alt',
      path: '/logs',
      permission: 'logs.view' as const,
    },
    {
      id: 'audit',
      label: 'Audit',
      icon: 'fa-file-contract',
      path: '/audit',
      permission: 'audit.view' as const,
    },
    {
      id: 'system-metrics',
      label: 'System',
      icon: 'fa-microchip',
      path: '/system-metrics',
    },
    {
      id: 'tasks',
      label: 'Tasks',
      icon: 'fa-tasks',
      path: '/tasks',
    },
  ];

  // Filter menu items based on permissions and feature flags
  const featureFlags = state.settings?.feature_flags || {};
  const visibleMenuItems = menuItems.filter(item => {
    if (item.isHeading) return true;
    if ('featureFlag' in item && item.featureFlag) {
      const flagValue = featureFlags[item.featureFlag as keyof typeof featureFlags];
      const defaultOn = 'featureFlagDefaultOn' in item && item.featureFlagDefaultOn === true;
      // Default-on entries hide only when explicitly set to `false`;
      // default-off entries show only when explicitly truthy.
      if (defaultOn ? flagValue === false : !flagValue) return false;
    }
    if ('permissionsAny' in item && item.permissionsAny) {
      return item.permissionsAny.some(permission => hasPermission(permission));
    }
    if (!item.permission) return true; // No permission required
    return hasPermission(item.permission);
  });

  const getNavItemClass = (item: (typeof menuItems)[0]) => {
    if (item.isHeading) return '';

    if (item.path) {
      const isActive =
        item.path === '/'
          ? location.pathname === '/'
          : location.pathname === item.path || location.pathname.startsWith(item.path + '/');
      return `nav-item ${isActive ? 'active' : ''}`;
    }

    return 'nav-item';
  };

  return (
    <nav
      className={`sidebar sidebar-dark accordion ${state.sidebarCollapsed ? 'toggled' : ''}`}
      id="accordionSidebar"
      aria-label="Primary"
      style={{
        overflowY: 'auto',
        overflowX: 'hidden',
        width: state.sidebarCollapsed ? '80px' : '220px',
        transition: 'width 250ms ease',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Sidebar - Brand */}
      <div className="sidebar-brand-wrapper">
        <button
          className="sidebar-brand d-flex flex-column align-items-center justify-content-center py-4 border-0 bg-transparent w-100"
          onClick={() => {
            if (!runNavGuard()) return;
            navigate('/');
          }}
        >
          <div className="sidebar-brand-icon w-100 px-3">
            <img
              src="/dashboard/images/agent_gateway_logo.svg"
              alt="Affinidi Logo"
              className="sidebar-logo"
              id="sidebar-logo-full"
              style={{ display: state.sidebarCollapsed ? 'none' : 'block' }}
            />
            <img
              src="/dashboard/images/gateway_logo_only.svg"
              alt="Affinidi Logo"
              className="sidebar-logo"
              id="sidebar-logo-compact"
              style={{ display: state.sidebarCollapsed ? 'block' : 'none' }}
            />
          </div>
        </button>
      </div>

      <hr className="sidebar-divider my-0" />

      {/* Scrollable nav area — flex: 1 + min-height: 0 is required for overflow-y to work in a flex container */}

      <ul className="navbar-nav" style={{ padding: 0, margin: 0 }}>
        {visibleMenuItems.map(item => {
          if (item.isHeading) {
            return (
              <li key={item.id} className="sidebar-heading-wrapper">
                <hr className="sidebar-divider" />
                <div className="sidebar-heading">{item.label}</div>
              </li>
            );
          }

          return (
            <li key={item.id} className={getNavItemClass(item)}>
              <Link
                className="nav-link"
                to={item.path!}
                data-testid={`nav-${item.id}`}
                onClick={e => {
                  if (!runNavGuard()) e.preventDefault();
                }}
              >
                <i className={`fas fa-fw ${item.icon}`}></i>
                <span>{item.label}</span>
              </Link>
            </li>
          );
        })}
      </ul>

      <hr className="sidebar-divider d-none d-md-block" />

      <div style={{ flex: 1 }} />

      {/* Sidebar Toggler */}
      <div className="text-center d-none d-md-block pb-2">
        <button
          className="rounded-circle border-0 bg-transparent text-white d-flex align-items-center justify-content-center mx-auto"
          id="sidebarToggle"
          title="Toggle Sidebar ( [ )"
          style={{ width: '2rem', height: '2rem' }}
          onClick={actions.toggleSidebar}
        >
          <i className={`fas fa-angle-${state.sidebarCollapsed ? 'right' : 'left'}`} />
        </button>
      </div>
    </nav>
  );
};

export default Sidebar;
