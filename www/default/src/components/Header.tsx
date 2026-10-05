import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { usePageTitleContext } from '../context/PageTitleContext';
import { apiClient } from '../api';
import { ROUTES } from '../routes';
import { DOCS_URL } from '../config/docs';
import { TopbarActionButton } from './shared/TopbarActionButton';
import { UserAvatar } from './shared/UserAvatar';

interface HeaderProps {
  onLogout?: () => void;
}

interface UserProfile {
  username: string;
  user_id: string;
  role: string;
  avatar_path?: string;
  first_name?: string;
  last_name?: string;
}

const Header: React.FC<HeaderProps> = ({ onLogout }) => {
  const { state, actions, getCurrentStats } = useApp();
  const { title: pageTitleOverride } = usePageTitleContext();
  const location = useLocation();
  const navigate = useNavigate();
  const [userProfile, setUserProfile] = React.useState<UserProfile | null>(null);
  const [showUserMenu, setShowUserMenu] = React.useState(false);
  const userMenuRef = React.useRef<HTMLLIElement>(null);
  const [fullscreen, setFullscreen] = React.useState(false);

  const toggleFullscreen = React.useCallback(() => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  }, []);

  React.useEffect(() => {
    const onChange = () => {
      const isFs = !!document.fullscreenElement;
      setFullscreen(isFs);
      document.documentElement.classList.toggle('app-fullscreen', isFs);
    };
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, []);

  React.useEffect(() => {
    document.documentElement.classList.toggle('dark-theme-fs', state.theme === 'dark');
  }, [state.theme]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const inInput =
        target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

      if (e.key === '[' && !inInput && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        actions.toggleSidebar();
        return;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [actions]);

  // Get unread count from dashboard stats (updated via delta sync)
  const stats = getCurrentStats();
  const unreadCount = stats?.unread_count || 0;

  // Close dropdown when clicking outside
  React.useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };

    if (showUserMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [showUserMenu]);

  // Fetch current user profile
  React.useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await apiClient.get('/profile');
        setUserProfile(response.data);
      } catch (error) {
        console.error('Failed to fetch user profile:', error);
      }
    };
    fetchProfile();
  }, []);

  const TITLE_PREFIX = '';

  const getPageTitle = () => {
    switch (location.pathname) {
      case ROUTES.DASHBOARD:
        return 'Dashboard';
      case '/identities':
        return `${TITLE_PREFIX}Identities`;
      case '/identities/integrations':
        return `${TITLE_PREFIX}Identity Integrations`;
      case '/surfaces':
        return `${TITLE_PREFIX}Agent Surfaces`;
      case '/connections':
        return `${TITLE_PREFIX}Connections`;
      case '/gateways':
        return `${TITLE_PREFIX}Linked Gateways`;
      case '/integrations':
        return `${TITLE_PREFIX}Integrations`;
      case '/mediators':
        return `${TITLE_PREFIX}Mediators`;
      case '/mcp-proxies':
        return `${TITLE_PREFIX}MCP Proxies`;
      case '/trust-registries':
        return `${TITLE_PREFIX}Trust Registries`;
      case '/secrets':
        return `${TITLE_PREFIX}Secrets`;
      case '/proxies':
        return `${TITLE_PREFIX}Proxies`;
      case '/credential-providers':
        return `${TITLE_PREFIX}Settings`;
      case '/credentials':
        return `${TITLE_PREFIX}Credentials`;
      case '/delegation-vault':
        return `${TITLE_PREFIX}Secrets`;
      case '/oidc-providers':
        return `${TITLE_PREFIX}OIDC Providers`;
      case '/users':
        return `${TITLE_PREFIX}Users`;
      case '/profile':
        return `${TITLE_PREFIX}Profile`;
      case '/notifications':
        return `${TITLE_PREFIX}Notifications`;
      case '/tasks':
        return `${TITLE_PREFIX}Tasks`;
      case '/audit':
        return `${TITLE_PREFIX}Audit`;
      case '/settings':
        return `${TITLE_PREFIX}Settings`;
      case '/logs':
        return `${TITLE_PREFIX}Logs`;
      case '/metrics':
        return `${TITLE_PREFIX}Metrics`;
      case '/system-metrics':
        return `${TITLE_PREFIX}System`;
      case '/issuers':
        return `${TITLE_PREFIX}Issuers`;
      case '/authorities':
        return `${TITLE_PREFIX}Authorities`;
      case '/policies':
        return `${TITLE_PREFIX}Policies`;
      case '/x402payments':
        return `${TITLE_PREFIX}x402 Payments`;
      default:
        // Handle dynamic routes with pattern matching
        if (location.pathname.startsWith('/identities/')) {
          return `${TITLE_PREFIX}Identities`;
        }
        // Handle dynamic routes with pattern matching
        if (location.pathname.startsWith('/surfaces/')) {
          return `${TITLE_PREFIX}Edit Agent Surface`;
        }
        if (location.pathname.startsWith('/gateways/')) {
          if (location.pathname.endsWith('/publish')) {
            return `${TITLE_PREFIX}Create Gateway Connection Point`;
          }
          if (location.pathname.endsWith('/connect')) {
            return `${TITLE_PREFIX}Connect Gateway`;
          }
          if (location.pathname.endsWith('/approve')) {
            return `${TITLE_PREFIX}Approve Gateway Connection`;
          }
          return `${TITLE_PREFIX}Edit Gateway`;
        }
        if (location.pathname.startsWith('/mediators/')) {
          if (location.pathname.endsWith('/wizard')) {
            return `${TITLE_PREFIX}Add Mediator`;
          }
          return `${TITLE_PREFIX}Edit Mediator`;
        }
        if (location.pathname.startsWith('/mcp-proxies/')) {
          if (location.pathname.endsWith('/wizard')) {
            return `${TITLE_PREFIX}Add MCP Proxy`;
          }
          return `${TITLE_PREFIX}Edit MCP Proxy`;
        }
        if (location.pathname.startsWith('/proxies/a2a-proxies/')) {
          if (location.pathname.endsWith('/new')) {
            return `${TITLE_PREFIX}Add A2A Proxy`;
          }
          return `${TITLE_PREFIX}Edit A2A Proxy`;
        }
        if (location.pathname.startsWith('/trust-registries/')) {
          if (location.pathname.endsWith('/wizard')) {
            return `${TITLE_PREFIX}Add Trust Registry`;
          }
          return `${TITLE_PREFIX}Edit Trust Registry`;
        }
        if (location.pathname.startsWith('/authorities/')) {
          if (location.pathname.endsWith('/new')) {
            return `${TITLE_PREFIX}Add Authority`;
          }
          return `${TITLE_PREFIX}Edit Authority`;
        }
        if (location.pathname.startsWith('/users/')) {
          return `${TITLE_PREFIX}Edit User`;
        }
        if (location.pathname.startsWith('/notifications/')) {
          return `${TITLE_PREFIX}Edit Notification`;
        }
        if (location.pathname.startsWith('/credential-providers/')) {
          return `${TITLE_PREFIX}Edit Credential Provider`;
        }
        if (location.pathname.startsWith('/oidc-providers/')) {
          return `${TITLE_PREFIX}Edit OIDC Provider`;
        }
        if (location.pathname.startsWith('/apikeys/')) {
          return `${TITLE_PREFIX}API Key`;
        }
        if (location.pathname.startsWith('/access-tokens/')) {
          return `${TITLE_PREFIX}Access Token`;
        }
        return `${TITLE_PREFIX}Dashboard`;
    }
  };

  return (
    <nav
      className="navbar navbar-expand navbar-light topbar static-top shadow"
      style={{
        left: state.sidebarCollapsed ? '100px' : '220px',
        transition: 'left 250ms ease',
      }}
    >
      {/* Sidebar Toggle (Topbar) */}
      <button
        type="button"
        title="Toggle sidebar ( [ )"
        id="sidebarToggleTop"
        className="btn btn-link d-md-none rounded-circle me-3"
        onClick={actions.toggleSidebar}
      >
        <i className="fa fa-bars"></i>
      </button>

      {/* Topbar Title — pages can override via `usePageTitle(...)`;
          falls back to a route-derived default. Truncates with an
          ellipsis so long titles never push the right-side controls. */}
      <h1
        className="h6 mb-0 me-auto ps-4 text-truncate"
        id="page-title"
        title={pageTitleOverride ?? getPageTitle()}
        style={{ minWidth: 0, maxWidth: 'calc(100vw - 520px)' }}
      >
        {pageTitleOverride ?? getPageTitle()}
      </h1>

      {/* Topbar Navbar */}
      <ul
        className="navbar-nav ms-auto align-items-center"
        style={{ paddingLeft: '24px', paddingRight: '24px' }}
      >
        {/* Theme Toggle */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            id="themeToggle"
            title="Toggle Dark Mode"
            onClick={actions.toggleTheme}
            iconClassName={`fas ${state.theme === 'dark' ? 'fa-sun' : 'fa-moon'}`}
            iconId="themeIcon"
            isActive={state.theme === 'dark'}
            data-testid="topbar-theme-button"
            aria-label="Toggle dark mode"
          />
        </li>

        {/* Fullscreen Toggle */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            title={fullscreen ? 'Exit full screen (Esc)' : 'Enter full screen'}
            onClick={toggleFullscreen}
            iconClassName={`fas fa-${fullscreen ? 'compress' : 'expand'}`}
            isActive={fullscreen}
            data-testid="topbar-fullscreen-button"
            aria-label={fullscreen ? 'Exit full screen' : 'Enter full screen'}
          />
        </li>

        {/* Status Badge
        <li className="nav-item">
          <span
            className={`badge ${getStatusBadgeClass()} px-3 py-2`}
            id="ws-status-badge"
            title="Click to view dashboard"
          >
            <i className="fas fa-circle"></i> <span id="ws-status-text">{getStatusText()}</span>
          </span>
        </li>

        {/* Channel Health Badge
        <li className="nav-item ms-2">
          <span
            className={`badge ${getChannelHealthBadgeClass()} px-3 py-2 d-inline-block text-center`}
            id="channel-status-badge"
            onClick={() => navigate('/surfaces')}
            style={{ cursor: 'pointer', width: '130px' }}
            title="Click to view channels"
          >
            <i className="fas fa-channel"></i>{' '}
            <span id="channel-status-text">{getChannelHealthText()}</span>
          </span>
        </li>
        */}

        {/* Notifications Badge */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            onClick={() => navigate('/notifications')}
            title="View notifications"
            iconClassName="fas fa-bell"
            badge={unreadCount > 0 ? (unreadCount > 99 ? '99+' : unreadCount) : null}
            data-testid="topbar-notifications-button"
            aria-label="View notifications"
          />
        </li>

        {/* Documentation */}
        <li className="nav-item topbar-action-item">
          <TopbarActionButton
            appearance="primary"
            title="Browse documentation"
            onClick={() => window.open(DOCS_URL.home, '_blank', 'noopener,noreferrer')}
            iconClassName="fas fa-book-open"
            data-testid="topbar-docs-button"
            aria-label="Browse documentation"
          />
        </li>

        {/* User Avatar & Menu */}
        {onLogout && (
          <li className="nav-item dropdown topbar-action-item" ref={userMenuRef}>
            <TopbarActionButton
              appearance="avatar"
              shape="content"
              onClick={() => setShowUserMenu(!showUserMenu)}
              isOpen={showUserMenu}
              data-testid="topbar-user-menu-button"
              aria-label="Open user menu"
              aria-haspopup="menu"
              aria-expanded={showUserMenu}
            >
              <UserAvatar
                alt="User avatar"
                avatarPath={userProfile?.avatar_path}
                size="topbar"
                imageClassName="topbar-avatar-image"
                fallbackClassName="topbar-avatar-fallback d-flex align-items-center justify-content-center text-white fw-bold"
              />
              {userProfile && (
                <span className="topbar-user-name d-none d-lg-inline">
                  {userProfile.first_name || userProfile.username}
                </span>
              )}
            </TopbarActionButton>
            {showUserMenu && (
              <div
                className="dropdown-menu dropdown-menu-right shadow animated--grow-in show topbar-user-menu"
                style={{
                  position: 'absolute',
                  right: 0,
                  marginTop: '0.5rem',
                  minWidth: '200px',
                }}
              >
                <button
                  className="dropdown-item d-flex align-items-center lh-base topbar-user-menu-item"
                  onClick={() => {
                    setShowUserMenu(false);
                    navigate('/profile');
                  }}
                >
                  <i className="fas fa-user fa-sm fa-fw me-2"></i>
                  Profile
                </button>
                <button
                  className="dropdown-item d-flex align-items-center lh-base topbar-user-menu-item"
                  onClick={() => {
                    setShowUserMenu(false);
                    onLogout();
                  }}
                >
                  <i className="fas fa-sign-out-alt fa-sm fa-fw me-2"></i>
                  Sign Out
                </button>
              </div>
            )}
          </li>
        )}
      </ul>
    </nav>
  );
};

export default Header;
