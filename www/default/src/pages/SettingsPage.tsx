import React, { useState, useEffect } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useApp } from '../context/AppContext';
import { usePermissions } from '../context/PermissionsContext';
import { Settings, UserSettingsOverrides } from '../types';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { showToast } from '../utils/toaster';
import { clearRuntimeVariablesCache } from '../utils/runtimeVariables';
import UserPreferencesTab from './SettingsPage/UserPreferencesTab';
import SystemSettingsTab from './SettingsPage/SystemSettingsTab';
import SystemTab from './SettingsPage/SystemTab';
import NetworkingTab from './SettingsPage/NetworkingTab';
import VpAuditTab from './SettingsPage/VpAuditTab';
import LimitsTab from './SettingsPage/LimitsTab';
import UsersPage from './UsersPage';
import TermsPage from './TermsPage';

const CREDENTIALS_TAB_REDIRECTS: Record<string, string> = {
  strategies: 'jwt-verification',
  'credential-providers': 'credential-providers',
};

const POLICIES_TAB_REDIRECT = 'policies';

const SettingsPage: React.FC = () => {
  const { state, actions } = useApp();
  const { hasPermission } = usePermissions();
  const isAdmin = hasPermission('settings.view');
  const canViewUsers = hasPermission('users.view');
  const canViewTerms = hasPermission('terms.view') && state.settings?.feature_flags?.terms === true;
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const tabFromUrl = searchParams.get('tab');
  const redirectTo = tabFromUrl ? CREDENTIALS_TAB_REDIRECTS[tabFromUrl] : undefined;
  useEffect(() => {
    if (redirectTo) {
      navigate(`/credentials?tab=${redirectTo}`, { replace: true });
    } else if (tabFromUrl === POLICIES_TAB_REDIRECT) {
      navigate('/policies', { replace: true });
    }
  }, [redirectTo, tabFromUrl, navigate]);
  const [activeTab, setActiveTab] = useState(
    tabFromUrl || (isAdmin ? 'system-settings' : 'user-settings')
  );
  const [formData, setFormData] = useState<Settings>({
    badge_threshold: 5,
    metrics_retention: 360, // 6 hours in minutes
    task_activity_window: 60,
    connections_window: 60,
    latency_window: 60,
    onboarding_channel_ttl_seconds: 30,
    refresh_interval_seconds: 5, // Default 5 seconds
    log_timestamp_format: 'local', // Default local time
    bucket_seconds: 30, // Default 30 seconds
    payments_min_display: 10, // Default 10 payments
    feature_flags: {},
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Update form data when settings load
  useEffect(() => {
    if (state.settings) {
      setFormData({
        ...state.settings,
        // Only convert hours to minutes for typical hour values (6, 12, 24, 48, 72, 168)
        // Common hour values that would be set in the old system
        // This prevents converting legitimate minute values incorrectly
        metrics_retention:
          state.settings.metrics_retention === 6 ||
          state.settings.metrics_retention === 12 ||
          state.settings.metrics_retention === 24 ||
          state.settings.metrics_retention === 48 ||
          state.settings.metrics_retention === 72 ||
          state.settings.metrics_retention === 168
            ? state.settings.metrics_retention * 60
            : state.settings.metrics_retention,
      });
    }
  }, [state.settings]);

  // Keyboard shortcut for save (Ctrl+S or Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!isSubmitting) {
          if (activeTab === 'user-settings') {
            handleSaveUserSettings({
              badge_threshold_minutes: formData.badge_threshold,
              refresh_interval_seconds: formData.refresh_interval_seconds,
              log_timestamp_format: formData.log_timestamp_format,
              bucket_seconds: formData.bucket_seconds,
              payments_min_display: formData.payments_min_display,
            });
          } else if (activeTab === 'system-settings') {
            handleSave(event as any);
          }
        }
      }
    };

    document.addEventListener('keydown', handleKeyboardSave);
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [isSubmitting, formData, activeTab]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    if (e.target.type !== 'number') {
      setFormData(prev => ({ ...prev, [name]: value }));
      setMessage(null);
      return;
    }
    const numValue = parseInt(value, 10) || 0;

    // Validate metrics_retention range
    if (name === 'metrics_retention') {
      if (numValue < 1) {
        setMessage({ type: 'error', text: 'Metrics retention must be at least 1 minute' });
        return;
      }
      if (numValue > 10080) {
        setMessage({
          type: 'error',
          text: 'Metrics retention cannot exceed 7 days (10,080 minutes)',
        });
        return;
      }
    }

    // Validate refresh_interval_seconds range
    if (name === 'refresh_interval_seconds') {
      if (numValue < 1) {
        setMessage({ type: 'error', text: 'Refresh interval must be at least 1 second' });
        return;
      }
      if (numValue > 300) {
        setMessage({
          type: 'error',
          text: 'Refresh interval cannot exceed 300 seconds (5 minutes)',
        });
        return;
      }
    }

    setFormData(prev => ({
      ...prev,
      [name]: numValue,
    }));

    // Clear any existing message
    setMessage(null);
  };

  const handleSelectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const { name, value } = e.target;

    // Parse numeric values for bucket_seconds
    const finalValue = name === 'bucket_seconds' ? parseInt(value, 10) : value;

    setFormData(prev => ({
      ...prev,
      [name]: finalValue,
    }));

    // Clear any existing message
    setMessage(null);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate metrics retention
    if (formData.metrics_retention < 1 || formData.metrics_retention > 10080) {
      showToast('error', 'Metrics retention must be between 1 minute and 7 days (10,080 minutes)');
      return;
    }

    setIsSubmitting(true);
    setMessage(null);

    showToast('loading', 'Saving settings...');

    try {
      await actions.updateSettings(formData);
      clearRuntimeVariablesCache();
      showToast('success', 'Settings saved successfully!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save settings';
      showToast('error', errorMessage);
      setMessage({ type: 'error', text: errorMessage });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReset = async () => {
    setIsSubmitting(true);
    setMessage(null);

    showToast('loading', 'Resetting settings to defaults...');

    try {
      await actions.resetSettings();
      showToast('success', 'Settings reset to defaults!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to reset settings';
      showToast('error', errorMessage);
      setMessage({ type: 'error', text: errorMessage });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTruncateMetrics = async () => {
    setIsSubmitting(true);
    setMessage(null);

    showToast('loading', 'Truncating old metrics...');

    try {
      const result = await actions.truncateMetrics();
      const detailsMessage = `Truncated ${result.connections_removed} connections and ${result.events_removed} events. Retained ${result.connections_retained} connections and ${result.events_retained} events.`;
      showToast('success', `Old metrics truncated successfully! ${detailsMessage}`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to truncate metrics';
      showToast('error', errorMessage);
      setMessage({ type: 'error', text: errorMessage });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSaveUserSettings = async (overrides: Partial<UserSettingsOverrides>) => {
    setIsSubmitting(true);
    setMessage(null);

    showToast('loading', 'Saving your preferences...');

    try {
      await actions.updateUserSettings(overrides);
      showToast('success', 'Your preferences saved successfully!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save preferences';
      showToast('error', errorMessage);
      setMessage({ type: 'error', text: errorMessage });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetUserSettings = async () => {
    setIsSubmitting(true);
    setMessage(null);

    showToast('loading', 'Resetting preferences to system defaults...');

    try {
      await actions.resetUserSettings();
      showToast('success', 'Preferences reset to system defaults!');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to reset preferences';
      showToast('error', errorMessage);
      setMessage({ type: 'error', text: errorMessage });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (state.isLoading.settings && !state.settings) {
    return (
      <div className="container-fluid">
        <div className="d-flex justify-content-center align-items-center">
          <div className="text-center">
            <div className="spinner-border text-primary" role="status">
              <span className="sr-only">Loading...</span>
            </div>
            <p className="mt-2 text-muted">Loading settings...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      {/* Message Display */}
      {message && (
        <div
          className={`alert alert-${message.type === 'success' ? 'success' : 'danger'} alert-dismissible fade show mb-4`}
        >
          <strong>{message.type === 'success' ? 'Success!' : 'Error!'}</strong> {message.text}
          <button
            type="button"
            className="btn-close"
            onClick={() => setMessage(null)}
            aria-label="Close"
          />
        </div>
      )}

      <Tabs
        activeKey={activeTab}
        onSelect={k => {
          const tab = k || (isAdmin ? 'system-settings' : 'user-settings');
          setActiveTab(tab);
          setSearchParams({ tab }, { replace: true });
        }}
        className="mb-3 custom-channel-tabs"
      >
        {isAdmin && (
          <Tab
            eventKey="system-settings"
            title={
              <>
                <i className="fas fa-cogs"></i> System
              </>
            }
          >
            <SystemSettingsTab
              formData={formData}
              isSubmitting={isSubmitting}
              onInputChange={handleInputChange}
              onSave={handleSave}
              onReset={handleReset}
            />
          </Tab>
        )}

        <Tab
          eventKey="user-settings"
          title={
            <>
              <i className="fas fa-user-cog"></i> User
            </>
          }
        >
          <UserPreferencesTab
            formData={formData}
            userSettingsOverrides={state.userSettingsOverrides}
            isSubmitting={isSubmitting}
            onInputChange={handleInputChange}
            onSelectChange={handleSelectChange}
            onSaveUserSettings={handleSaveUserSettings}
            onResetUserSettings={handleResetUserSettings}
          />
        </Tab>

        {isAdmin && (
          <Tab
            eventKey="admin"
            title={
              <>
                <i className="fas fa-server"></i> Admin
              </>
            }
          >
            <SystemTab
              isSubmitting={isSubmitting}
              onTruncateMetrics={handleTruncateMetrics}
              settings={state.settings}
              updateSettings={actions.updateSettings}
            />
          </Tab>
        )}

        {isAdmin && (
          <Tab
            eventKey="networking"
            title={
              <>
                <i className="fas fa-network-wired"></i> Networking
              </>
            }
          >
            <NetworkingTab />
          </Tab>
        )}

        {isAdmin && (
          <Tab
            eventKey="security"
            title={
              <>
                <i className="fas fa-file-contract"></i> Security
              </>
            }
          >
            <VpAuditTab settings={state.settings} updateSettings={actions.updateSettings} />
          </Tab>
        )}

        {canViewTerms && (
          <Tab
            eventKey="terms"
            title={
              <>
                <i className="fas fa-file-signature"></i> T&amp;C Manager
              </>
            }
          >
            <TermsPage />
          </Tab>
        )}

        <Tab
          eventKey="limits"
          title={
            <>
              <i className="fas fa-gauge-high"></i> Limits
            </>
          }
        >
          <LimitsTab />
        </Tab>

        {canViewUsers && (
          <Tab
            eventKey="users"
            title={
              <>
                <i className="fas fa-users-cog"></i> Users
              </>
            }
          >
            <UsersPage />
          </Tab>
        )}
      </Tabs>
    </div>
  );
};

export default SettingsPage;
