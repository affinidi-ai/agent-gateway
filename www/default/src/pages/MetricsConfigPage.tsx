import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Tab, Tabs } from 'react-bootstrap';
import { apiClient } from '../api';
import { MetricsConfig } from './MetricsConfigPage/types';
import OpenTelemetryTab from './MetricsConfigPage/tabs/OpenTelemetryTab';
import CloudWatchTab from './MetricsConfigPage/tabs/CloudWatchTab';
import RetentionTab from './MetricsConfigPage/tabs/RetentionTab';
import AdvancedTab from './MetricsConfigPage/tabs/AdvancedTab';
import HelpTab from './MetricsConfigPage/tabs/HelpTab';

const MetricsConfigPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<string>('opentelemetry');
  const [config, setConfig] = useState<MetricsConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  // Keyboard shortcut for save (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (!saving && config) {
          handleSave();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [config, saving]);

  const loadConfig = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getMetricsConfig();
      setConfig(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load metrics configuration');
      console.error('Failed to load metrics config:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!config) return;

    try {
      setSaving(true);
      setError(null);
      setSuccessMessage(null);
      const response = await apiClient.updateMetricsConfig(config);
      setSuccessMessage(response.message);

      // Reload config after save
      setTimeout(() => {
        loadConfig();
      }, 1000);
    } catch (err: any) {
      setError(err.message || 'Failed to save metrics configuration');
      console.error('Failed to save metrics config:', err);
    } finally {
      setSaving(false);
    }
  };

  const updateConfig = (path: string[], value: any) => {
    setConfig(prev => {
      if (!prev) return prev;

      const newConfig = { ...prev };
      let current: any = newConfig;

      for (let i = 0; i < path.length - 1; i++) {
        current[path[i]] = { ...current[path[i]] };
        current = current[path[i]];
      }

      current[path[path.length - 1]] = value;
      return newConfig;
    });
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="card shadow mb-4">
          <div className="card-body">
            <div
              className="d-flex justify-content-center align-items-center"
              style={{ minHeight: '400px' }}
            >
              <div className="spinner-border text-primary" role="status">
                <span className="sr-only">Loading...</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="container-fluid">
        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-sliders-h"></i> Metrics Configuration
            </h6>
          </div>
          <div className="card-body">
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-triangle me-2"></i>
              Failed to load metrics configuration. Please try again.
            </div>
            <button className="btn btn-primary" onClick={loadConfig}>
              <i className="fas fa-redo me-2"></i>
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={() => navigate('/metrics')}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <div className="d-flex align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-sliders-h"></i> Metrics Configuration
            </h6>
          </div>
          <div>
            <button
              className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
              onClick={handleSave}
              disabled={saving}
              title="Saves the configuration and applies it to the running gateway without a restart"
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {saving ? ' Saving...' : ' Save'}
            </button>
          </div>
        </div>

        <div className="card-body">
          {error && (
            <div
              className="alert alert-danger alert-dismissible fade show mb-4"
              style={{
                position: 'fixed',
                top: '20px',
                right: '20px',
                zIndex: 9999,
                minWidth: '400px',
                fontSize: '14px',
                fontWeight: 'bold',
                border: '2px solid var(--danger)',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              }}
            >
              <i className="fas fa-exclamation-triangle me-2"></i>
              <strong>Error!</strong> {error}
              <button
                type="button"
                className="btn-close"
                onClick={() => setError(null)}
                title="Close notification"
                aria-label="Close"
              />
            </div>
          )}

          {/* Success Alert */}
          {successMessage && (
            <div
              className="alert alert-success alert-dismissible fade show mb-4"
              style={{
                position: 'fixed',
                top: '20px',
                right: '20px',
                zIndex: 9999,
                minWidth: '400px',
                fontSize: '14px',
                fontWeight: 'bold',
                border: '2px solid #151615ff',
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              }}
            >
              <i className="fas fa-check-circle me-2"></i>
              <strong>Success!</strong> {successMessage}
              <button
                type="button"
                className="btn-close"
                onClick={() => setSuccessMessage(null)}
                title="Close notification"
                aria-label="Close"
              />
            </div>
          )}

          {/* Tabs */}
          <Tabs
            activeKey={activeTab}
            onSelect={k => k && setActiveTab(k)}
            className="mb-3 custom-channel-tabs"
          >
            <Tab
              eventKey="opentelemetry"
              title={
                <>
                  <i className="fas fa-diagram-project"></i> OpenTelemetry
                </>
              }
            >
              <OpenTelemetryTab config={config} updateConfig={updateConfig} />
            </Tab>

            <Tab
              eventKey="cloudwatch"
              title={
                <>
                  <i className="fab fa-aws"></i> CloudWatch
                </>
              }
            >
              <CloudWatchTab config={config} updateConfig={updateConfig} />
            </Tab>

            <Tab
              eventKey="retention"
              title={
                <>
                  <i className="fas fa-clock"></i> Retention
                </>
              }
            >
              <RetentionTab config={config} updateConfig={updateConfig} />
            </Tab>

            <Tab
              eventKey="advanced"
              title={
                <>
                  <i className="fas fa-cog"></i> Advanced
                </>
              }
            >
              <AdvancedTab config={config} updateConfig={updateConfig} />
            </Tab>

            <Tab
              eventKey="help"
              title={
                <>
                  <i className="fas fa-question-circle"></i> Help
                </>
              }
            >
              <HelpTab />
            </Tab>
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default MetricsConfigPage;
