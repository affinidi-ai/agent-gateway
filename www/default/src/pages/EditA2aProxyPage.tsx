import React, { useEffect, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api';
import InfoBanner from '../components/shared/InfoBanner';
import { DOCS_URL } from '../config/docs';
import AgentCardTab from './A2aProxyPage/AgentCardTab';
import BackendTab from './A2aProxyPage/BackendTab';
import OverviewTab from './A2aProxyPage/OverviewTab';
import {
  defaultA2aProxyFormData,
  formDataFromProxy,
  payloadFromFormData,
  validateA2aProxyForm,
} from './A2aProxyPage/formHelpers';
import type { A2aProxy, A2aProxyFormData, SecretOption } from './A2aProxyPage/types';

const EditA2aProxyPage: React.FC = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;
  const [formData, setFormData] = useState<A2aProxyFormData>(() => defaultA2aProxyFormData());
  const [secrets, setSecrets] = useState<SecretOption[]>([]);
  const [loading, setLoading] = useState(isEditMode);
  const [saving, setSaving] = useState(false);
  const [modified, setModified] = useState(!isEditMode);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadSecrets();
    if (isEditMode && id) loadProxy(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, isEditMode]);

  const loadSecrets = async () => {
    try {
      const response = await apiClient.get<SecretOption[]>('/secrets/');
      setSecrets(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      console.warn('Failed to load secrets for A2A Proxy form:', err);
      setSecrets([]);
    }
  };

  const loadProxy = async (proxyId: string) => {
    try {
      setLoading(true);
      const response = await apiClient.get<A2aProxy>(`/a2a-proxies/${proxyId}`);
      setFormData(formDataFromProxy(response.data));
      setModified(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load A2A Proxy';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (patch: Partial<A2aProxyFormData>) => {
    setFormData(prev => ({ ...prev, ...patch }));
    setModified(true);
  };

  const handleBackendChange = (patch: Partial<A2aProxyFormData['backend']>) => {
    setFormData(prev => ({ ...prev, backend: { ...prev.backend, ...patch } }));
    setModified(true);
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setSuccess(null);

    const validationError = validateA2aProxyForm(formData);
    if (validationError) {
      setError(validationError);
      return;
    }

    try {
      setSaving(true);
      const payload = payloadFromFormData(formData, isEditMode);
      if (isEditMode && id) {
        await apiClient.put(`/a2a-proxies/${id}`, payload);
        setModified(false);
        setSuccess('A2A Proxy saved successfully');
      } else {
        const response = await apiClient.post<A2aProxy>('/a2a-proxies', payload);
        navigate(`/proxies/a2a-proxies/${response.data.id}`, { replace: true });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save A2A Proxy';
      setError(message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading A2A Proxy</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid" data-testid="page-a2a-proxy-editor">
      <div className="mb-3">
        <button
          type="button"
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/proxies')}
          data-testid="a2a-proxy-back-button"
        >
          <i className="fas fa-arrow-left" aria-hidden="true" /> Back
        </button>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}
      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="card shadow mb-4">
          <div className="card-header py-3 d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              {isEditMode ? `Edit A2A Proxy: ${formData.name || id}` : 'Add A2A Proxy'}
            </h6>
            <button
              type="submit"
              className="btn btn-sm btn-primary"
              disabled={saving || (isEditMode && !modified)}
              data-testid="a2a-proxy-save-button"
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'} me-1`} />
              {saving ? 'Saving…' : isEditMode ? 'Save' : 'Create'}
            </button>
          </div>
          <div className="card-body">
            <InfoBanner
              title="What is an A2A Proxy?"
              testIdPrefix="a2a-proxy-overview"
              docLink={DOCS_URL.proxies}
            >
              <p className="mb-0">
                An A2A Proxy makes a Microsoft Copilot-based bot reachable through A2A, the protocol
                AI agents use to call each other directly. Its MCP Proxy sibling does the same job
                for REST APIs.
              </p>
            </InfoBanner>

            <Tabs
              defaultActiveKey="overview"
              className="mb-3 custom-channel-tabs"
              data-testid="a2a-proxy-tabs"
            >
              <Tab
                eventKey="overview"
                title={
                  <>
                    <i className="fas fa-info-circle" /> Overview
                  </>
                }
              >
                <OverviewTab formData={formData} isEditMode={isEditMode} onChange={handleChange} />
              </Tab>
              <Tab
                eventKey="backend"
                title={
                  <>
                    <i className="fas fa-server" /> Backend
                  </>
                }
              >
                <BackendTab
                  formData={formData}
                  secrets={secrets}
                  onBackendChange={handleBackendChange}
                />
              </Tab>
              <Tab
                eventKey="agent-card"
                title={
                  <>
                    <i className="fas fa-id-card" /> Agent Card
                  </>
                }
              >
                <AgentCardTab formData={formData} onChange={handleChange} />
              </Tab>
            </Tabs>
          </div>
        </div>
      </form>
    </div>
  );
};

export default EditA2aProxyPage;
