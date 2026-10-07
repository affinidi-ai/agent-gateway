import React, { useEffect, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { Tab, Tabs } from 'react-bootstrap';
import { apiClient } from '../api';
import { validateOpenApiSpecServer } from '../utils/yamlValidation';
import OverviewTab from './EditMcpProxyPage/tabs/OverviewTab';
import RoutingTab from './EditMcpProxyPage/tabs/RoutingTab';
import RestApiTab from './EditMcpProxyPage/tabs/RestApiTab';
import McpSandbox from '../components/McpSandbox';
import { McpProxyFormData, ChannelPrefix, ValidationResult } from './EditMcpProxyPage/types';
import './SchemaEditor.css';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import { ManagedByBadge, useSurfacesFronting } from '../components/mcp-proxy/exposure';
import WriteWarnings, { McpProxyWriteResult } from '../components/mcp-proxy/WriteWarnings';

interface McpProxy {
  id: string;
  name: string;
  description: string;
  channel_prefix: string;
  base_url: string;
  openapi_spec: string;
  status: 'active' | 'disabled';
  endpoint_path: string;
  flatten_post_params: boolean;
  direct_access?: boolean;
  managed_by?: string | null;
  created_at: string;
  updated_at: string;
}

const EditMcpProxyPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const isEditMode = !!id;

  const tabFromUrl = searchParams.get('tab');
  const [activeTab, setActiveTab] = useState(tabFromUrl || 'overview');

  const handleTabChange = (tab: string | null) => {
    const newTab = tab || 'overview';
    setActiveTab(newTab);
    setSearchParams({ tab: newTab }, { replace: true });
  };

  const [formData, setFormData] = useState<McpProxyFormData>({
    name: '',
    description: '',
    channel_prefix: '',
    base_url: '',
    openapi_spec: '',
    endpoint_path: '',
    status: 'active',
    flatten_post_params: false,
    // New proxies keep the gateway's own default: served on their route too.
    direct_access: true,
  });
  const frontingSurfaces = useSurfacesFronting(isEditMode ? id : undefined);

  const [loading, setLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isModified, setIsModified] = useState(false);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [writeWarnings, setWriteWarnings] = useState<string[]>([]);
  const [availablePrefixes, setAvailablePrefixes] = useState<ChannelPrefix[]>([]);
  const [availableListenAddresses, setAvailableListenAddresses] = useState<string[]>([]);
  const [selectedHostPort, setSelectedHostPort] = useState<string>('');
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);

  useEffect(() => {
    setWriteWarnings([]);
    if (isEditMode && id) {
      fetchProxy();
    }
    fetchPrefixes();
  }, [id, isEditMode]);

  const fetchPrefixes = async () => {
    try {
      const response = await apiClient.fetch('/api/v1/config/surface-routing');
      if (!response.ok) {
        throw new Error('Failed to fetch routing configuration');
      }
      const config = await response.json();
      if (config.mcp_proxy_path_prefix && config.mcp_proxy_path_prefix.length > 0) {
        setAvailablePrefixes(config.mcp_proxy_path_prefix);
        // Set default if not already set and not in edit mode
        if (!formData.channel_prefix && !isEditMode) {
          setFormData(prev => ({
            ...prev,
            channel_prefix: config.mcp_proxy_path_prefix[0].prefix,
          }));
        }
      }
      if (config.available_listen_addresses && config.available_listen_addresses.length > 0) {
        setAvailableListenAddresses(config.available_listen_addresses);
        // Set default if not already set
        if (!selectedHostPort) {
          setSelectedHostPort(config.available_listen_addresses[0]);
        }
      }
    } catch (error) {
      console.error('Failed to fetch MCP proxy prefixes:', error);
    }
  };

  const fetchProxy = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get<McpProxy>(`/mcp-proxies/${id}`);
      // A gateway that predates the field serves every proxy directly.
      setFormData({ ...response.data, direct_access: response.data.direct_access ?? true });
    } catch (error: any) {
      setError(error.message || 'Failed to load MCP Proxy');
    } finally {
      setLoading(false);
    }
  };

  const handleValidate = async () => {
    if (!formData.openapi_spec || !formData.base_url) {
      setError('Please provide both OpenAPI spec and Base URL to validate');
      return;
    }

    try {
      setValidating(true);
      setValidationResult(null);
      const result = await validateOpenApiSpecServer(formData.openapi_spec, formData.base_url);
      setValidationResult(result);

      if (!result.valid) {
        setError(result.error || 'Validation failed');
      }
    } catch (error: any) {
      setError(error.message || 'Validation failed');
    } finally {
      setValidating(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setWriteWarnings([]);

    try {
      setIsSaving(true);
      if (isEditMode && id) {
        const response = await apiClient.put<McpProxyWriteResult>(`/mcp-proxies/${id}`, formData);
        setWriteWarnings(response.data?.warnings ?? []);
        // Clear dirty state on successful save
        setIsModified(false);
        // Stay on the edit page after saving
      } else {
        const response = await apiClient.post('/mcp-proxies', formData);
        // Navigate to edit page for the newly created proxy
        if (response.data && response.data.id) {
          navigate(`/proxies/mcp-proxies/${response.data.id}`, { replace: true });
        } else {
          navigate('/proxies');
        }
      }
    } catch (error: any) {
      setError(error.message || `Failed to ${isEditMode ? 'update' : 'create'} MCP Proxy`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target;

    // Handle checkbox for enabled status
    if (type === 'checkbox' && name === 'enabled') {
      const checked = (e.target as HTMLInputElement).checked;
      setFormData(prev => ({ ...prev, status: checked ? 'active' : 'disabled' }));
      setIsModified(true);
      return;
    }

    // Handle generic boolean checkboxes
    if (type === 'checkbox') {
      const checked = (e.target as HTMLInputElement).checked;
      setFormData(prev => ({ ...prev, [name]: checked }));
      setIsModified(true);
      return;
    }

    // Normalize endpoint_path to always start with /
    let normalizedValue = value;
    if (name === 'endpoint_path' && value && !value.startsWith('/')) {
      normalizedValue = '/' + value;
    }

    setFormData(prev => ({ ...prev, [name]: normalizedValue }));
    setIsModified(true);
    // Clear validation result when spec or base_url changes
    if (name === 'openapi_spec' || name === 'base_url') {
      setValidationResult(null);
    }
  };

  const handleCancel = () => {
    navigate('/proxies');
  };

  // Add keyboard shortcut support for save (Ctrl+S / Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      // Check for Ctrl+S (Windows/Linux) or Cmd+S (Mac)
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault(); // Prevent browser's default save behavior

        // Only trigger save if form has been modified and not already saving
        if (isModified && !isSaving) {
          // Trigger the same save handler as the button
          handleSubmit(new Event('submit') as any);
        }
      }
    };

    // Add event listener when component mounts
    document.addEventListener('keydown', handleKeyboardSave);

    // Cleanup: remove event listener when component unmounts
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [isModified, isSaving, handleSubmit]); // Dependencies for the effect

  if (loading && isEditMode) {
    return (
      <div className="container-fluid">
        <div className="text-center">
          <div className="spinner-border" role="status"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={handleCancel}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
          <button type="button" className="btn-close" onClick={() => setError(null)}></button>
        </div>
      )}

      <WriteWarnings warnings={writeWarnings} />

      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            Edit MCP Proxy: {formData.name}
            {formData.managed_by ? <ManagedByBadge managedBy={formData.managed_by} /> : null}
          </h6>
          <div>
            <button
              className={`btn btn-sm btn-primary me-2 ${isSaving ? 'disabled' : ''}`}
              onClick={handleSubmit}
              style={{ marginRight: '8px' }}
              disabled={(!isModified && isEditMode) || isSaving}
            >
              <i className={`fas ${isSaving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {isSaving ? ' Saving...' : isEditMode ? ' Save' : ' Create'}
            </button>
          </div>
        </div>

        <div className="card-body">
          <form onSubmit={handleSubmit}>
            <Tabs
              activeKey={activeTab}
              onSelect={handleTabChange}
              className="mb-3 custom-channel-tabs"
            >
              <Tab
                eventKey="overview"
                title={
                  <>
                    <i className="fas fa-info-circle"></i> Overview
                  </>
                }
              >
                <OverviewTab
                  formData={formData}
                  handleChange={handleChange}
                  isEditMode={isEditMode}
                  frontingSurfaces={frontingSurfaces}
                />
              </Tab>

              <Tab
                eventKey="routing"
                title={
                  <>
                    <i className="fas fa-route"></i> Routing
                  </>
                }
              >
                <RoutingTab
                  formData={formData}
                  handleChange={handleChange}
                  availablePrefixes={availablePrefixes}
                  availableListenAddresses={availableListenAddresses}
                  selectedHostPort={selectedHostPort}
                  onHostPortChange={setSelectedHostPort}
                  onDirectAccessChange={directAccess => {
                    setFormData(prev => ({ ...prev, direct_access: directAccess }));
                    setIsModified(true);
                  }}
                  frontingSurfaces={frontingSurfaces}
                />
              </Tab>

              <Tab
                eventKey="restapi"
                title={
                  <>
                    <i className="fas fa-code"></i> REST API
                  </>
                }
              >
                <RestApiTab
                  formData={formData}
                  handleChange={handleChange}
                  validationResult={validationResult}
                  validating={validating}
                  handleValidate={handleValidate}
                />
              </Tab>

              {isEditMode && formData.status === 'active' && (
                <Tab
                  eventKey="sandbox"
                  title={
                    <>
                      <i className="fas fa-flask"></i> Sandbox
                    </>
                  }
                >
                  {!formData.direct_access && !isModified ? (
                    <div
                      className="alert alert-info mt-3"
                      data-testid="mcp-proxy-sandbox-surface-only"
                    >
                      <i className="fas fa-shield-alt me-2" aria-hidden="true" />
                      <strong>Test it through a surface.</strong> This proxy has no route of its
                      own, so the sandbox cannot call it directly. Use the sandbox of a surface that
                      targets it, which also shows what that surface&apos;s authentication and
                      policies do to each call.
                    </div>
                  ) : isModified ? (
                    <div className="alert alert-warning mt-3">
                      <i className="fas fa-exclamation-triangle me-2"></i>
                      <strong>Unsaved Changes:</strong> You must save your changes before testing in
                      the sandbox. The sandbox tests the currently saved configuration.
                    </div>
                  ) : (
                    <McpSandbox
                      endpointUrl={`${formData.channel_prefix}${formData.endpoint_path}`}
                      endpointName={formData.name}
                      endpointDescription={formData.description}
                      flattenPostParams={formData.flatten_post_params}
                    />
                  )}
                </Tab>
              )}
            </Tabs>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditMcpProxyPage;
