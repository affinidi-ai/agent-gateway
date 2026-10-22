import React, { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Tab, Tabs } from 'react-bootstrap';
import { apiClient } from '../api';
import { ConnectionRuntimeStatus } from '../utils/connectionHealth';
import { showToast } from '../utils/toaster';
import { ExposureMode, exposureModeOf } from '../utils/gateways';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import OverviewTab from './EditGatewayPage/OverviewTab';
import PublishingTab from './EditGatewayPage/PublishingTab';
import RemoteTab from './EditGatewayPage/RemoteTab';
import IssuerDidsCard, {
  GatewayIssuerDids,
  issuerDidsFromGateway,
} from './EditGatewayPage/IssuerDidsCard';
import GlobalPolicyTab from './EditGatewayPage/GlobalPolicyTab';

interface GatewayForm {
  name: string;
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: 'active' | 'disabled';
  exposed_channels?: string[];
  exposure_mode?: ExposureMode;
}

interface GatewayMetadata {
  created_at: string;
  updated_at: string;
}

interface RemoteChannel {
  config_id: string;
  name: string;
  description?: string;
  listen_address: string;
  protocol: string;
}

const EditGatewayPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = id !== undefined && id !== 'new';

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<GatewayForm>({
    name: '',
    description: '',
    did: '',
    gateway_type: 'remote',
    status: 'active',
  });
  const [error, setError] = useState<string>('');
  const [remoteChannels, setRemoteChannels] = useState<RemoteChannel[]>([]);
  const [loadingChannels, setLoadingChannels] = useState(false);
  const [channelsError, setChannelsError] = useState<string>('');
  const [allChannels, setAllChannels] = useState<any[]>([]);
  const [savingExposedChannels, setSavingExposedChannels] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const isSelfGateway = form.gateway_type === 'self';
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [gatewayMetadata, setGatewayMetadata] = useState<GatewayMetadata | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<ConnectionRuntimeStatus | null>(null);
  const [issuerDids, setIssuerDids] = useState<GatewayIssuerDids>(issuerDidsFromGateway({}));

  // Handle /gateways/self - look up the actual self gateway ID and redirect
  useEffect(() => {
    if (id === 'self') {
      const resolveSelfGateway = async () => {
        try {
          const response = await apiClient.get('/gateways');
          const selfGateway = response.data.find((g: any) => g.gateway_type === 'self');
          if (selfGateway) {
            navigate(`/gateways/${encodeURIComponent(selfGateway.id)}`, { replace: true });
          } else {
            setError('No self gateway found');
          }
        } catch (error: any) {
          setError(error.message || 'Failed to resolve self gateway');
        }
      };
      resolveSelfGateway();
    }
  }, [id, navigate]);

  const fetchRemoteChannels = useCallback(
    async (forceRefresh: boolean = false) => {
      if (!id) return;

      try {
        setLoadingChannels(true);
        setChannelsError('');
        const url = forceRefresh
          ? `/gateways/${id}/surfaces?force_refresh=true`
          : `/gateways/${id}/surfaces`;
        const response = await apiClient.get(url);

        if (response.data.success) {
          setRemoteChannels(response.data.channels || []);
        } else {
          setChannelsError(response.data.message || 'Failed to fetch channels');
        }
      } catch (error: any) {
        setChannelsError(error.message || 'Failed to fetch channels from remote gateway');
      } finally {
        setLoadingChannels(false);
      }
    },
    [id]
  );

  const fetchAllChannels = useCallback(async () => {
    try {
      const surfaces = await apiClient.listSurfaces();
      setAllChannels(
        surfaces.map(surface => ({
          config_id: surface.surface_id,
          name: surface.name,
          description: surface.description,
        }))
      );
    } catch (error: any) {
      console.error('Failed to load local surfaces:', error);
      setAllChannels([]);
    }
  }, []);

  const fetchGateway = useCallback(async () => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/gateways/${id}`);
      setGatewayMetadata({
        created_at: response.data.created_at,
        updated_at: response.data.updated_at,
      });
      setRuntimeStatus(response.data.runtime_status ?? null);
      setIssuerDids(issuerDidsFromGateway(response.data));
      setForm({
        name: response.data.name,
        description: response.data.description,
        did: response.data.did,
        gateway_type: response.data.gateway_type,
        status: response.data.status,
        exposed_channels: response.data.exposed_channels || [],
        exposure_mode: exposureModeOf(response.data),
      });

      // Load all local channels for remote gateways
      if (response.data.gateway_type === 'remote') {
        fetchAllChannels();
      }

      // Auto-load channels for remote gateways
      if (response.data.gateway_type === 'remote' && response.data.status === 'active') {
        fetchRemoteChannels();
      }
    } catch (error: any) {
      setError(error.message || 'Failed to load gateway');
    } finally {
      setLoading(false);
    }
  }, [fetchAllChannels, fetchRemoteChannels, id]);

  useEffect(() => {
    if (isEditMode && id && id !== 'self') {
      fetchGateway();
    }
  }, [fetchGateway, id, isEditMode]);

  const handleToggleExposedChannel = (channelId: string) => {
    const exposed = form.exposed_channels || [];
    const isCurrentlyExposed = exposed.includes(channelId);
    setForm({
      ...form,
      exposed_channels: isCurrentlyExposed
        ? exposed.filter(id => id !== channelId)
        : [...exposed, channelId],
    });
  };

  const handleSaveExposedChannels = async () => {
    if (!id) return;

    try {
      setSavingExposedChannels(true);
      const exposureMode = form.exposure_mode ?? 'none';
      await apiClient.put(`/gateways/${id}/exposed-surfaces`, {
        exposure_mode: exposureMode,
        exposed_channels: exposureMode === 'list' ? form.exposed_channels || [] : [],
      });
      setSuccess('Exposure updated successfully!');
      setTimeout(() => setSuccess(null), 3000);
    } catch (error: any) {
      setError(error.message || 'Failed to update exposure');
    } finally {
      setSavingExposedChannels(false);
    }
  };

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');
      setSuccess(null);

      if (!form.name || !form.did) {
        setError('Name and DID are required');
        return;
      }

      try {
        setSaving(true);
        const gatewayData = {
          name: form.name,
          description: form.description,
          did: form.did,
          gateway_type: form.gateway_type,
          status: form.status,
        };
        if (isEditMode) {
          await apiClient.put(`/gateways/${id}`, gatewayData);
          showToast('success', 'Gateway updated successfully!');
        } else {
          await apiClient.post('/gateways', form);
          showToast('success', 'Gateway created successfully!');
        }
        navigate('/connections?tab=gateways');
      } catch (error: any) {
        setError(error.message || 'Failed to save gateway');
      } finally {
        setSaving(false);
      }
    },
    [form, isEditMode, id, navigate]
  );

  const handleDelete = async () => {
    try {
      setSaving(true);
      await apiClient.delete(`/gateways/${id}`);
      navigate('/connections?tab=gateways');
    } catch (error: any) {
      setError(error.message || 'Failed to delete gateway');
    } finally {
      setSaving(false);
    }
  };

  // Add keyboard shortcut support for save (Ctrl+S / Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      // Check for Ctrl+S (Windows/Linux) or Cmd+S (Mac)
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault(); // Prevent browser's default save behavior

        // Only trigger save if not currently saving and form is valid
        if (!saving && form.name && form.did) {
          handleSubmit(event as any);
        }
      }
    };

    // Add event listener when component mounts
    document.addEventListener('keydown', handleKeyboardSave);

    // Cleanup: remove event listener when component unmounts
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [saving, form.name, form.did, handleSubmit]);

  if (id === 'self' || loading) {
    return (
      <div className="container mt-4">
        <div className="text-center py-4">
          <div className="spinner-border" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid" data-testid="page-gateway-editor">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          data-testid="gateway-editor-back-button"
          onClick={() => navigate('/connections?tab=gateways')}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      {error && (
        <div
          key={`error-${Date.now()}`}
          className="alert alert-danger alert-dismissible fade show"
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
            onClick={() => setError('')}
            title="Close notification"
            aria-label="Close"
          />
        </div>
      )}

      {success && (
        <div
          key={`success-${Date.now()}`}
          className="alert alert-success alert-dismissible fade show"
          style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: 9999,
            minWidth: '400px',
            fontSize: '14px',
            fontWeight: 'bold',
            border: '2px solid var(--success)',
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
          }}
        >
          <i className="fas fa-check-circle me-2"></i>
          <strong>Success!</strong> {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            title="Close notification"
            aria-label="Close"
          />
        </div>
      )}

      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <div className="d-flex align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className={`fas fa-${isEditMode ? 'edit' : 'plus'}`}></i>{' '}
              {isEditMode ? `Edit Gateway: ${form.name}` : 'Add New Gateway'}
              {form.status === 'disabled' && (
                <span className="badge text-bg-warning ms-2">
                  <i className="fas fa-power-off"></i> DISABLED
                </span>
              )}
            </h6>
          </div>
          <div>
            {isEditMode && (
              <button
                className={`btn btn-sm btn-primary me-2 ${saving ? 'disabled' : ''}`}
                data-testid="gateway-editor-save-button"
                onClick={handleSubmit}
                disabled={saving}
              >
                <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
                {saving ? ' Saving...' : ' Save'}
              </button>
            )}
            {isEditMode && !isSelfGateway && (
              <button
                className={`btn btn-sm btn-outline-danger me-2 ${saving ? 'disabled' : ''}`}
                data-testid="gateway-editor-delete-button"
                onClick={handleDelete}
                disabled={saving}
                title="Delete this gateway"
              >
                <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-trash'}`}></i>
                {saving ? ' Deleting...' : ' Delete'}
              </button>
            )}
          </div>
        </div>
        <div className="card-body-channel-editor">
          <Tabs
            activeKey={activeTab}
            onSelect={k => setActiveTab(k || 'overview')}
            className="mb-3 custom-channel-tabs"
          >
            {/* Overview Tab */}
            <Tab
              eventKey="overview"
              tabAttrs={{ 'data-testid': 'gateway-editor-overview-tab-trigger' }}
              title={
                <>
                  <i className="fas fa-info-circle"></i> Overview
                </>
              }
            >
              <OverviewTab
                form={form}
                setForm={setForm}
                createdAt={gatewayMetadata?.created_at}
                updatedAt={gatewayMetadata?.updated_at}
                runtimeStatus={runtimeStatus}
                isEditMode={isEditMode}
                isSelfGateway={isSelfGateway}
                saving={saving}
                id={id}
                handleSubmit={handleSubmit}
                handleDelete={handleDelete}
                onNavigate={() => navigate('/connections?tab=gateways')}
              />
            </Tab>

            {/* Publishing Tab - Only for remote gateways in edit mode */}
            {isEditMode && form.gateway_type === 'remote' && (
              <Tab
                eventKey="publishing"
                tabAttrs={{ 'data-testid': 'gateway-editor-publishing-tab-trigger' }}
                title={
                  <>
                    <i className="fas fa-filter"></i> Publishing
                  </>
                }
              >
                <PublishingTab
                  form={form}
                  setForm={setForm}
                  allChannels={allChannels}
                  savingExposedChannels={savingExposedChannels}
                  success={success}
                  setSuccess={setSuccess}
                  handleToggleExposedChannel={handleToggleExposedChannel}
                  handleSaveExposedChannels={handleSaveExposedChannels}
                />
              </Tab>
            )}

            {/* Remote Tab - Only for remote gateways in edit mode */}
            {isEditMode && form.gateway_type === 'remote' && (
              <Tab
                eventKey="remote"
                tabAttrs={{ 'data-testid': 'gateway-editor-remote-tab-trigger' }}
                title={
                  <>
                    <i className="fas fa-network-wired"></i> Remote
                  </>
                }
              >
                <IssuerDidsCard gatewayId={id!} value={issuerDids} onChange={setIssuerDids} />
                <RemoteTab
                  remoteSurfaces={remoteChannels}
                  loadingSurfaces={loadingChannels}
                  surfacesError={channelsError}
                  fetchRemoteSurfaces={fetchRemoteChannels}
                />
              </Tab>
            )}

            {/* Global Policy Tab - Only in edit mode */}
            {isEditMode && (
              <Tab
                eventKey="global-policy"
                tabAttrs={{ 'data-testid': 'gateway-editor-global-policy-tab-trigger' }}
                title={
                  <>
                    <i className="fas fa-shield-alt"></i> Global Policy
                  </>
                }
              >
                <GlobalPolicyTab gatewayId={id!} isSelfGateway={isSelfGateway} />
              </Tab>
            )}
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default EditGatewayPage;
