import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useApp } from '../context/AppContext';
import { usePermissions } from '../context/PermissionsContext';
import { WS_NONE, WS_DASHBOARD } from '../utils/wsSubscriptions';
import { formatDateTime, timeAgo, topAndTail } from '../utils/stringUtils';
import TrustScoreModal from '../components/didwebvh/TrustScoreModal';
import VersionHistoryModal from '../components/didwebvh/VersionHistoryModal';
import PolicyConfigModal from '../components/didwebvh/PolicyConfigModal';
import { apiClient } from '../api';
import SearchInput from '../components/shared/SearchInput';
import { EmptyState } from '../components/shared/EmptyState';
import { Badge } from '../components/shared/Badge';
import { DOCS_URL } from '../config/docs';
import { CopyButton } from '../components/shared/CopyButton';
import IssuersTab from './SettingsPage/IssuersTab';
import AuthoritiesTab from './SettingsPage/AuthoritiesTab';

const IdentitiesPage: React.FC = () => {
  const { actions, getCurrentStats } = useApp();
  const { hasPermission } = usePermissions();
  const navigate = useNavigate();
  const { did: didParam } = useParams<{ did?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [expandedIdentityDids, setExpandedIdentityDids] = useState<Set<string>>(new Set());
  const [expandedSections, setExpandedSections] = useState<Record<string, Set<string>>>({});
  const [didDocumentContent, setDidDocumentContent] = useState<any>(null);
  const [loadingDidDocument, setLoadingDidDocument] = useState(false);
  const identityRefs = useRef<Record<string, HTMLTableRowElement | null>>({});
  const [searchTerm, setSearchTerm] = useState('');
  const [issuersCount, setIssuersCount] = useState(0);
  const [authoritiesCount, setAuthoritiesCount] = useState(0);

  const tabBadge = (count: number) => {
    if (!searchTerm.trim()) return null;
    return (
      <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
        {count}
      </span>
    );
  };

  // Force re-render every 30 seconds to update relative time displays ("5 minutes ago")
  const [, setTick] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => {
      setTick(prev => prev + 1);
    }, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  // Subscribe to everything except logs to reduce WS payload size
  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // DID:webvh identities (fetched from dedicated API)
  const [didWebVhIdentities, setDidWebVhIdentities] = useState<any[]>([]);

  // DID:webvh modals
  const [showTrustScoreModal, setShowTrustScoreModal] = useState(false);
  const [showVersionHistoryModal, setShowVersionHistoryModal] = useState(false);
  const [showPolicyConfigModal, setShowPolicyConfigModal] = useState(false);
  const [selectedIdentity, setSelectedIdentity] = useState<any>(null);
  const canViewIssuers = hasPermission('issuers.view');
  const canViewAuthorities = hasPermission('authorities.view');
  const issuerParam = searchParams.get('issuer');
  const authorityParam = searchParams.get('authority');
  const activeTab = (() => {
    const rawTab = searchParams.get('tab');
    if (canViewAuthorities && (rawTab === 'authorities' || authorityParam)) {
      return 'authorities';
    }
    if (canViewIssuers && (rawTab === 'issuers' || issuerParam)) {
      return 'issuers';
    }
    return 'identities';
  })();

  // Fetch DID:webvh identities
  const fetchDidWebVhIdentities = useCallback(async () => {
    try {
      const response = await apiClient.listDidWebVhIdentities();
      setDidWebVhIdentities(response.identities || []);
    } catch (error) {
      console.error('[IdentitiesPage] Failed to fetch DID:webvh identities:', error);
      setDidWebVhIdentities([]);
    }
  }, []);

  // Load DID:webvh identities on mount
  useEffect(() => {
    fetchDidWebVhIdentities();
  }, [fetchDidWebVhIdentities]);

  const stats = getCurrentStats();

  // Merge dashboard identities with DID:webvh identities
  const identities = useMemo(() => {
    const rawIdentities = stats?.identities || [];
    const didMap = new Map<string, any>();

    // Add dashboard identities first
    rawIdentities.forEach((identity: any) => {
      if (!didMap.has(identity.did)) {
        didMap.set(identity.did, identity);
      } else {
        const existing = didMap.get(identity.did);
        if ((identity.total_count || 0) > (existing.total_count || 0)) {
          didMap.set(identity.did, identity);
        }
      }
    });

    // Add DID:webvh identities (mark them as is_local=true)
    didWebVhIdentities.forEach((identity: any) => {
      if (!didMap.has(identity.did)) {
        didMap.set(identity.did, {
          ...identity,
          is_local: true,
          is_didwebvh: true,
          name: identity.metadata?.agent_name || identity.did.split(':').pop(),
          created_at: identity.created_at,
        });
      } else {
        // Merge: prefer existing data but add DID:webvh metadata
        const existing = didMap.get(identity.did);
        didMap.set(identity.did, {
          ...existing,
          is_didwebvh: true,
          metadata: identity.metadata,
        });
      }
    });

    return Array.from(didMap.values());
  }, [stats?.identities, didWebVhIdentities]);

  // Filter identities based on search term
  const filteredIdentities = useMemo(() => {
    const trimmedSearch = searchTerm.trim();
    if (!trimmedSearch) return identities;

    const searchLower = trimmedSearch.toLowerCase();
    return identities.filter(
      identity =>
        identity.name?.toLowerCase().includes(searchLower) ||
        identity.did?.toLowerCase().includes(searchLower) ||
        identity.channel_name?.toLowerCase().includes(searchLower) ||
        identity.identity_hash?.toLowerCase().includes(searchLower)
    );
  }, [identities, searchTerm]);

  // Handle deep linking to a specific identity
  useEffect(() => {
    if (didParam) {
      const decodedDid = decodeURIComponent(didParam);
      // Expand the identity
      setExpandedIdentityDids(new Set([decodedDid]));
      setExpandedSections({
        [decodedDid]: new Set(['summary']),
      });

      // Scroll to the identity after a short delay to ensure rendering
      setTimeout(() => {
        const element = identityRefs.current[decodedDid];
        if (element) {
          element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
    }
  }, [didParam]);

  // Toggle identity details expansion
  const toggleIdentityDetails = (did: string) => {
    setExpandedIdentityDids(prev => {
      const newSet = new Set(prev);
      if (newSet.has(did)) {
        newSet.delete(did);
        // Clean up expanded sections for this identity
        setExpandedSections(prevSections => {
          const newSections = { ...prevSections };
          delete newSections[did];
          return newSections;
        });
        // Navigate back to identities list when closing
        navigate('/identities');
      } else {
        newSet.add(did);
        // Initialize with summary section open
        setExpandedSections(prevSections => ({
          ...prevSections,
          [did]: new Set(['summary']),
        }));
        // Navigate to the deep link URL when expanding
        navigate(`/identities/${encodeURIComponent(did)}`);
      }
      return newSet;
    });
  };

  // Toggle a specific section within an identity
  const toggleSection = (did: string, section: string) => {
    setExpandedSections(prev => {
      const sections = prev[did] || new Set();
      const newSections = new Set(sections);
      if (newSections.has(section)) {
        newSections.delete(section);
      } else {
        newSections.add(section);
      }
      return {
        ...prev,
        [did]: newSections,
      };
    });
  };

  const isSectionExpanded = (did: string, section: string) => {
    return expandedSections[did]?.has(section) || false;
  };

  /**
   * Converts a did:webvh DID to its standard HTTPS URL per did:webvh spec §3.4
   * (DID-to-HTTPS Transformation). Uses the current origin so the URL points to
   * the running gateway instance.
   *
   * Examples:
   *   did:webvh:<scid>:example.com:surface:<uuid>
   *     → http://localhost:8080/surface/<uuid>/did.jsonl
   *   did:webvh:<scid>:localhost%3A8080:demo-path
   *     → http://localhost:8080/demo-path/did.jsonl
   *   did:webvh:<scid>:example.com
   *     → http://localhost:8080/.well-known/did.jsonl
   */
  const didWebVhToUrl = (did: string, origin: string): string => {
    const prefix = 'did:webvh:';
    if (!did.startsWith(prefix)) {
      // Not a did:webvh — fall back to resolve-did API endpoint
      return `${origin}/api/v1/identity/resolve-did?did=${encodeURIComponent(did)}`;
    }

    const rest = did.slice(prefix.length);
    // Split by ':' — SCID is first, domain (with %3A-encoded port) is second,
    // remaining segments form the path.
    const segments = rest.split(':');

    if (segments.length < 2) {
      return `${origin}/api/v1/identity/resolve-did?did=${encodeURIComponent(did)}`;
    }

    // segments[0] = SCID  (skipped — not part of the URL)
    // segments[1] = domain (ignored — we use the current origin)
    // segments[2..] = path segments
    const pathSegments = segments.slice(2);

    if (pathSegments.length === 0) {
      // Domain-only DID → .well-known path
      return `${origin}/.well-known/did.jsonl`;
    }

    const path = pathSegments.map(s => encodeURIComponent(s)).join('/');
    return `${origin}/${path}/did.jsonl`;
  };

  // Copy spec-compliant DID document URL to clipboard (did:webvh §3.4)
  const copyDeepLink = (did: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const url = didWebVhToUrl(did, window.location.origin);
    navigator.clipboard.writeText(url);
  };

  // Load DID document for identity
  const loadDidDocumentForIdentity = async (did: string) => {
    setLoadingDidDocument(true);
    try {
      const response = await apiClient.fetch(
        `/api/v1/identity/resolve-did?did=${encodeURIComponent(did)}`
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch DID document: ${response.status}`);
      }
      const didDoc = await response.json();
      setDidDocumentContent(didDoc);
    } catch (error) {
      console.error('Error loading DID document:', error);
      setDidDocumentContent({ error: 'Failed to load DID document' });
    } finally {
      setLoadingDidDocument(false);
    }
  };

  const getBadgeClass = (badge?: string) => {
    switch (badge) {
      case 'NEW':
        return 'text-bg-success';
      case 'ACTIVE':
        return 'text-bg-primary';
      default:
        return '';
    }
  };

  const openTrustScoreModal = (identity: any, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIdentity(identity);
    setShowTrustScoreModal(true);
  };

  const openVersionHistoryModal = (identity: any, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIdentity(identity);
    setShowVersionHistoryModal(true);
  };

  const openPolicyConfigModal = (identity: any, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIdentity(identity);
    setShowPolicyConfigModal(true);
  };

  const handlePolicyConfigSave = async (config: any) => {
    // Use 'id' field from backend API (not 'uuid')
    const identityId = selectedIdentity?.id || selectedIdentity?.uuid;

    if (!identityId) {
      console.error('[IdentitiesPage] No identity ID available for policy save');
      throw new Error('No identity ID available');
    }

    try {
      const { apiClient } = await import('../api');
      // Note: apiClient already adds /api/v1 prefix, so use relative path
      await apiClient.put(`/identities/${identityId}/policy`, { config });
      // Refresh DID:webvh identities instead of full page reload
      fetchDidWebVhIdentities();
    } catch (error) {
      console.error('[IdentitiesPage] Failed to save policy config:', error);
      throw error;
    }
  };

  const handleTabSelect = (nextTab: string | null) => {
    const tab = nextTab || 'identities';
    const nextParams = new URLSearchParams(searchParams);

    if (tab === 'issuers' && canViewIssuers) {
      nextParams.set('tab', 'issuers');
      nextParams.delete('authority');
    } else if (tab === 'authorities' && canViewAuthorities) {
      nextParams.set('tab', 'authorities');
      nextParams.delete('issuer');
    } else {
      nextParams.delete('tab');
      nextParams.delete('issuer');
      nextParams.delete('authority');
    }

    setSearchParams(nextParams, { replace: true });
  };

  const handleIssuerViewChange = (viewId: string | null) => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set('tab', 'issuers');
    nextParams.delete('authority');

    if (viewId) {
      nextParams.set('issuer', viewId);
    } else {
      nextParams.delete('issuer');
    }

    setSearchParams(nextParams, { replace: true });
  };

  const handleAuthorityViewChange = (viewId: string | null) => {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set('tab', 'authorities');
    nextParams.delete('issuer');

    if (viewId) {
      nextParams.set('authority', viewId);
    } else {
      nextParams.delete('authority');
    }

    setSearchParams(nextParams, { replace: true });
  };

  return (
    <div className="container-fluid">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div className="d-flex align-items-center">
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter Agent Identities, Issuers, Authorities..."
            width="384px"
          />
        </div>
      </div>

      <div style={{ position: 'relative' }}>
        <Tabs activeKey={activeTab} onSelect={handleTabSelect} className="mb-3 custom-channel-tabs">
          <Tab
            eventKey="identities"
            title={
              <>
                <i className="fas fa-fingerprint"></i> Agent Identities{' '}
                {tabBadge(filteredIdentities.length)}
              </>
            }
          >
            <div className="pt-3">
              {identities.length === 0 ? (
                <div className="card shadow mb-4">
                  <div className="card-body">
                    <EmptyState
                      icon="fa-fingerprint"
                      title="No agent identities yet"
                      body="Agent identities are the DIDs the gateway manages or resolves for your agents. They appear here once surfaces start resolving them."
                      docsHref={DOCS_URL.identity}
                    />
                  </div>
                </div>
              ) : (
                <div className="card shadow mb-4">
                  <div className="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 className="m-0 font-weight-bold text-primary d-flex align-items-center">
                      <i className="fas fa-fingerprint me-2"></i> Agent Identities
                      <Badge
                        value={filteredIdentities.length}
                        className="ms-2"
                        ariaLabel={`${filteredIdentities.length} agent identities`}
                        suffix={searchTerm ? ` of ${identities.length}` : undefined}
                      />
                    </h6>
                  </div>
                  <div className="card-body">
                    {filteredIdentities.length === 0 ? (
                      <div className="text-center text-muted py-5">
                        <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
                        <p className="mb-0">No identities match your search.</p>
                      </div>
                    ) : (
                      <div className="table-responsive">
                        <table className="table table-hover table-sm">
                          <thead>
                            <tr>
                              <th>DID</th>
                              <th>Agent Surface</th>
                              <th>Trust Score</th>
                              <th>Attestation</th>
                              <th title="Universal Agent Identifier">UAI</th>
                              <th>Created</th>
                              <th>Usage Count</th>
                              <th>Last Used</th>
                              <th>Status</th>
                              <th>Actions</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredIdentities.map(identity => {
                              const isExpanded = expandedIdentityDids.has(identity.did);
                              return (
                                <React.Fragment key={identity.did}>
                                  <tr
                                    ref={el => {
                                      identityRefs.current[identity.did] = el;
                                    }}
                                    style={{ cursor: 'pointer' }}
                                    onClick={() => toggleIdentityDetails(identity.did)}
                                  >
                                    <td>
                                      <div className="d-inline-flex align-items-center flex-nowrap">
                                        <i
                                          className={`fas fa-chevron-${isExpanded ? 'down' : 'right'} me-2`}
                                        ></i>
                                        <code
                                          style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}
                                          title={identity.did}
                                        >
                                          {topAndTail(identity.did, 20, 16)}
                                        </code>
                                        <CopyButton text={identity.did} title="Copy DID" />
                                      </div>
                                      {identity.version !== undefined &&
                                        identity.version !== null && (
                                          <span className="badge badge-primary ml-2">
                                            v{identity.version}
                                          </span>
                                        )}
                                      {identity.scid && (
                                        <small className="text-muted ml-2" title={identity.scid}>
                                          SCID {identity.scid.slice(0, 10)}...
                                        </small>
                                      )}
                                    </td>
                                    <td>
                                      {identity.channel_name && identity.channel_config_id ? (
                                        <button
                                          type="button"
                                          onClick={e => {
                                            e.stopPropagation();
                                            navigate(`/surfaces/${identity.channel_config_id}`);
                                          }}
                                          className="btn btn-link p-0 align-baseline text-primary"
                                          style={{ fontSize: '0.75rem' }}
                                        >
                                          {identity.channel_name}
                                        </button>
                                      ) : (
                                        <span className="text-muted">-</span>
                                      )}
                                    </td>
                                    <td>
                                      {identity.trust_score !== undefined ? (
                                        <div style={{ minWidth: '120px' }}>
                                          <div
                                            className="progress"
                                            style={{ height: '20px', marginBottom: '2px' }}
                                          >
                                            <div
                                              className={`progress-bar ${
                                                identity.trust_score >= 0.8
                                                  ? 'bg-success'
                                                  : identity.trust_score >= 0.6
                                                    ? 'bg-info'
                                                    : identity.trust_score >= 0.4
                                                      ? 'bg-warning'
                                                      : 'bg-danger'
                                              }`}
                                              role="progressbar"
                                              style={{
                                                width: `${identity.trust_score * 100}%`,
                                              }}
                                              aria-valuenow={identity.trust_score * 100}
                                              aria-valuemin={0}
                                              aria-valuemax={100}
                                            >
                                              <small
                                                className="font-weight-bold"
                                                style={{ fontSize: '0.7rem' }}
                                              >
                                                {(identity.trust_score * 100).toFixed(0)}%
                                              </small>
                                            </div>
                                          </div>
                                        </div>
                                      ) : (
                                        <span className="text-muted">-</span>
                                      )}
                                    </td>
                                    <td>
                                      {identity.has_tee && (
                                        <i
                                          className="fas fa-bolt text-warning me-1"
                                          title="TEE Enabled"
                                        ></i>
                                      )}
                                      {identity.has_cloud && (
                                        <i
                                          className="fas fa-cloud text-info me-1"
                                          title="Cloud Attestation"
                                        ></i>
                                      )}
                                      {identity.attestation_count !== undefined ? (
                                        <small className="text-muted">
                                          {identity.attestation_count}
                                        </small>
                                      ) : !identity.has_tee && !identity.has_cloud ? (
                                        <span className="text-muted">-</span>
                                      ) : null}
                                    </td>
                                    <td>
                                      {(() => {
                                        const uai =
                                          identity.metadata?.agentDNA?.uai || identity.uai;
                                        if (!uai) return <span className="text-muted">—</span>;
                                        // Extract the 4-part fingerprint after the 3rd colon
                                        const parts = uai.split(':');
                                        const fingerprint = parts[3] || '';
                                        return (
                                          <span
                                            title={uai}
                                            style={{
                                              fontFamily: 'monospace',
                                              fontSize: '0.75rem',
                                              letterSpacing: '0.02em',
                                            }}
                                          >
                                            {fingerprint || uai.slice(0, 20) + '…'}
                                          </span>
                                        );
                                      })()}
                                    </td>
                                    <td>
                                      <small>
                                        {identity.created_at
                                          ? formatDateTime(identity.created_at, true)
                                          : 'Never'}
                                      </small>
                                    </td>
                                    <td>
                                      <small>
                                        {identity.usage_count || identity.use_count || 0}
                                      </small>
                                    </td>
                                    <td>
                                      <small>
                                        {identity.last_used_at || identity.last_used
                                          ? timeAgo((identity.last_used_at || identity.last_used)!)
                                          : 'Never'}
                                      </small>
                                    </td>
                                    <td>
                                      {identity.is_local !== undefined ? (
                                        <>
                                          <span
                                            className={`badge ${identity.is_local ? 'text-bg-info' : 'text-bg-warning'}`}
                                          >
                                            {identity.is_local ? 'LOCAL' : 'REMOTE'}
                                          </span>
                                          {!identity.is_local && identity.verified && (
                                            <span
                                              className="badge text-bg-success ms-1"
                                              style={{ marginLeft: '0.75rem' }}
                                            >
                                              VERIFIED
                                            </span>
                                          )}
                                        </>
                                      ) : identity.badge ? (
                                        <>
                                          <span
                                            className={`badge ${getBadgeClass(identity.badge)}`}
                                          >
                                            {identity.badge}
                                          </span>
                                        </>
                                      ) : (
                                        <>
                                          <span className="text-muted">-</span>
                                        </>
                                      )}
                                    </td>
                                    <td>
                                      <div className="btn-group btn-group-sm" role="group">
                                        {identity.trust_score !== undefined && (
                                          <button
                                            className="btn btn-outline-primary"
                                            onClick={e => openTrustScoreModal(identity, e)}
                                            title="View Trust Score"
                                          >
                                            <i className="fas fa-chart-line"></i>
                                          </button>
                                        )}
                                        {identity.uuid && (
                                          <button
                                            className="btn btn-outline-secondary"
                                            onClick={e => openVersionHistoryModal(identity, e)}
                                            title="View version history"
                                          >
                                            <i className="fas fa-history"></i>
                                          </button>
                                        )}
                                        <button
                                          className="btn btn-outline-info"
                                          onClick={e => openPolicyConfigModal(identity, e)}
                                          title="Configure Policy"
                                        >
                                          <i className="fas fa-shield-alt"></i>
                                        </button>
                                        <button
                                          className="btn btn-outline-secondary"
                                          onClick={e => copyDeepLink(identity.did, e)}
                                          title="Copy link"
                                        >
                                          <i className="fas fa-link"></i>
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                  {expandedIdentityDids.has(identity.did) && (
                                    <tr className="expanded-detail-row">
                                      <td colSpan={10} className="p-0">
                                        <div className="p-3">
                                          <div
                                            className="accordion"
                                            id={`identityAccordion-${identity.did}`}
                                          >
                                            {/* Summary */}
                                            <div className="card mb-2">
                                              <div
                                                className="card-header py-1 bg-light"
                                                style={{ cursor: 'pointer' }}
                                                onClick={() =>
                                                  toggleSection(identity.did, 'summary')
                                                }
                                              >
                                                <small className="mb-0 text-muted">
                                                  <i
                                                    className={`fas fa-chevron-${isSectionExpanded(identity.did, 'summary') ? 'down' : 'right'} me-2`}
                                                  ></i>
                                                  <i className="fas fa-info-circle"></i> Summary
                                                </small>
                                              </div>
                                              {isSectionExpanded(identity.did, 'summary') && (
                                                <div className="card-body py-2 px-3">
                                                  <div className="row">
                                                    <div className="col-md-6">
                                                      <div className="mb-2">
                                                        <small className="font-weight-bold text-muted">
                                                          DID:
                                                        </small>
                                                        <div className="d-flex align-items-center">
                                                          <small>
                                                            <code style={{ fontSize: '0.75rem' }}>
                                                              {identity.did}
                                                            </code>
                                                          </small>
                                                          <CopyButton
                                                            text={identity.did}
                                                            title="Copy DID"
                                                          />
                                                        </div>
                                                      </div>
                                                      <div className="mb-2">
                                                        <small className="font-weight-bold text-muted">
                                                          Identity Hash:
                                                        </small>
                                                        <div>
                                                          <small>{identity.identity_hash}</small>
                                                        </div>
                                                      </div>
                                                      {identity.channel_name &&
                                                        identity.channel_config_id && (
                                                          <div className="mb-2">
                                                            <small className="font-weight-bold text-muted">
                                                              Channel:
                                                            </small>
                                                            <div>
                                                              <small>
                                                                <button
                                                                  type="button"
                                                                  onClick={e => {
                                                                    e.stopPropagation();
                                                                    navigate(
                                                                      `/surfaces/${identity.channel_config_id}`
                                                                    );
                                                                  }}
                                                                  className="btn btn-link p-0 align-baseline text-primary"
                                                                >
                                                                  {identity.channel_name}
                                                                </button>
                                                              </small>
                                                            </div>
                                                          </div>
                                                        )}
                                                    </div>
                                                    <div className="col-md-6">
                                                      <div className="mb-2">
                                                        <small className="font-weight-bold text-muted">
                                                          Created:
                                                        </small>
                                                        <div>
                                                          <small>
                                                            {identity.created_at
                                                              ? formatDateTime(
                                                                  identity.created_at,
                                                                  true
                                                                )
                                                              : 'Never'}
                                                          </small>
                                                        </div>
                                                      </div>
                                                      <div className="mb-2">
                                                        <small className="font-weight-bold text-muted">
                                                          Usage Count:
                                                        </small>
                                                        <div>
                                                          <small>
                                                            <strong>
                                                              {identity.usage_count ||
                                                                identity.use_count ||
                                                                0}
                                                            </strong>{' '}
                                                            {(identity.usage_count ||
                                                              identity.use_count ||
                                                              0) === 1
                                                              ? 'time'
                                                              : 'times'}
                                                          </small>
                                                        </div>
                                                      </div>
                                                      <div className="mb-2">
                                                        <small className="font-weight-bold text-muted">
                                                          Last Used:
                                                        </small>
                                                        <div>
                                                          <small>
                                                            {identity.last_used_at ||
                                                            identity.last_used
                                                              ? formatDateTime(
                                                                  (identity.last_used_at ||
                                                                    identity.last_used)!,
                                                                  true
                                                                )
                                                              : 'Never'}
                                                          </small>
                                                        </div>
                                                      </div>
                                                    </div>
                                                  </div>
                                                </div>
                                              )}
                                            </div>

                                            {/* Identity Field Values */}
                                            {identity.agent_identity && (
                                              <div className="card mb-2">
                                                <div
                                                  className="card-header py-1 bg-light"
                                                  style={{ cursor: 'pointer' }}
                                                  onClick={() =>
                                                    toggleSection(identity.did, 'fields')
                                                  }
                                                >
                                                  <small className="mb-0 text-muted">
                                                    <i
                                                      className={`fas fa-chevron-${isSectionExpanded(identity.did, 'fields') ? 'down' : 'right'} me-2`}
                                                    ></i>
                                                    <i className="fas fa-id-badge"></i> Identity
                                                    Field Values
                                                  </small>
                                                </div>
                                                {isSectionExpanded(identity.did, 'fields') && (
                                                  <div className="card-body py-2 px-3">
                                                    <p className="text-muted small mb-2">
                                                      <i className="fas fa-info-circle"></i> These
                                                      fields marked with x-identity were used to
                                                      create this identity mapping
                                                    </p>
                                                    {(() => {
                                                      const identityFields =
                                                        identity.agent_identity;

                                                      if (
                                                        !identityFields ||
                                                        typeof identityFields !== 'object' ||
                                                        Object.keys(identityFields).length === 0
                                                      ) {
                                                        return (
                                                          <p className="text-muted">
                                                            <i className="fas fa-exclamation-circle"></i>{' '}
                                                            No identity fields stored for this
                                                            identity
                                                          </p>
                                                        );
                                                      }

                                                      const fieldEntries = Object.entries(
                                                        identityFields
                                                      ).map(([key, value]) => ({ key, value }));

                                                      return (
                                                        <table className="table table-sm table-borderless mb-0">
                                                          <tbody>
                                                            {fieldEntries.map(({ key, value }) => (
                                                              <tr key={key}>
                                                                <td style={{ width: '40%' }}>
                                                                  <strong className="text-primary">
                                                                    {key}
                                                                  </strong>
                                                                </td>
                                                                <td style={{ width: '60%' }}>
                                                                  <code className="text-body">
                                                                    {typeof value === 'object'
                                                                      ? JSON.stringify(
                                                                          value,
                                                                          null,
                                                                          2
                                                                        )
                                                                      : String(value)}
                                                                  </code>
                                                                </td>
                                                              </tr>
                                                            ))}
                                                          </tbody>
                                                        </table>
                                                      );
                                                    })()}
                                                  </div>
                                                )}
                                              </div>
                                            )}

                                            {/* Identity Field Values (Full JSON) */}
                                            {identity.agent_identity && (
                                              <div className="card mb-2">
                                                <div
                                                  className="card-header py-1 bg-light"
                                                  style={{ cursor: 'pointer' }}
                                                  onClick={() =>
                                                    toggleSection(identity.did, 'json')
                                                  }
                                                >
                                                  <small className="mb-0 text-muted">
                                                    <i
                                                      className={`fas fa-chevron-${isSectionExpanded(identity.did, 'json') ? 'down' : 'right'} me-2`}
                                                    ></i>
                                                    <i className="fas fa-robot"></i> Identity Field
                                                    Values (Full JSON)
                                                  </small>
                                                </div>
                                                {isSectionExpanded(identity.did, 'json') && (
                                                  <div className="card-body py-2 px-3">
                                                    <pre className="mb-0">
                                                      <code>
                                                        {JSON.stringify(
                                                          identity.agent_identity,
                                                          null,
                                                          2
                                                        )}
                                                      </code>
                                                    </pre>
                                                  </div>
                                                )}
                                              </div>
                                            )}

                                            {/* Agent DNA */}
                                            {identity.metadata?.agentDNA && (
                                              <div className="card mb-2">
                                                <div
                                                  className="card-header py-1 bg-light"
                                                  style={{ cursor: 'pointer' }}
                                                  onClick={() => toggleSection(identity.did, 'dna')}
                                                >
                                                  <small className="mb-0 text-muted">
                                                    <i
                                                      className={`fas fa-chevron-${isSectionExpanded(identity.did, 'dna') ? 'down' : 'right'} mr-2`}
                                                    ></i>
                                                    <i className="fas fa-dna"></i> Agent DNA
                                                    <span
                                                      className="badge badge-info ml-2"
                                                      style={{ fontSize: '0.65rem' }}
                                                    >
                                                      UAI
                                                    </span>
                                                  </small>
                                                </div>
                                                {isSectionExpanded(identity.did, 'dna') && (
                                                  <div className="card-body py-2 px-3">
                                                    {(() => {
                                                      const dna = identity.metadata.agentDNA;
                                                      const copyUai = (e: React.MouseEvent) => {
                                                        e.stopPropagation();
                                                        navigator.clipboard.writeText(
                                                          dna.uai || ''
                                                        );
                                                      };
                                                      return (
                                                        <>
                                                          {/* UAI string */}
                                                          <div className="mb-3 p-2 bg-light border rounded d-flex justify-content-between align-items-center">
                                                            <div>
                                                              <small className="font-weight-bold text-muted d-block">
                                                                UAI
                                                              </small>
                                                              <code
                                                                style={{
                                                                  fontSize: '0.75rem',
                                                                  wordBreak: 'break-all',
                                                                }}
                                                              >
                                                                {dna.uai}
                                                              </code>
                                                            </div>
                                                            <button
                                                              className="btn btn-sm btn-outline-secondary ml-2"
                                                              style={{ whiteSpace: 'nowrap' }}
                                                              onClick={copyUai}
                                                              title="Copy UAI"
                                                            >
                                                              <i className="fas fa-copy"></i>
                                                            </button>
                                                          </div>

                                                          <div className="row">
                                                            {/* Genesis */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-seedling"></i>{' '}
                                                                Genesis
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0 pr-1"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Provider
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {
                                                                          dna.genesis?.modelSpec
                                                                            ?.provider
                                                                        }
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Model
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {
                                                                          dna.genesis?.modelSpec
                                                                            ?.model
                                                                        }
                                                                        {dna.genesis?.modelSpec
                                                                          ?.version
                                                                          ? ` v${dna.genesis.modelSpec.version}`
                                                                          : ''}
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Genesis hash
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.genesis?.genesisHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Behavioral */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-brain"></i>{' '}
                                                                Behavioral
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Fingerprint
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.behavioral?.behavioralHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Measured
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <small>
                                                                        {dna.behavioral?.measuredAt
                                                                          ? new Date(
                                                                              dna.behavioral
                                                                                .measuredAt
                                                                            ).toLocaleDateString()
                                                                          : '—'}
                                                                      </small>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Operational */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-server"></i>{' '}
                                                                Operational
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      TEE
                                                                    </td>
                                                                    <td className="py-0">
                                                                      {dna.operational
                                                                        ?.teeAttestation ? (
                                                                        <span className="text-success">
                                                                          <i className="fas fa-check-circle"></i>{' '}
                                                                          Present
                                                                        </span>
                                                                      ) : (
                                                                        <span className="text-muted">
                                                                          —
                                                                        </span>
                                                                      )}
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Cloud
                                                                    </td>
                                                                    <td className="py-0">
                                                                      {dna.operational
                                                                        ?.cloudAttestation ? (
                                                                        <span className="text-success">
                                                                          <i className="fas fa-check-circle"></i>{' '}
                                                                          {dna.operational
                                                                            .cloudAttestation
                                                                            .provider || 'Present'}
                                                                        </span>
                                                                      ) : (
                                                                        <span className="text-muted">
                                                                          —
                                                                        </span>
                                                                      )}
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Op hash
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.operational?.operationalHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Attestations */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-certificate"></i>{' '}
                                                                Attestations
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Count
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <strong>
                                                                        {dna.attestations?.count ??
                                                                          '—'}
                                                                      </strong>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Merkle root
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.attestations?.merkleRoot?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  {dna.attestations
                                                                    ?.lastUpdated && (
                                                                    <tr>
                                                                      <td className="text-muted py-0">
                                                                        Updated
                                                                      </td>
                                                                      <td className="py-0">
                                                                        <small>
                                                                          {new Date(
                                                                            dna.attestations
                                                                              .lastUpdated
                                                                          ).toLocaleDateString()}
                                                                        </small>
                                                                      </td>
                                                                    </tr>
                                                                  )}
                                                                </tbody>
                                                              </table>
                                                            </div>
                                                          </div>
                                                        </>
                                                      );
                                                    })()}
                                                  </div>
                                                )}
                                              </div>
                                            )}

                                            {/* Agent DNA */}
                                            {identity.metadata?.agentDNA && (
                                              <div className="card mb-2">
                                                <div
                                                  className="card-header py-1 bg-light"
                                                  style={{ cursor: 'pointer' }}
                                                  onClick={() => toggleSection(identity.did, 'dna')}
                                                >
                                                  <small className="mb-0 text-muted">
                                                    <i
                                                      className={`fas fa-chevron-${isSectionExpanded(identity.did, 'dna') ? 'down' : 'right'} mr-2`}
                                                    ></i>
                                                    <i className="fas fa-dna"></i> Agent DNA
                                                    <span
                                                      className="badge badge-info ml-2"
                                                      style={{ fontSize: '0.65rem' }}
                                                    >
                                                      UAI
                                                    </span>
                                                  </small>
                                                </div>
                                                {isSectionExpanded(identity.did, 'dna') && (
                                                  <div className="card-body py-2 px-3">
                                                    {(() => {
                                                      const dna = identity.metadata.agentDNA;
                                                      const copyUai = (e: React.MouseEvent) => {
                                                        e.stopPropagation();
                                                        navigator.clipboard.writeText(
                                                          dna.uai || ''
                                                        );
                                                      };
                                                      return (
                                                        <>
                                                          {/* UAI string */}
                                                          <div className="mb-3 p-2 bg-light border rounded d-flex justify-content-between align-items-center">
                                                            <div>
                                                              <small className="font-weight-bold text-muted d-block">
                                                                UAI
                                                              </small>
                                                              <code
                                                                style={{
                                                                  fontSize: '0.75rem',
                                                                  wordBreak: 'break-all',
                                                                }}
                                                              >
                                                                {dna.uai}
                                                              </code>
                                                            </div>
                                                            <button
                                                              className="btn btn-sm btn-outline-secondary ml-2"
                                                              style={{ whiteSpace: 'nowrap' }}
                                                              onClick={copyUai}
                                                              title="Copy UAI"
                                                            >
                                                              <i className="fas fa-copy"></i>
                                                            </button>
                                                          </div>

                                                          <div className="row">
                                                            {/* Genesis */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-seedling"></i>{' '}
                                                                Genesis
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0 pr-1"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Provider
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {
                                                                          dna.genesis?.modelSpec
                                                                            ?.provider
                                                                        }
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Model
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {
                                                                          dna.genesis?.modelSpec
                                                                            ?.model
                                                                        }
                                                                        {dna.genesis?.modelSpec
                                                                          ?.version
                                                                          ? ` v${dna.genesis.modelSpec.version}`
                                                                          : ''}
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Genesis hash
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.genesis?.genesisHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Behavioral */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-brain"></i>{' '}
                                                                Behavioral
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Fingerprint
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.behavioral?.behavioralHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Measured
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <small>
                                                                        {dna.behavioral?.measuredAt
                                                                          ? new Date(
                                                                              dna.behavioral
                                                                                .measuredAt
                                                                            ).toLocaleDateString()
                                                                          : '—'}
                                                                      </small>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Operational */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-server"></i>{' '}
                                                                Operational
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      TEE
                                                                    </td>
                                                                    <td className="py-0">
                                                                      {dna.operational
                                                                        ?.teeAttestation ? (
                                                                        <span className="text-success">
                                                                          <i className="fas fa-check-circle"></i>{' '}
                                                                          Present
                                                                        </span>
                                                                      ) : (
                                                                        <span className="text-muted">
                                                                          —
                                                                        </span>
                                                                      )}
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Cloud
                                                                    </td>
                                                                    <td className="py-0">
                                                                      {dna.operational
                                                                        ?.cloudAttestation ? (
                                                                        <span className="text-success">
                                                                          <i className="fas fa-check-circle"></i>{' '}
                                                                          {dna.operational
                                                                            .cloudAttestation
                                                                            .provider || 'Present'}
                                                                        </span>
                                                                      ) : (
                                                                        <span className="text-muted">
                                                                          —
                                                                        </span>
                                                                      )}
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Op hash
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.operational?.operationalHash?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                </tbody>
                                                              </table>
                                                            </div>

                                                            {/* Attestations */}
                                                            <div className="col-md-6 mb-2">
                                                              <small className="font-weight-bold text-primary">
                                                                <i className="fas fa-certificate"></i>{' '}
                                                                Attestations
                                                              </small>
                                                              <table
                                                                className="table table-sm table-borderless mb-0"
                                                                style={{ fontSize: '0.75rem' }}
                                                              >
                                                                <tbody>
                                                                  <tr>
                                                                    <td
                                                                      className="text-muted py-0"
                                                                      style={{ width: '45%' }}
                                                                    >
                                                                      Count
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <strong>
                                                                        {dna.attestations?.count ??
                                                                          '—'}
                                                                      </strong>
                                                                    </td>
                                                                  </tr>
                                                                  <tr>
                                                                    <td className="text-muted py-0">
                                                                      Merkle root
                                                                    </td>
                                                                    <td className="py-0">
                                                                      <code>
                                                                        {dna.attestations?.merkleRoot?.slice(
                                                                          0,
                                                                          12
                                                                        )}
                                                                        …
                                                                      </code>
                                                                    </td>
                                                                  </tr>
                                                                  {dna.attestations
                                                                    ?.lastUpdated && (
                                                                    <tr>
                                                                      <td className="text-muted py-0">
                                                                        Updated
                                                                      </td>
                                                                      <td className="py-0">
                                                                        <small>
                                                                          {new Date(
                                                                            dna.attestations
                                                                              .lastUpdated
                                                                          ).toLocaleDateString()}
                                                                        </small>
                                                                      </td>
                                                                    </tr>
                                                                  )}
                                                                </tbody>
                                                              </table>
                                                            </div>
                                                          </div>
                                                        </>
                                                      );
                                                    })()}
                                                  </div>
                                                )}
                                              </div>
                                            )}

                                            {/* DID Document */}
                                            <div className="card mb-2">
                                              <div
                                                className="card-header py-1 bg-light"
                                                style={{ cursor: 'pointer' }}
                                                onClick={() => {
                                                  toggleSection(identity.did, 'did');
                                                  if (
                                                    !isSectionExpanded(identity.did, 'did') &&
                                                    !didDocumentContent &&
                                                    !loadingDidDocument
                                                  ) {
                                                    loadDidDocumentForIdentity(identity.did);
                                                  }
                                                }}
                                              >
                                                <small className="mb-0 text-muted">
                                                  <i
                                                    className={`fas fa-chevron-${isSectionExpanded(identity.did, 'did') ? 'down' : 'right'} me-2`}
                                                  ></i>
                                                  <i className="fas fa-file-alt"></i> DID Document
                                                </small>
                                              </div>
                                              {isSectionExpanded(identity.did, 'did') && (
                                                <div className="card-body py-2 px-3">
                                                  {loadingDidDocument ? (
                                                    <div className="text-center text-muted">
                                                      <i className="fas fa-spinner fa-spin"></i>{' '}
                                                      Loading DID document...
                                                    </div>
                                                  ) : didDocumentContent?.error ? (
                                                    <div className="text-center text-danger">
                                                      <i className="fas fa-exclamation-triangle"></i>{' '}
                                                      {didDocumentContent.error}
                                                    </div>
                                                  ) : didDocumentContent ? (
                                                    <pre className="mb-0">
                                                      <code>
                                                        {JSON.stringify(
                                                          didDocumentContent,
                                                          null,
                                                          2
                                                        )}
                                                      </code>
                                                    </pre>
                                                  ) : (
                                                    <div className="text-center text-muted">
                                                      Click to load DID document
                                                    </div>
                                                  )}
                                                </div>
                                              )}
                                            </div>
                                          </div>
                                        </div>
                                      </td>
                                    </tr>
                                  )}
                                </React.Fragment>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </Tab>

          {canViewIssuers && (
            <Tab
              eventKey="issuers"
              title={
                <>
                  <i className="fas fa-sitemap"></i> Issuers {tabBadge(issuersCount)}
                </>
              }
            >
              <div className="pt-3">
                <IssuersTab
                  initialViewId={issuerParam}
                  onViewChange={handleIssuerViewChange}
                  externalSearchTerm={searchTerm}
                  onFilteredCountChange={setIssuersCount}
                />
              </div>
            </Tab>
          )}

          {canViewAuthorities && (
            <Tab
              eventKey="authorities"
              title={
                <>
                  <i className="fas fa-landmark"></i> Authorities {tabBadge(authoritiesCount)}
                </>
              }
            >
              <div className="pt-3">
                <AuthoritiesTab
                  initialViewId={authorityParam}
                  onViewChange={handleAuthorityViewChange}
                  externalSearchTerm={searchTerm}
                  onFilteredCountChange={setAuthoritiesCount}
                />
              </div>
            </Tab>
          )}
        </Tabs>
      </div>

      {/* DID:webvh Modals */}
      {selectedIdentity && (
        <>
          <TrustScoreModal
            identityId={selectedIdentity.uuid || selectedIdentity.did}
            did={selectedIdentity.did}
            show={showTrustScoreModal}
            onHide={() => {
              setShowTrustScoreModal(false);
              setSelectedIdentity(null);
            }}
            agentDna={selectedIdentity?.metadata?.agentDNA}
          />
          <VersionHistoryModal
            identityId={selectedIdentity.uuid || selectedIdentity.did}
            did={selectedIdentity.did}
            show={showVersionHistoryModal}
            onHide={() => {
              setShowVersionHistoryModal(false);
              setSelectedIdentity(null);
            }}
          />
          <PolicyConfigModal
            identity={selectedIdentity}
            show={showPolicyConfigModal}
            onHide={() => {
              setShowPolicyConfigModal(false);
              setSelectedIdentity(null);
            }}
            onSave={handlePolicyConfigSave}
          />
        </>
      )}
    </div>
  );
};

export default IdentitiesPage;
