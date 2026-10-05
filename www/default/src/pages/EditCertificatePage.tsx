import React, { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { getErrorMessage } from '../utils/apiError';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import FieldHelp from '../components/shared/FieldHelp';
import { Link } from '../components/shared/Link';
import { DOCS_URL } from '../config/docs';
import { CertificateKind, CERTIFICATE_KIND_LABEL } from '../types';
import { useSafeNavigate } from '../hooks/useSafeNavigate';

interface Certificate {
  id: string;
  name: string;
  description?: string;
  certificate_pem: string;
  private_key_pem?: string;
  active: boolean;
  kind?: CertificateKind;
  expires_at?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  identity_did?: string;
}

const EditCertificatePage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;

  const [loading, setLoading] = useState(isEditMode);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState('');
  const [isModified, setIsModified] = useState(false);
  const [certificateData, setCertificateData] = useState<Certificate | null>(null);

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    certificate_data: '',
    private_key_pem: '',
    active: true,
    kind: 'server_leaf' as CertificateKind,
    expires_at: '',
    tags: [] as string[],
    useIdentity: false,
    identity_did: '',
  });

  const [tagInput, setTagInput] = useState('');
  const [existingTags, setExistingTags] = useState<string[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch certificate details if in edit mode
  useEffect(() => {
    if (isEditMode && id) {
      fetchCertificate(id);
    }
  }, [id, isEditMode]);

  // Load tags already used across certificates, to offer as click-to-add
  // suggestions (mirrors the same pattern on the Secret form).
  useEffect(() => {
    (async () => {
      try {
        const response = await apiClient.get('/certificates/');
        const list: { tags?: string[] }[] = response.data || [];
        const set = new Set<string>();
        list.forEach(c => (c.tags || []).forEach(t => set.add(t)));
        setExistingTags(Array.from(set).sort((a, b) => a.localeCompare(b)));
      } catch {
        // Non-fatal — suggestions just don't show.
      }
    })();
  }, []);

  // Keyboard shortcut for saving (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        if (!isSaving && (!isEditMode || isModified)) {
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSaving, isModified, isEditMode]);

  const fetchCertificate = async (certId: string) => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/certificates/${certId}`);
      const cert: Certificate = response.data;

      setCertificateData(cert);
      setFormData({
        name: cert.name,
        description: cert.description || '',
        certificate_data: cert.certificate_pem,
        private_key_pem: cert.private_key_pem || '',
        active: cert.active,
        kind: cert.kind ?? 'server_leaf',
        expires_at: cert.expires_at ? cert.expires_at.split('T')[0] : '', // Format for date input
        tags: cert.tags || [],
        useIdentity: !!cert.identity_did,
        identity_did: cert.identity_did || '',
      });

      setError('');
    } catch (err: any) {
      console.error('Failed to fetch certificate:', err);
      const errorMessage = getErrorMessage(err, 'Failed to load certificate');
      showToast('error', errorMessage);
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      setError('Certificate name is required');
      return;
    }

    if (!formData.certificate_data.trim()) {
      setError('Certificate data is required');
      return;
    }

    try {
      setIsSaving(true);
      setError('');

      const payload: any = {
        name: formData.name,
        description: formData.description || undefined,
        certificate_pem: formData.certificate_data,
        private_key_pem: formData.private_key_pem || undefined,
        active: formData.active,
        kind: formData.kind,
        expires_at: formData.expires_at || undefined,
        tags: formData.tags,
        identity_did:
          formData.useIdentity && formData.identity_did ? formData.identity_did : undefined,
      };

      if (isEditMode && id) {
        await apiClient.put(`/certificates/${id}`, payload);
        showToast('success', 'Certificate updated successfully');
        setIsModified(false);
      } else {
        await apiClient.post('/certificates', payload);
        showToast('success', 'Certificate created successfully');
        navigate('/secrets');
      }
    } catch (err: any) {
      console.error('Failed to save certificate:', err);
      const errorMessage = getErrorMessage(err, 'Failed to save certificate');
      showToast('error', errorMessage);
      setError(errorMessage);
    } finally {
      setIsSaving(false);
    }
  };

  const generateIdentity = async () => {
    try {
      console.log('[EditCertificatePage] Generating new identity...');
      const response = await apiClient.post('/vault/identity/generate', {
        purpose: `Certificate: ${formData.name || 'Unnamed'}`,
        item_type: 'cert',
      });
      const { did } = response.data;
      console.log('[EditCertificatePage] Generated DID:', did);
      setFormData({ ...formData, identity_did: did, useIdentity: true });
      setIsModified(true);
      showToast('success', 'Identity generated successfully');
    } catch (err: any) {
      console.error('Failed to generate identity:', err);
      showToast('error', getErrorMessage(err, 'Failed to generate identity'));
    }
  };
  const handleDelete = async () => {
    if (!id) return;

    try {
      await apiClient.delete(`/certificates/${id}`);
      showToast('success', 'Certificate deleted successfully');
      navigate('/secrets');
    } catch (err: any) {
      console.error('Failed to delete certificate:', err);
      const errorMessage = getErrorMessage(err, 'Failed to delete certificate');
      showToast('error', errorMessage);
    }
  };

  const handleInputChange = (field: string, value: any) => {
    // Validate certificate data
    if (field === 'certificate_data' && typeof value === 'string') {
      const validation = validateCertificateData(value);
      if (!validation.valid) {
        showToast('error', validation.error || 'Invalid certificate format');
        return; // Don't update if validation fails
      }
    }

    setFormData(prev => ({ ...prev, [field]: value }));
    setIsModified(true);
  };

  const addTag = (tag: string) => {
    const t = tag.trim();
    if (t && !formData.tags.includes(t)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, t],
      }));
      setIsModified(true);
    }
  };

  const handleAddTag = () => {
    const tag = tagInput.trim();
    if (tag && !formData.tags.includes(tag)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tag],
      }));
      setTagInput('');
      setIsModified(true);
    }
  };

  const validateCertificateData = (data: string): { valid: boolean; error?: string } => {
    const trimmed = data.trim();

    if (!trimmed) {
      return { valid: true }; // Allow empty for clearing
    }

    // Check if it contains private key
    const privateKeyMarkers = ['', 'RSA ', 'EC '].map(kind => `-----BEGIN ${kind}PRIVATE KEY-----`);
    if (privateKeyMarkers.some(marker => trimmed.includes(marker))) {
      return {
        valid: false,
        error:
          'This appears to be a private key. Please paste the certificate, not the private key!',
      };
    }

    // Check if it starts and ends with certificate markers
    if (!trimmed.startsWith('-----BEGIN CERTIFICATE-----')) {
      return {
        valid: false,
        error: 'Certificate must start with "-----BEGIN CERTIFICATE-----"',
      };
    }

    if (!trimmed.endsWith('-----END CERTIFICATE-----')) {
      return {
        valid: false,
        error: 'Certificate must end with "-----END CERTIFICATE-----"',
      };
    }

    return { valid: true };
  };

  const handleFileUpload = async (file: File) => {
    try {
      const text = await file.text();

      const validation = validateCertificateData(text);
      if (!validation.valid) {
        showToast('error', validation.error || 'Invalid certificate format');
        return;
      }

      handleInputChange('certificate_data', text);
      showToast('success', `File "${file.name}" loaded successfully`);
    } catch (err) {
      console.error('Failed to read file:', err);
      showToast('error', 'Failed to read file');
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileUpload(file);
    }
    // Reset input so same file can be selected again
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileUpload(file);
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(t => t !== tagToRemove),
    }));
    setIsModified(true);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddTag();
    }
  };

  if (isEditMode && loading) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: '400px' }}
        >
          <div className="spinner-border text-primary" role="status">
            <span className="sr-only">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/secrets')}
          disabled={isSaving}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-certificate me-2"></i>
            {isEditMode ? 'Edit Certificate' : 'Create Certificate'}
          </h1>
          <p className="text-muted mt-2">
            {isEditMode
              ? 'Update certificate details and data'
              : 'Add a new client certificate for mTLS authentication'}
          </p>
        </div>
        <div>
          <button
            className="btn btn-sm btn-primary me-2"
            onClick={handleSubmit}
            disabled={isSaving || (isEditMode && !isModified)}
          >
            {isSaving ? (
              <>
                <span
                  className="spinner-border spinner-border-sm me-1"
                  role="status"
                  aria-hidden="true"
                ></span>
                Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save me-1"></i>
                Save
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
      )}

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                {isEditMode ? 'Certificate Details' : 'New Certificate'}
              </h6>
            </div>
            <div className="card-body">
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="name">
                    Certificate Name <span className="text-danger">*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    id="name"
                    value={formData.name}
                    onChange={e => handleInputChange('name', e.target.value)}
                    placeholder="e.g., Client mTLS Certificate"
                    required
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="description">Description</label>
                  <input
                    className="form-control"
                    id="description"
                    value={formData.description}
                    onChange={e => handleInputChange('description', e.target.value)}
                    placeholder="What is this certificate used for?"
                  />
                  <small className="form-text text-muted">
                    Shown in the Certificates list to help you recognize this certificate later.
                  </small>
                </div>

                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label htmlFor="certificate_data" className="mb-0">
                      Certificate Data (PEM format) <span className="text-danger">*</span>
                    </label>
                    <FieldHelp
                      ariaLabel="About Certificate Data"
                      testId="field-help-certificate-data"
                    >
                      Base64 text between <code>-----BEGIN CERTIFICATE-----</code> and{' '}
                      <code>-----END CERTIFICATE-----</code> markers.
                    </FieldHelp>
                  </div>
                  <div
                    className={`position-relative ${isDragging ? 'border-primary' : ''}`}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                    style={{
                      border: isDragging ? '2px dashed var(--accent-blue)' : 'none',
                      borderRadius: '4px',
                      transition: 'border 0.2s',
                    }}
                  >
                    <textarea
                      className="form-control font-monospace"
                      id="certificate_data"
                      rows={12}
                      value={formData.certificate_data}
                      onChange={e => handleInputChange('certificate_data', e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                      required
                      style={{ fontFamily: 'monospace', fontSize: '0.85em' }}
                    />
                    {isDragging && (
                      <div
                        className="position-absolute d-flex align-items-center justify-content-center"
                        style={{
                          top: 0,
                          left: 0,
                          right: 0,
                          bottom: 0,
                          backgroundColor: 'rgba(74, 144, 226, 0.1)',
                          pointerEvents: 'none',
                          borderRadius: '4px',
                        }}
                      >
                        <div className="text-primary font-weight-bold">
                          <i className="fas fa-cloud-upload-alt fa-2x mb-2"></i>
                          <div>Drop certificate file here</div>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="d-flex justify-content-between align-items-center mt-2">
                    <small className="form-text text-muted mb-0">
                      PEM format, not the private key. Paste it below or drag &amp; drop a file.
                    </small>
                    <button
                      type="button"
                      className="btn btn-sm btn-outline-primary"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <i className="fas fa-upload me-1"></i>
                      Upload File
                    </button>
                  </div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".pem,.crt,.cer,.cert"
                    onChange={handleFileSelect}
                    style={{ display: 'none' }}
                  />
                </div>

                <div className="form-row">
                  <div className="mb-3 col-md-6">
                    <div className="field-label-with-help">
                      <label htmlFor="kind" className="mb-0">
                        Kind
                      </label>
                      <FieldHelp ariaLabel="About Kind" testId="field-help-certificate-kind">
                        mTLS (mutual TLS) means both sides of the connection, not just the caller,
                        present a certificate during the handshake.
                      </FieldHelp>
                    </div>
                    <select
                      className="form-control dropdown-styling"
                      id="kind"
                      value={formData.kind}
                      onChange={e => handleInputChange('kind', e.target.value as CertificateKind)}
                    >
                      <option value="server_leaf">{CERTIFICATE_KIND_LABEL.server_leaf}</option>
                      <option value="client_leaf">{CERTIFICATE_KIND_LABEL.client_leaf}</option>
                      <option value="ca">{CERTIFICATE_KIND_LABEL.ca}</option>
                    </select>
                    <small className="form-text text-muted">
                      <strong>Server leaf</strong>: TLS server cert presented by the gateway.{' '}
                      <strong>Client leaf</strong>: pinned client cert for mTLS source auth.{' '}
                      <strong>Certificate Authority</strong>: CA used to verify client chains.
                    </small>
                  </div>
                </div>

                <div className="form-row">
                  <div className="mb-3 col-md-6">
                    <div className="field-label-with-help">
                      <label htmlFor="expires_at" className="mb-0">
                        Expiration Date
                      </label>
                      <FieldHelp
                        ariaLabel="About Expiration Date"
                        testId="field-help-certificate-expiration"
                      >
                        Only enforced if this certificate also derives an agent's identity via
                        mTLS-based managed identity. After this date, those requests will fail. It
                        has no effect on whether the certificate itself is trusted for the mTLS
                        connection, which is governed by the certificate's own built-in validity
                        dates.
                      </FieldHelp>
                    </div>
                    <input
                      type="date"
                      className="form-control"
                      id="expires_at"
                      value={formData.expires_at}
                      onChange={e => handleInputChange('expires_at', e.target.value)}
                    />
                    <small className="form-text text-muted">Optional.</small>
                  </div>

                  <div className="mb-3 col-md-6">
                    <label htmlFor="active">Status</label>
                    <select
                      className="form-control dropdown-styling"
                      id="active"
                      value={formData.active ? 'active' : 'inactive'}
                      onChange={e => handleInputChange('active', e.target.value === 'active')}
                    >
                      <option value="active">Active</option>
                      <option value="inactive">Inactive</option>
                    </select>
                    <small className="form-text text-muted">
                      Only active certificates can be used
                    </small>
                  </div>
                </div>

                {/* Identity */}
                <div className="mb-3">
                  <div className="custom-control custom-switch mb-2">
                    <input
                      type="checkbox"
                      className="custom-control-input"
                      id="useIdentity"
                      checked={formData.useIdentity}
                      onChange={e => {
                        setFormData({ ...formData, useIdentity: e.target.checked });
                        setIsModified(true);
                      }}
                    />
                    <label className="custom-control-label font-weight-bold" htmlFor="useIdentity">
                      Use for Identity
                    </label>{' '}
                    <FieldHelp
                      ariaLabel="About Use for Identity"
                      testId="field-help-use-for-identity"
                    >
                      Turn this on to link this certificate to a DID identity the gateway manages,
                      useful when this certificate also needs to prove the surface's identity, not
                      just secure the connection.
                    </FieldHelp>
                  </div>
                  {formData.useIdentity && (
                    <>
                      <div className="field-label-with-help">
                        <label htmlFor="identity_did" className="font-weight-bold mb-0">
                          DID
                        </label>
                        <FieldHelp ariaLabel="About DID" testId="field-help-certificate-did">
                          A DID (Decentralized Identifier) is a portable ID the gateway can prove
                          ownership of.
                        </FieldHelp>
                      </div>
                      <div className="input-group">
                        <input
                          type="text"
                          className="form-control font-monospace"
                          id="identity_did"
                          value={formData.identity_did}
                          onChange={e => {
                            setFormData({ ...formData, identity_did: e.target.value });
                            setIsModified(true);
                          }}
                          placeholder="did:web:..."
                        />
                        <div className="input-group-append">
                          <button
                            type="button"
                            className="btn btn-outline-primary"
                            onClick={generateIdentity}
                            title="Generate new DID"
                          >
                            <i className="fas fa-magic"></i> Generate
                          </button>
                        </div>
                      </div>
                      <small className="form-text text-muted">
                        Import an existing DID or generate a new one that the Gateway will manage
                      </small>
                    </>
                  )}
                </div>
                <div className="mb-3">
                  <label htmlFor="tags">Tags</label>
                  <div className="input-group mb-2">
                    <input
                      type="text"
                      className="form-control"
                      id="tags"
                      value={tagInput}
                      onChange={e => setTagInput(e.target.value)}
                      onKeyDown={handleKeyDown}
                      placeholder="Add a tag and press Enter"
                    />
                    <div className="input-group-append">
                      <button
                        type="button"
                        className="btn btn-outline-secondary"
                        onClick={handleAddTag}
                      >
                        <i className="fas fa-plus"></i> Add
                      </button>
                    </div>
                  </div>
                  <small className="form-text text-muted d-block mb-2">
                    Use tags to filter and organize certificates, for example by environment or
                    service.
                  </small>
                  {existingTags.filter(t => !formData.tags.includes(t)).length > 0 && (
                    <div className="mb-2">
                      <small className="text-muted d-block mb-1">
                        <i className="fas fa-tags me-1"></i>Existing tags, click to add.
                      </small>
                      {existingTags
                        .filter(t => !formData.tags.includes(t))
                        .map(tag => (
                          <button
                            key={tag}
                            type="button"
                            className="badge bg-transparent border text-muted me-2 mb-2"
                            style={{ cursor: 'pointer', fontSize: '0.9em' }}
                            title="Already used on other certificates"
                            onClick={() => addTag(tag)}
                          >
                            <i className="fas fa-plus fa-xs me-1"></i>
                            {tag}
                          </button>
                        ))}
                    </div>
                  )}
                  {formData.tags.length > 0 && (
                    <div className="mt-2">
                      {formData.tags.map(tag => (
                        <span
                          key={tag}
                          className="badge text-bg-primary me-2 mb-2"
                          style={{ fontSize: '0.9em' }}
                        >
                          {tag}
                          <button
                            type="button"
                            className="btn btn-link btn-sm text-white ms-1 p-0"
                            onClick={() => handleRemoveTag(tag)}
                            style={{ textDecoration: 'none' }}
                          >
                            <i className="fas fa-times"></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <hr />

                <div className="d-flex justify-content-between align-items-center">
                  {isEditMode && (
                    <DeleteButton
                      onDelete={handleDelete}
                      title="Delete this certificate"
                      disabled={isSaving}
                      variant="danger"
                    >
                      Delete Certificate
                    </DeleteButton>
                  )}
                  <div className={!isEditMode ? 'ms-auto' : ''}>
                    <button
                      type="submit"
                      className="btn btn-sm btn-primary"
                      disabled={isSaving || (isEditMode && !isModified)}
                    >
                      {isSaving ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                            aria-hidden="true"
                          ></span>
                          Saving...
                        </>
                      ) : (
                        <>
                          <i className="fas fa-save me-1"></i>
                          {isEditMode ? 'Save Changes' : 'Create Certificate'}
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          {isEditMode && (
            <div className="card shadow mb-4">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-clock me-2"></i>
                  Metadata
                </h6>
              </div>
              <div className="card-body">
                <div className="mb-2">
                  <strong className="text-muted">Created</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {certificateData?.created_at
                      ? formatDateTime(certificateData.created_at, true)
                      : 'N/A'}
                  </div>
                </div>
                <div>
                  <strong className="text-muted">Last Updated</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {certificateData?.updated_at
                      ? formatDateTime(certificateData.updated_at, true)
                      : 'N/A'}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="card shadow mb-4 border-warning">
            <div className="card-body">
              <h6 className="font-weight-bold text-warning">
                <i className="fas fa-shield-alt me-2"></i>
                Security Notice
              </h6>
              <p className="mb-0" style={{ fontSize: '0.85em' }}>
                Client certificates are used for mTLS (mutual TLS) authentication. Ensure
                certificates are from trusted sources and properly secured.
              </p>
            </div>
          </div>

          <div className="card shadow mb-4 border-left-info">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-terminal me-2"></i>
                Creating mTLS Certificates
              </h6>
            </div>
            <div className="card-body">
              <h6 className="font-weight-bold">Generate a Private Key and Certificate</h6>
              <p style={{ fontSize: '0.9em' }}>
                Use OpenSSL to create a new private key and self-signed certificate:
              </p>

              <div
                className="bg-light p-3 mb-3"
                style={{ borderRadius: '4px', fontSize: '0.85em', fontFamily: 'monospace' }}
              >
                <div className="mb-2"># Generate a private key (2048-bit RSA)</div>
                <div className="mb-3">openssl genrsa -out client-key.pem 2048</div>

                <div className="mb-2"># Create a certificate signing request (CSR)</div>
                <div className="mb-3">openssl req -new -key client-key.pem -out client-csr.pem</div>

                <div className="mb-2">
                  # Generate a self-signed certificate (valid for 365 days)
                </div>
                <div>
                  openssl x509 -req -in client-csr.pem -signkey client-key.pem -out client-cert.pem
                  -days 365
                </div>
              </div>

              <h6 className="font-weight-bold">One-Step Certificate Generation</h6>
              <p style={{ fontSize: '0.9em' }}>
                Alternatively, generate both key and certificate in a single command:
              </p>

              <div
                className="bg-light p-3 mb-3"
                style={{ borderRadius: '4px', fontSize: '0.85em', fontFamily: 'monospace' }}
              >
                openssl req -x509 -newkey rsa:2048 -keyout client-key.pem -out client-cert.pem -days
                365 -nodes
              </div>

              <div className="alert alert-warning" style={{ fontSize: '0.85em' }}>
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Note:</strong> The <code>-nodes</code> flag creates an unencrypted private
                key. For production use, omit this flag and protect the key with a passphrase.
              </div>

              <h6 className="font-weight-bold mt-3">Using the Certificate</h6>
              <p style={{ fontSize: '0.9em' }}>
                After generation, paste the contents of <code>client-cert.pem</code> into the
                certificate field above. Keep <code>client-key.pem</code> secure and private.
              </p>
            </div>
          </div>

          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2"></i>
                Certificate Information
              </h6>
            </div>
            <div className="card-body">
              <h6 className="font-weight-bold">What are Client Certificates?</h6>
              <p style={{ fontSize: '0.9em' }}>
                Client certificates are used for mTLS (mutual TLS) authentication, allowing secure
                verification of client identity.
              </p>

              <h6 className="font-weight-bold mt-3">Certificate Format</h6>
              <p style={{ fontSize: '0.9em' }}>
                Certificates should be in PEM format, which is a Base64 encoded DER certificate
                surrounded by BEGIN/END markers.
              </p>

              <h6 className="font-weight-bold mt-3">Tags</h6>
              <p style={{ fontSize: '0.9em' }}>
                Use tags to organize certificates by environment, service, or purpose.
              </p>

              <Link href={DOCS_URL.secrets} external>
                Learn more about Certificates
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EditCertificatePage;
