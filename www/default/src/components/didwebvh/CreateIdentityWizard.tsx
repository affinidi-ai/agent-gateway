import React, { useState } from 'react';
import { Alert, Button, Form, Modal, ProgressBar, Spinner } from 'react-bootstrap';
import { CreateIdentityRequest } from '../../types';
import { apiClient } from '../../api';

interface CreateIdentityWizardProps {
  show: boolean;
  onHide: () => void;
  onSuccess: (identity: any) => void;
}

const CreateIdentityWizard: React.FC<CreateIdentityWizardProps> = ({ show, onHide, onSuccess }) => {
  const [step, setStep] = useState(1);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [formData, setFormData] = useState<CreateIdentityRequest>({
    name: '',
    did_path: '',
    description: '',
    metadata: {
      llm_provider: '',
      llm_model: '',
      llm_version: '',
      deployment_env: '',
      owner: '',
      team: '',
      capabilities: [],
    },
    generate_keys: true,
  });

  const [pathPreview, setPathPreview] = useState('');

  React.useEffect(() => {
    const didPath = formData.did_path.trim().replace(/^\/+|\/+$/g, '');
    if (didPath) {
      setPathPreview(`did:webvh:${window.location.host}:${didPath.replace(/\//g, ':')}`);
    } else {
      setPathPreview('');
    }
  }, [formData.did_path]);

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleMetadataChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      metadata: {
        ...prev.metadata,
        [field]: value,
      },
    }));
  };

  const handleNext = () => {
    if (step < 3) {
      setStep(step + 1);
      setError(null);
    }
  };

  const handlePrevious = () => {
    if (step > 1) {
      setStep(step - 1);
      setError(null);
    }
  };

  const handleSubmit = async () => {
    setCreating(true);
    setError(null);

    try {
      const identity = await apiClient.createDidWebVhIdentity(formData);
      onSuccess(identity);
      handleClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create identity');
      setCreating(false);
    }
  };

  const handleClose = () => {
    setStep(1);
    setFormData({
      name: '',
      did_path: '',
      description: '',
      metadata: {
        llm_provider: '',
        llm_model: '',
        llm_version: '',
        deployment_env: '',
        owner: '',
        team: '',
        capabilities: [],
      },
      generate_keys: true,
    });
    setError(null);
    setCreating(false);
    onHide();
  };

  const isStep1Valid = () => {
    return formData.name.trim() !== '' && formData.did_path.trim() !== '';
  };

  const isStep2Valid = () => {
    // LLM fields are optional — DNA is auto-generated from SCID at creation time
    return true;
  };

  const getProgressPercentage = () => {
    return (step / 3) * 100;
  };

  return (
    <Modal
      show={show}
      onHide={creating ? undefined : handleClose}
      size="lg"
      backdrop={creating ? 'static' : true}
    >
      <Modal.Header closeButton={!creating}>
        <Modal.Title>
          <i className="fas fa-plus-circle"></i> Create New DID:webvh Identity
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {/* Progress Bar */}
        <div className="mb-4">
          <div className="d-flex justify-content-between mb-2">
            <span className={`small ${step >= 1 ? 'text-primary font-weight-bold' : 'text-muted'}`}>
              1. Basic Info
            </span>
            <span className={`small ${step >= 2 ? 'text-primary font-weight-bold' : 'text-muted'}`}>
              2. Configuration
            </span>
            <span className={`small ${step >= 3 ? 'text-primary font-weight-bold' : 'text-muted'}`}>
              3. Metadata
            </span>
          </div>
          <ProgressBar now={getProgressPercentage()} variant="primary" />
        </div>

        {error && (
          <Alert variant="danger" dismissible onClose={() => setError(null)}>
            <i className="fas fa-exclamation-triangle"></i> {error}
          </Alert>
        )}

        {/* Step 1: Basic Information */}
        {step === 1 && (
          <div>
            <h5 className="mb-3">Step 1: Basic Information</h5>

            <Form.Group className="mb-3" controlId="identity-name">
              <Form.Label>
                Identity Name <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g., GPT-4 Production Agent"
                value={formData.name}
                onChange={e => handleInputChange('name', e.target.value)}
                disabled={creating}
              />
              <Form.Text className="text-muted">A friendly name for this identity</Form.Text>
            </Form.Group>

            <Form.Group className="mb-3" controlId="did-path">
              <Form.Label>
                DID Path <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g., agents/gpt4-prod"
                value={formData.did_path}
                onChange={e => handleInputChange('did_path', e.target.value)}
                disabled={creating}
              />
              <Form.Text className="text-muted">
                Path component for the DID (no leading/trailing slashes)
              </Form.Text>
              {pathPreview && (
                <div className="mt-2 p-2 bg-light border rounded">
                  <small>
                    <strong>Preview:</strong> <code>{pathPreview}</code>
                  </small>
                </div>
              )}
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                placeholder="Brief description of this agent identity..."
                value={formData.description}
                onChange={e => handleInputChange('description', e.target.value)}
                disabled={creating}
              />
            </Form.Group>
          </div>
        )}

        {/* Step 2: Agent Configuration */}
        {step === 2 && (
          <div>
            <h5 className="mb-3">Step 2: Agent Configuration</h5>

            <div className="row">
              <div className="col-md-4">
                <Form.Group className="mb-3" controlId="llm-provider">
                  <Form.Label>LLM Provider</Form.Label>
                  <Form.Select
                    className="dropdown-styling"
                    value={formData.metadata?.llm_provider || ''}
                    onChange={e => handleMetadataChange('llm_provider', e.target.value)}
                    disabled={creating}
                  >
                    <option value="">Select provider...</option>
                    <option value="OpenAI">OpenAI</option>
                    <option value="Anthropic">Anthropic</option>
                    <option value="Google">Google</option>
                    <option value="Meta">Meta</option>
                    <option value="Cohere">Cohere</option>
                    <option value="Other">Other</option>
                  </Form.Select>
                </Form.Group>
              </div>

              <div className="col-md-5">
                <Form.Group className="mb-3" controlId="llm-model">
                  <Form.Label>Model</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="e.g., GPT-4-turbo"
                    value={formData.metadata?.llm_model || ''}
                    onChange={e => handleMetadataChange('llm_model', e.target.value)}
                    disabled={creating}
                  />
                </Form.Group>
              </div>

              <div className="col-md-3">
                <Form.Group className="mb-3">
                  <Form.Label>Version</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="e.g., 1.0"
                    value={formData.metadata?.llm_version || ''}
                    onChange={e => handleMetadataChange('llm_version', e.target.value)}
                    disabled={creating}
                  />
                </Form.Group>
              </div>
            </div>

            <Form.Group className="mb-3">
              <Form.Label>Deployment Environment</Form.Label>
              <Form.Select
                className="dropdown-styling"
                value={formData.metadata?.deployment_env || ''}
                onChange={e => handleMetadataChange('deployment_env', e.target.value)}
                disabled={creating}
              >
                <option value="">Select environment...</option>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
                <option value="testing">Testing</option>
              </Form.Select>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Attestation Options</Form.Label>
              <div>
                <Form.Check
                  id="chk-has-tee"
                  type="checkbox"
                  label="TEE (Trusted Execution Environment)"
                  checked={formData.metadata?.has_tee || false}
                  onChange={e => handleMetadataChange('has_tee', e.target.checked)}
                  disabled={creating}
                />
                <Form.Check
                  id="chk-has-cloud-attestation"
                  type="checkbox"
                  label="Cloud Attestation"
                  checked={formData.metadata?.has_cloud_attestation || false}
                  onChange={e => handleMetadataChange('has_cloud_attestation', e.target.checked)}
                  disabled={creating}
                />
              </div>
            </Form.Group>

            {formData.metadata?.has_cloud_attestation && (
              <Form.Group className="mb-3">
                <Form.Label>Cloud Provider</Form.Label>
                <Form.Select
                  className="dropdown-styling"
                  value={formData.metadata?.cloud_provider || ''}
                  onChange={e => handleMetadataChange('cloud_provider', e.target.value)}
                  disabled={creating}
                >
                  <option value="">Select provider...</option>
                  <option value="AWS">AWS</option>
                  <option value="GCP">Google Cloud Platform</option>
                  <option value="Azure">Microsoft Azure</option>
                </Form.Select>
              </Form.Group>
            )}

            <Form.Group className="mb-3">
              <Form.Label>Capabilities</Form.Label>
              <div>
                <Form.Check
                  type="checkbox"
                  label="Reasoning"
                  id="cap-reasoning"
                  checked={(formData.metadata?.capabilities || []).includes('Reasoning')}
                  onChange={e => {
                    const caps = formData.metadata?.capabilities || [];
                    handleMetadataChange(
                      'capabilities',
                      e.target.checked
                        ? [...caps, 'Reasoning']
                        : caps.filter(c => c !== 'Reasoning')
                    );
                  }}
                  disabled={creating}
                />
                <Form.Check
                  type="checkbox"
                  label="Code Generation"
                  id="cap-code"
                  checked={(formData.metadata?.capabilities || []).includes('Code')}
                  onChange={e => {
                    const caps = formData.metadata?.capabilities || [];
                    handleMetadataChange(
                      'capabilities',
                      e.target.checked ? [...caps, 'Code'] : caps.filter(c => c !== 'Code')
                    );
                  }}
                  disabled={creating}
                />
                <Form.Check
                  type="checkbox"
                  label="Vision"
                  id="cap-vision"
                  checked={(formData.metadata?.capabilities || []).includes('Vision')}
                  onChange={e => {
                    const caps = formData.metadata?.capabilities || [];
                    handleMetadataChange(
                      'capabilities',
                      e.target.checked ? [...caps, 'Vision'] : caps.filter(c => c !== 'Vision')
                    );
                  }}
                  disabled={creating}
                />
                <Form.Check
                  type="checkbox"
                  label="Audio"
                  id="cap-audio"
                  checked={(formData.metadata?.capabilities || []).includes('Audio')}
                  onChange={e => {
                    const caps = formData.metadata?.capabilities || [];
                    handleMetadataChange(
                      'capabilities',
                      e.target.checked ? [...caps, 'Audio'] : caps.filter(c => c !== 'Audio')
                    );
                  }}
                  disabled={creating}
                />
              </div>
            </Form.Group>
          </div>
        )}

        {/* Step 3: Metadata & Policies */}
        {step === 3 && (
          <div>
            <h5 className="mb-3">Step 3: Metadata & Policies</h5>

            <div className="row">
              <div className="col-md-6">
                <Form.Group className="mb-3">
                  <Form.Label>Owner Email</Form.Label>
                  <Form.Control
                    type="email"
                    placeholder="owner@example.com"
                    value={formData.metadata?.owner || ''}
                    onChange={e => handleMetadataChange('owner', e.target.value)}
                    disabled={creating}
                  />
                </Form.Group>
              </div>

              <div className="col-md-6">
                <Form.Group className="mb-3">
                  <Form.Label>Team</Form.Label>
                  <Form.Control
                    type="text"
                    placeholder="e.g., AI Engineering"
                    value={formData.metadata?.team || ''}
                    onChange={e => handleMetadataChange('team', e.target.value)}
                    disabled={creating}
                  />
                </Form.Group>
              </div>
            </div>

            <Form.Group className="mb-3">
              <Form.Label>Cost Center</Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g., CC-42"
                value={formData.metadata?.cost_center || ''}
                onChange={e => handleMetadataChange('cost_center', e.target.value)}
                disabled={creating}
              />
            </Form.Group>

            <hr />

            <Form.Group className="mb-3">
              <Form.Check
                id="chk-generate-keys"
                type="checkbox"
                label="Generate new key pair automatically"
                checked={formData.generate_keys || false}
                onChange={e => handleInputChange('generate_keys', e.target.checked)}
                disabled={creating}
              />
              <Form.Text className="text-muted">
                A new signing key will be generated for this identity
              </Form.Text>
            </Form.Group>

            <Alert variant="info" className="mt-4">
              <h6>
                <i className="fas fa-info-circle"></i> Review Your Configuration
              </h6>
              <ul className="mb-0 small">
                <li>
                  <strong>Name:</strong> {formData.name}
                </li>
                <li>
                  <strong>DID:</strong> <code>{pathPreview}</code>
                </li>
                <li>
                  <strong>Provider:</strong> {formData.metadata?.llm_provider || 'auto-detected'}{' '}
                  &mdash; {formData.metadata?.llm_model || 'tgw-managed'}
                </li>
                {formData.metadata?.deployment_env && (
                  <li>
                    <strong>Environment:</strong> {formData.metadata.deployment_env}
                  </li>
                )}
                {formData.metadata?.owner && (
                  <li>
                    <strong>Owner:</strong> {formData.metadata.owner}
                  </li>
                )}
              </ul>
            </Alert>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleClose} disabled={creating}>
          Cancel
        </Button>
        {step > 1 && (
          <Button variant="outline-secondary" onClick={handlePrevious} disabled={creating}>
            <i className="fas fa-arrow-left"></i> Previous
          </Button>
        )}
        {step < 3 && (
          <Button
            variant="primary"
            onClick={handleNext}
            disabled={
              creating || (step === 1 && !isStep1Valid()) || (step === 2 && !isStep2Valid())
            }
          >
            Next <i className="fas fa-arrow-right"></i>
          </Button>
        )}
        {step === 3 && (
          <Button variant="success" onClick={handleSubmit} disabled={creating}>
            {creating ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Creating...
              </>
            ) : (
              <>
                <i className="fas fa-check"></i> Create Identity
              </>
            )}
          </Button>
        )}
      </Modal.Footer>
    </Modal>
  );
};

export default CreateIdentityWizard;
