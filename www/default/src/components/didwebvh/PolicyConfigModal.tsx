import React, { useEffect, useState } from 'react';
import { Accordion, Alert, Badge, Button, Card, Form, Modal } from 'react-bootstrap';
import { apiClient } from '../../api';
import FieldHelp from '../shared/FieldHelp';

interface PolicyTemplate {
  name: string;
  description: string;
  config: PolicyConfig;
}

interface PolicyConfig {
  minTrustScore: number;
  components: {
    genesis: { threshold: number; required: boolean; weight: number };
    behavioral: { threshold: number; required: boolean; weight: number };
    operational: {
      threshold: number;
      required: boolean;
      weight: number;
      requireTEE: boolean;
      requireCloud: boolean;
    };
    attestation: { threshold: number; required: boolean; weight: number; minCount: number };
    history: { threshold: number; required: boolean; weight: number };
  };
  advancedPolicy?: string;
}

interface PolicyConfigModalProps {
  show: boolean;
  onHide: () => void;
  identity: any;
  onSave: (config: PolicyConfig) => void;
}

const TEMPLATES: PolicyTemplate[] = [
  {
    name: 'Standard',
    description: 'Balanced security for most use cases',
    config: {
      minTrustScore: 0.7,
      components: {
        genesis: { threshold: 0.75, required: false, weight: 0.25 },
        behavioral: { threshold: 0.7, required: true, weight: 0.25 },
        operational: {
          threshold: 0.7,
          required: false,
          weight: 0.2,
          requireTEE: false,
          requireCloud: false,
        },
        attestation: { threshold: 0.6, required: false, weight: 0.2, minCount: 50 },
        history: { threshold: 0.6, required: false, weight: 0.1 },
      },
    },
  },
  {
    name: 'High Security',
    description: 'Maximum security with TEE required',
    config: {
      minTrustScore: 0.85,
      components: {
        genesis: { threshold: 0.85, required: true, weight: 0.25 },
        behavioral: { threshold: 0.85, required: true, weight: 0.25 },
        operational: {
          threshold: 0.85,
          required: true,
          weight: 0.2,
          requireTEE: true,
          requireCloud: false,
        },
        attestation: { threshold: 0.8, required: true, weight: 0.2, minCount: 100 },
        history: { threshold: 0.75, required: false, weight: 0.1 },
      },
    },
  },
  {
    name: 'Development',
    description: 'Relaxed settings for testing',
    config: {
      minTrustScore: 0.5,
      components: {
        genesis: { threshold: 0.5, required: false, weight: 0.25 },
        behavioral: { threshold: 0.5, required: false, weight: 0.25 },
        operational: {
          threshold: 0.5,
          required: false,
          weight: 0.2,
          requireTEE: false,
          requireCloud: false,
        },
        attestation: { threshold: 0.4, required: false, weight: 0.2, minCount: 10 },
        history: { threshold: 0.4, required: false, weight: 0.1 },
      },
    },
  },
  {
    name: 'Production',
    description: 'All components validated and verified',
    config: {
      minTrustScore: 0.8,
      components: {
        genesis: { threshold: 0.8, required: true, weight: 0.25 },
        behavioral: { threshold: 0.8, required: true, weight: 0.25 },
        operational: {
          threshold: 0.75,
          required: true,
          weight: 0.2,
          requireTEE: false,
          requireCloud: true,
        },
        attestation: { threshold: 0.75, required: true, weight: 0.2, minCount: 75 },
        history: { threshold: 0.7, required: false, weight: 0.1 },
      },
    },
  },
];

const DEFAULT_REGO_POLICY = `package authz

default allow = false

# Require minimum trust score
allow {
    input.trust_score.overall_score >= 0.7
    input.trust_score.components.genesis >= 0.75
    input.trust_score.components.behavioral >= 0.7
}

# Require TEE for sensitive operations
allow {
    input.trust_score.has_tee == true
    input.mcp.tool_name == "sensitive_operation"
}`;

export const PolicyConfigModal: React.FC<PolicyConfigModalProps> = ({
  show,
  onHide,
  identity,
  onSave,
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState<string>('Standard');
  const [config, setConfig] = useState<PolicyConfig>(TEMPLATES[0].config);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [saving, setSaving] = useState(false);
  const [modified, setModified] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Fetch existing policy from backend when modal opens
  useEffect(() => {
    const fetchExistingPolicy = async () => {
      // Get identity ID (prefer 'id' from backend, fallback to 'uuid')
      const identityId = identity?.id || identity?.uuid;

      if (!show || !identityId) {
        console.log('[PolicyConfigModal] Modal not shown or no identity ID');
        return;
      }

      console.log('[PolicyConfigModal] Fetching policy for identity:', identityId);
      setLoading(true);
      setLoadError(null);

      try {
        const response = await apiClient.fetch(`/api/v1/identities/${identityId}/policy`);
        console.log('[PolicyConfigModal] Policy fetch response status:', response.status);

        if (response.ok) {
          const data = await response.json();
          console.log('[PolicyConfigModal] Loaded policy config:', data);
          if (data.config) {
            setConfig(data.config);
            setSelectedTemplate('Custom');
            setModified(false);
          }
        } else if (response.status === 404) {
          // No existing policy, use default
          console.log('[PolicyConfigModal] No existing policy, using Standard template');
          setConfig(TEMPLATES[0].config);
          setSelectedTemplate('Standard');
          setModified(false);
        } else {
          console.warn('[PolicyConfigModal] Failed to load policy:', response.status);
          setLoadError(`Failed to load policy: ${response.statusText}`);
          // Fallback to local data if available
          if (identity?.policy_config) {
            setConfig(identity.policy_config);
            setSelectedTemplate('Custom');
          } else {
            setConfig(TEMPLATES[0].config);
            setSelectedTemplate('Standard');
          }
        }
      } catch (error) {
        console.error('[PolicyConfigModal] Error fetching policy:', error);
        setLoadError('Network error loading policy');
        // Fallback to local data
        if (identity?.policy_config) {
          setConfig(identity.policy_config);
          setSelectedTemplate('Custom');
        } else {
          setConfig(TEMPLATES[0].config);
          setSelectedTemplate('Standard');
        }
      } finally {
        setLoading(false);
        setTestResult(null);
      }
    };

    fetchExistingPolicy();
  }, [show, identity]);

  const applyTemplate = (templateName: string) => {
    const template = TEMPLATES.find(t => t.name === templateName);
    if (template) {
      setConfig({ ...template.config });
      setSelectedTemplate(templateName);
      setModified(true);
      setTestResult(null);
    }
  };

  const updateConfig = (path: string[], value: any) => {
    const newConfig = { ...config };
    let current: any = newConfig;
    for (let i = 0; i < path.length - 1; i++) {
      current = current[path[i]];
    }
    current[path[path.length - 1]] = value;
    setConfig(newConfig);
    setModified(true);
    setTestResult(null);
    if (selectedTemplate !== 'Custom') {
      setSelectedTemplate('Custom');
    }
  };

  const testPolicy = (): { allowed: boolean; checks: any[] } => {
    console.log('[PolicyConfigModal] testPolicy called for identity:', identity?.did);
    console.log('[PolicyConfigModal] Current config:', JSON.stringify(config, null, 2));

    // Validate policy configuration locally
    const result = {
      allowed: true,
      checks: [
        {
          name: 'Overall score',
          value: identity?.trust_score?.overall_score || 0,
          threshold: config.minTrustScore,
          passed: (identity?.trust_score?.overall_score || 0) >= config.minTrustScore,
        },
        {
          name: 'Genesis score',
          value: identity?.trust_score?.components?.genesis || 0,
          threshold: config.components.genesis.threshold,
          passed:
            (identity?.trust_score?.components?.genesis || 0) >=
            config.components.genesis.threshold,
        },
        {
          name: 'Behavioral score',
          value: identity?.trust_score?.components?.behavioral || 0,
          threshold: config.components.behavioral.threshold,
          passed:
            (identity?.trust_score?.components?.behavioral || 0) >=
            config.components.behavioral.threshold,
        },
        {
          name: 'Operational score',
          value: identity?.trust_score?.components?.operational || 0,
          threshold: config.components.operational.threshold,
          passed:
            (identity?.trust_score?.components?.operational || 0) >=
            config.components.operational.threshold,
        },
      ],
    };
    result.allowed = result.checks.every(c => c.passed);

    console.log(
      '[PolicyConfigModal] Test result:',
      result.allowed ? 'ALLOWED' : 'DENIED',
      'checks:',
      result.checks.length
    );
    setTestResult(result);
    return result;
  };

  const handleSave = async () => {
    console.log('[PolicyConfigModal] handleSave called');
    setSaving(true);
    try {
      await onSave(config);
      console.log('[PolicyConfigModal] Save successful');
      setModified(false);
      onHide();
    } catch (error) {
      console.error('[PolicyConfigModal] Failed to save policy config:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleTestAndSave = async () => {
    console.log('[PolicyConfigModal] handleTestAndSave called');
    // Run test synchronously and get result directly (not from stale state)
    const result = testPolicy();

    // Show test results briefly before saving
    if (result.allowed) {
      console.log('[PolicyConfigModal] Test passed, proceeding to save');
      // Small delay to show test results visually
      await new Promise(resolve => setTimeout(resolve, 500));
      await handleSave();
    } else {
      console.log(
        '[PolicyConfigModal] Test failed, not saving. Failed checks:',
        result.checks
          .filter((c: any) => !c.passed)
          .map((c: any) => c.name)
          .join(', ')
      );
    }
  };

  return (
    <Modal show={show} onHide={onHide} size="lg" backdrop="static">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="fas fa-shield-alt text-primary me-2"></i>
          Policy Configuration
          {identity?.name && <small className="text-muted ms-2">({identity.name})</small>}
        </Modal.Title>
      </Modal.Header>

      <Modal.Body style={{ maxHeight: '70vh', overflowY: 'auto' }}>
        {/* Loading indicator */}
        {loading && (
          <div className="text-center py-4">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
            <p className="mt-2 text-muted">Loading policy configuration...</p>
          </div>
        )}

        {/* Error alert */}
        {loadError && (
          <Alert variant="warning" className="mb-3">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {loadError}
          </Alert>
        )}

        {/* Main content - only show when not loading */}
        {!loading && (
          <>
            {/* Quick Template Selection */}
            <div className="mb-4">
              <h6 className="mb-3 d-flex align-items-center">
                <i className="fas fa-layer-group me-2"></i>
                Policy Templates
                <small className="text-muted ms-2">Click to apply instantly</small>
                <FieldHelp ariaLabel="About Policy Templates" testId="field-help-policy-templates">
                  Start from a preset, then adjust anything below.
                </FieldHelp>
              </h6>
              <small className="text-muted d-block mb-2">
                Switching presets overwrites your current settings.
              </small>
              <div className="d-flex gap-2 flex-wrap">
                {TEMPLATES.map(template => (
                  <Button
                    key={template.name}
                    variant={selectedTemplate === template.name ? 'primary' : 'outline-primary'}
                    size="sm"
                    onClick={() => applyTemplate(template.name)}
                    title={template.description}
                  >
                    {template.name}
                    {selectedTemplate === template.name && <i className="fas fa-check ms-2"></i>}
                  </Button>
                ))}
                {selectedTemplate === 'Custom' && (
                  <Badge bg="info" className="d-flex align-items-center">
                    <i className="fas fa-pencil-alt me-1"></i> Custom
                  </Badge>
                )}
              </div>
              <small className="text-muted d-block mt-2">
                {TEMPLATES.find(t => t.name === selectedTemplate)?.description ||
                  'Modified from template'}
              </small>
            </div>

            {/* Overall Trust Score */}
            <div className="mb-4">
              <h6 className="mb-3 d-flex align-items-center">
                <i className="fas fa-chart-line me-2"></i>
                Overall Minimum Trust Score
                <FieldHelp
                  ariaLabel="About Overall Minimum Trust Score"
                  testId="field-help-min-trust-score"
                >
                  The lowest overall Trust Score (a 0–100% summary of the five signals below) this
                  identity must have to pass this policy.
                </FieldHelp>
              </h6>
              <div className="d-flex align-items-center gap-3">
                <input
                  type="range"
                  className="form-range flex-grow-1"
                  min="0"
                  max="100"
                  step="5"
                  value={config.minTrustScore * 100}
                  onChange={e => updateConfig(['minTrustScore'], parseInt(e.target.value) / 100)}
                />
                <Badge
                  bg={
                    config.minTrustScore >= 0.8
                      ? 'success'
                      : config.minTrustScore >= 0.6
                        ? 'warning'
                        : 'danger'
                  }
                  style={{ minWidth: '60px' }}
                >
                  {(config.minTrustScore * 100).toFixed(0)}%
                </Badge>
              </div>
            </div>

            {/* Component Requirements - Compact View */}
            <div className="mb-4">
              <h6 className="mb-3">
                <i className="fas fa-puzzle-piece me-2"></i>
                Component Thresholds
              </h6>

              {/* Genesis */}
              <Card className="mb-2 border-0 bg-light">
                <Card.Body className="p-3">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <div className="d-flex align-items-center">
                      <strong>Genesis Score</strong>
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        weight: {config.components.genesis.weight}
                      </Badge>
                      <FieldHelp
                        ariaLabel="About Genesis Score weight"
                        testId="field-help-genesis-weight"
                      >
                        How much this component counts toward the Overall Score above. Set by the
                        selected template, not directly editable here.
                      </FieldHelp>
                    </div>
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="Required"
                        checked={config.components.genesis.required}
                        onChange={e =>
                          updateConfig(['components', 'genesis', 'required'], e.target.checked)
                        }
                      />
                      <FieldHelp
                        ariaLabel="About Genesis Score Required"
                        testId="field-help-genesis-required"
                      >
                        Test Policy checks the Genesis threshold every time, independent of this
                        setting. A low score here always fails the policy, regardless of the overall
                        score.
                      </FieldHelp>
                    </div>
                  </div>
                  <div className="d-flex align-items-center gap-2">
                    <input
                      type="range"
                      className="form-range flex-grow-1"
                      min="0"
                      max="100"
                      step="5"
                      value={config.components.genesis.threshold * 100}
                      onChange={e =>
                        updateConfig(
                          ['components', 'genesis', 'threshold'],
                          parseInt(e.target.value) / 100
                        )
                      }
                    />
                    <Badge bg="info" style={{ minWidth: '50px' }}>
                      {(config.components.genesis.threshold * 100).toFixed(0)}%
                    </Badge>
                    <FieldHelp
                      ariaLabel="About Genesis Score Threshold"
                      testId="field-help-genesis-threshold"
                    >
                      How closely this identity's current configuration (model, code, provider) must
                      match what it had when it was first created.
                    </FieldHelp>
                  </div>
                </Card.Body>
              </Card>

              {/* Behavioral */}
              <Card className="mb-2 border-0 bg-light">
                <Card.Body className="p-3">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <div className="d-flex align-items-center">
                      <strong>Behavioral Score</strong>
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        weight: {config.components.behavioral.weight}
                      </Badge>
                      <FieldHelp
                        ariaLabel="About Behavioral Score weight"
                        testId="field-help-behavioral-weight"
                      >
                        How much this component counts toward the Overall Score above. Set by the
                        selected template, not directly editable here.
                      </FieldHelp>
                    </div>
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="Required"
                        checked={config.components.behavioral.required}
                        onChange={e =>
                          updateConfig(['components', 'behavioral', 'required'], e.target.checked)
                        }
                      />
                      <FieldHelp
                        ariaLabel="About Behavioral Score Required"
                        testId="field-help-behavioral-required"
                      >
                        Test Policy checks the Behavioral threshold every time, independent of this
                        setting: how consistent this identity's real-world usage patterns are.
                      </FieldHelp>
                    </div>
                  </div>
                  <div className="d-flex align-items-center gap-2">
                    <input
                      type="range"
                      className="form-range flex-grow-1"
                      min="0"
                      max="100"
                      step="5"
                      value={config.components.behavioral.threshold * 100}
                      onChange={e =>
                        updateConfig(
                          ['components', 'behavioral', 'threshold'],
                          parseInt(e.target.value) / 100
                        )
                      }
                    />
                    <Badge bg="info" style={{ minWidth: '50px' }}>
                      {(config.components.behavioral.threshold * 100).toFixed(0)}%
                    </Badge>
                    <FieldHelp
                      ariaLabel="About Behavioral Score Threshold"
                      testId="field-help-behavioral-threshold"
                    >
                      How consistent this identity's usage patterns (latency, token use, response
                      behavior) are with its own history.
                    </FieldHelp>
                  </div>
                </Card.Body>
              </Card>

              {/* Operational */}
              <Card className="mb-2 border-0 bg-light">
                <Card.Body className="p-3">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <div className="d-flex align-items-center">
                      <strong>Operational Score</strong>
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        weight: {config.components.operational.weight}
                      </Badge>
                      <FieldHelp
                        ariaLabel="About Operational Score weight"
                        testId="field-help-operational-weight"
                      >
                        How much this component counts toward the Overall Score above. Set by the
                        selected template, not directly editable here.
                      </FieldHelp>
                    </div>
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="Required"
                        checked={config.components.operational.required}
                        onChange={e =>
                          updateConfig(['components', 'operational', 'required'], e.target.checked)
                        }
                      />
                      <FieldHelp
                        ariaLabel="About Operational Score Required"
                        testId="field-help-operational-required"
                      >
                        Test Policy checks the Operational threshold every time, independent of this
                        setting: whether this identity's hosting environment meets your security bar
                        (see TEE/Cloud below).
                      </FieldHelp>
                    </div>
                  </div>
                  <div className="d-flex align-items-center gap-2 mb-1">
                    <input
                      type="range"
                      className="form-range flex-grow-1"
                      min="0"
                      max="100"
                      step="5"
                      value={config.components.operational.threshold * 100}
                      onChange={e =>
                        updateConfig(
                          ['components', 'operational', 'threshold'],
                          parseInt(e.target.value) / 100
                        )
                      }
                    />
                    <Badge bg="info" style={{ minWidth: '50px' }}>
                      {(config.components.operational.threshold * 100).toFixed(0)}%
                    </Badge>
                  </div>
                  <small className="text-muted d-block mb-2">
                    How secure this identity's hosting environment is, based on the checks below.
                  </small>
                  <div className="d-flex gap-3 align-items-center">
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="TEE Required"
                        checked={config.components.operational.requireTEE}
                        onChange={e =>
                          updateConfig(
                            ['components', 'operational', 'requireTEE'],
                            e.target.checked
                          )
                        }
                      />
                      <FieldHelp ariaLabel="About TEE Required" testId="field-help-tee-required">
                        Hardware that keeps its code and data isolated even from its own host
                        machine's operator.
                      </FieldHelp>
                    </div>
                    <Form.Check
                      type="checkbox"
                      label="Cloud Required"
                      checked={config.components.operational.requireCloud}
                      onChange={e =>
                        updateConfig(
                          ['components', 'operational', 'requireCloud'],
                          e.target.checked
                        )
                      }
                    />
                  </div>
                  <small className="text-muted d-block mt-1">
                    TEE Required: require this identity to run inside a Trusted Execution
                    Environment (TEE). Cloud Required: require verifiable proof of which cloud
                    provider is hosting this identity. Test Policy checks the Overall, Genesis,
                    Behavioral, and Operational thresholds; these two settings aren't part of that
                    check.
                  </small>
                </Card.Body>
              </Card>

              {/* Attestation */}
              <Card className="mb-2 border-0 bg-light">
                <Card.Body className="p-3">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <div className="d-flex align-items-center">
                      <strong>Attestation Score</strong>
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        weight: {config.components.attestation.weight}
                      </Badge>
                      <FieldHelp
                        ariaLabel="About Attestation Score weight"
                        testId="field-help-attestation-weight"
                      >
                        How much this component counts toward the Overall Score above. Set by the
                        selected template, not directly editable here.
                      </FieldHelp>
                    </div>
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="Required"
                        checked={config.components.attestation.required}
                        onChange={e =>
                          updateConfig(['components', 'attestation', 'required'], e.target.checked)
                        }
                      />
                      <FieldHelp
                        ariaLabel="About Attestation Score Required"
                        testId="field-help-attestation-required"
                      >
                        How much verified evidence (attestations) backs this identity's claims. Test
                        Policy checks the Overall, Genesis, Behavioral, and Operational thresholds;
                        Attestation isn't part of that check.
                      </FieldHelp>
                    </div>
                  </div>
                  <div className="d-flex align-items-center gap-2 mb-1">
                    <input
                      type="range"
                      className="form-range flex-grow-1"
                      min="0"
                      max="100"
                      step="5"
                      value={config.components.attestation.threshold * 100}
                      onChange={e =>
                        updateConfig(
                          ['components', 'attestation', 'threshold'],
                          parseInt(e.target.value) / 100
                        )
                      }
                    />
                    <Badge bg="info" style={{ minWidth: '50px' }}>
                      {(config.components.attestation.threshold * 100).toFixed(0)}%
                    </Badge>
                  </div>
                  <small className="text-muted d-block mb-2">
                    How strong the body of attestation evidence for this identity is.
                  </small>
                  <Form.Group className="mb-0">
                    <Form.Label className="small mb-1">Minimum attestation count</Form.Label>
                    <Form.Text className="text-muted d-block mb-1">
                      The fewest individual attestations this identity must have on record to pass,
                      regardless of score. Test Policy checks the Overall, Genesis, Behavioral, and
                      Operational thresholds; this setting isn't part of that check.
                    </Form.Text>
                    <Form.Control
                      type="number"
                      size="sm"
                      value={config.components.attestation.minCount}
                      onChange={e =>
                        updateConfig(
                          ['components', 'attestation', 'minCount'],
                          parseInt(e.target.value) || 0
                        )
                      }
                      style={{ width: '100px' }}
                    />
                  </Form.Group>
                </Card.Body>
              </Card>

              {/* History */}
              <Card className="mb-2 border-0 bg-light">
                <Card.Body className="p-3">
                  <div className="d-flex align-items-center justify-content-between mb-2">
                    <div className="d-flex align-items-center">
                      <strong>History Score</strong>
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        weight: {config.components.history.weight}
                      </Badge>
                      <FieldHelp
                        ariaLabel="About History Score weight"
                        testId="field-help-history-weight"
                      >
                        How much this component counts toward the Overall Score above. Set by the
                        selected template, not directly editable here.
                      </FieldHelp>
                    </div>
                    <div className="d-flex align-items-center">
                      <Form.Check
                        type="checkbox"
                        label="Required"
                        checked={config.components.history.required}
                        onChange={e =>
                          updateConfig(['components', 'history', 'required'], e.target.checked)
                        }
                      />
                      <FieldHelp
                        ariaLabel="About History Score Required"
                        testId="field-help-history-required"
                      >
                        How clean this identity's version history is (no signs of tampering or
                        unexplained changes). Test Policy checks the Overall, Genesis, Behavioral,
                        and Operational thresholds; History isn't part of that check.
                      </FieldHelp>
                    </div>
                  </div>
                  <div className="d-flex align-items-center gap-2 mb-1">
                    <input
                      type="range"
                      className="form-range flex-grow-1"
                      min="0"
                      max="100"
                      step="5"
                      value={config.components.history.threshold * 100}
                      onChange={e =>
                        updateConfig(
                          ['components', 'history', 'threshold'],
                          parseInt(e.target.value) / 100
                        )
                      }
                    />
                    <Badge bg="info" style={{ minWidth: '50px' }}>
                      {(config.components.history.threshold * 100).toFixed(0)}%
                    </Badge>
                  </div>
                  <small className="text-muted d-block">
                    How clean this identity's version history is.
                  </small>
                </Card.Body>
              </Card>
            </div>

            {/* Advanced Section - Collapsible */}
            <Accordion className="mb-3">
              <Accordion.Item eventKey="0">
                <Accordion.Header>
                  <i className="fas fa-code me-2"></i>
                  Advanced: OPA/Rego Policy (Optional)
                </Accordion.Header>
                <Accordion.Body>
                  <Form.Group>
                    <Form.Label className="small d-flex align-items-center">
                      Custom Rego Policy
                      <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.7em' }}>
                        Optional
                      </Badge>
                      <FieldHelp
                        ariaLabel="About Custom Rego Policy"
                        testId="field-help-custom-rego"
                      >
                        Write custom rules in Rego (the policy language used by OPA, Open Policy
                        Agent) for logic the sliders above can't express.
                      </FieldHelp>
                    </Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={10}
                      value={config.advancedPolicy || DEFAULT_REGO_POLICY}
                      onChange={e => updateConfig(['advancedPolicy'], e.target.value)}
                      style={{ fontFamily: 'monospace', fontSize: '0.85em' }}
                      placeholder="Enter OPA/Rego policy code..."
                    />
                    <Form.Text className="text-muted">
                      Optional. Leave this alone unless you need conditions beyond simple score
                      thresholds.
                    </Form.Text>
                  </Form.Group>
                </Accordion.Body>
              </Accordion.Item>
            </Accordion>

            {/* Test Results */}
            {testResult && (
              <Alert variant={testResult.allowed ? 'success' : 'danger'} className="mb-3">
                <div className="d-flex align-items-center mb-2">
                  <i
                    className={`fas fa-${testResult.allowed ? 'check-circle' : 'times-circle'} me-2`}
                  ></i>
                  <strong>{testResult.allowed ? 'ALLOWED' : 'DENIED'}</strong>
                </div>
                <ul className="mb-0 small">
                  {testResult.checks.map((check: any, idx: number) => (
                    <li key={idx}>
                      {check.passed ? '✓' : '✗'} {check.name}: {(check.value * 100).toFixed(0)}%{' '}
                      {check.passed ? '≥' : '<'} {(check.threshold * 100).toFixed(0)}%
                    </li>
                  ))}
                </ul>
              </Alert>
            )}

            {modified && (
              <Alert variant="info" className="mb-0">
                <i className="fas fa-info-circle me-2"></i>
                You have unsaved changes. Click "Save" or "Test & Save" to apply them.
              </Alert>
            )}
          </>
        )}
      </Modal.Body>

      <Modal.Footer className="d-block">
        <small className="text-muted d-block mb-2">
          Save applies this policy immediately. Test & Save runs the check above first and only
          saves if it passes.
        </small>
        <div className="d-flex align-items-center">
          <Button
            variant="outline-secondary"
            onClick={() => testPolicy()}
            disabled={saving || loading}
          >
            <i className="fas fa-vial me-2"></i>
            Test Policy
          </Button>
          <div className="flex-grow-1"></div>
          <Button variant="secondary" onClick={onHide} disabled={saving} className="me-2">
            Cancel
          </Button>
          <Button
            variant="success"
            onClick={handleTestAndSave}
            disabled={saving || loading || !modified}
            className="me-2"
          >
            <i className="fas fa-check-double me-2"></i>
            {saving ? 'Saving...' : 'Test & Save'}
          </Button>
          <Button variant="primary" onClick={handleSave} disabled={saving || loading || !modified}>
            <i className="fas fa-save me-2"></i>
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
};

export default PolicyConfigModal;
