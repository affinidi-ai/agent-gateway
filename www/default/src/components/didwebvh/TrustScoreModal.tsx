import React, { useEffect, useState } from 'react';
import { Alert, Button, Modal, ProgressBar, Spinner } from 'react-bootstrap';
import {
  Chart as ChartJS,
  Filler,
  Legend,
  LineElement,
  PointElement,
  RadialLinearScale,
  Tooltip,
} from 'chart.js';
import { Radar } from 'react-chartjs-2';
import { AgentDNA, TrustScoreResponse } from '../../types';
import { apiClient } from '../../api';
import { UI_COLORS, withAlpha } from '../../utils/uiPalette';

// Register Chart.js components
ChartJS.register(RadialLinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

interface TrustScoreModalProps {
  identityId: string;
  did: string;
  show: boolean;
  onHide: () => void;
  /** Optional Agent DNA to display alongside the trust score */
  agentDna?: AgentDNA;
}

const TrustScoreModal: React.FC<TrustScoreModalProps> = ({
  identityId,
  did,
  show,
  onHide,
  agentDna,
}) => {
  const [trustScore, setTrustScore] = useState<TrustScoreResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (show && identityId) {
      loadTrustScore();
    }
  }, [show, identityId]);

  const loadTrustScore = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.getIdentityTrustScore(identityId);
      setTrustScore(data);
    } catch (err: any) {
      console.error('Failed to load trust score:', err);
      setError(err.message || 'Failed to load trust score');
    } finally {
      setLoading(false);
    }
  };

  const getScoreVariant = (score: number): string => {
    if (score >= 0.8) return 'success';
    if (score >= 0.6) return 'info';
    if (score >= 0.4) return 'warning';
    return 'danger';
  };

  const getScoreLabel = (score: number): string => {
    if (score >= 0.8) return 'TRUSTED';
    if (score >= 0.6) return 'ACCEPTABLE';
    if (score >= 0.4) return 'CAUTION';
    return 'LOW TRUST';
  };

  const getComponentStatus = (score: number): { icon: string; color: string; label: string } => {
    if (score >= 0.8) return { icon: '✓', color: 'text-success', label: 'Excellent' };
    if (score >= 0.6) return { icon: '⚠', color: 'text-warning', label: 'Good' };
    return { icon: '⚠', color: 'text-danger', label: 'Needs Attention' };
  };

  // Prepare radar chart data for Chart.js
  const radarData = trustScore
    ? {
        labels: ['Genesis', 'Behavioral', 'Operational', 'Attestation', 'History'],
        datasets: [
          {
            label: 'Trust Score',
            data: [
              trustScore.components.genesis * 100,
              trustScore.components.behavioral * 100,
              trustScore.components.operational * 100,
              trustScore.components.attestation * 100,
              trustScore.components.history * 100,
            ],
            backgroundColor: withAlpha(UI_COLORS.primary, 0.2),
            borderColor: withAlpha(UI_COLORS.primary, 1),
            borderWidth: 2,
            pointBackgroundColor: withAlpha(UI_COLORS.primary, 1),
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: withAlpha(UI_COLORS.primary, 1),
          },
        ],
      }
    : { labels: [], datasets: [] };

  const radarOptions = {
    scales: {
      r: {
        min: 0,
        max: 100,
        beginAtZero: true,
        ticks: {
          stepSize: 20,
        },
      },
    },
    plugins: {
      legend: {
        display: false,
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <Modal show={show} onHide={onHide} size="xl">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="fas fa-chart-line"></i> Trust Score Analysis
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading && (
          <div className="text-center py-5">
            <Spinner animation="border" variant="primary" />
            <p className="mt-3">Loading trust score...</p>
          </div>
        )}

        {error && (
          <Alert variant="danger">
            <i className="fas fa-exclamation-triangle"></i> {error}
            <Button variant="link" size="sm" onClick={loadTrustScore}>
              Retry
            </Button>
          </Alert>
        )}

        {trustScore && !loading && (
          <>
            {/* Overall Score Card */}
            <div className="card mb-4">
              <div className="card-header">
                <h5 className="mb-0">Overall Trust Score</h5>
              </div>
              <div className="card-body text-center">
                <h1 className="display-3 mb-3">{(trustScore.overall_score * 100).toFixed(0)}%</h1>
                <h4 className={`text-${getScoreVariant(trustScore.overall_score)}`}>
                  {getScoreLabel(trustScore.overall_score)}
                </h4>
                <ProgressBar
                  now={trustScore.overall_score * 100}
                  variant={getScoreVariant(trustScore.overall_score)}
                  className="mt-3"
                  style={{ height: '25px' }}
                />

                {/* Weighted Breakdown */}
                <div className="mt-4 text-start">
                  <h6>Weighted Components:</h6>
                  <ul className="list-unstyled small">
                    <li>
                      Genesis (25%): {trustScore.components.genesis.toFixed(2)} × 0.25 ={' '}
                      {(trustScore.components.genesis * 0.25).toFixed(3)}
                    </li>
                    <li>
                      Behavioral (25%): {trustScore.components.behavioral.toFixed(2)} × 0.25 ={' '}
                      {(trustScore.components.behavioral * 0.25).toFixed(3)}
                    </li>
                    <li>
                      Operational (20%): {trustScore.components.operational.toFixed(2)} × 0.20 ={' '}
                      {(trustScore.components.operational * 0.2).toFixed(3)}
                    </li>
                    <li>
                      Attestation (20%): {trustScore.components.attestation.toFixed(2)} × 0.20 ={' '}
                      {(trustScore.components.attestation * 0.2).toFixed(3)}
                    </li>
                    <li>
                      History (10%): {trustScore.components.history.toFixed(2)} × 0.10 ={' '}
                      {(trustScore.components.history * 0.1).toFixed(3)}
                    </li>
                  </ul>
                  <hr />
                  <p className="font-weight-bold">Total: {trustScore.overall_score.toFixed(3)}</p>
                </div>
              </div>
            </div>

            {/* Radar Chart and Details */}
            <div className="row">
              <div className="col-md-6">
                <div className="card mb-4">
                  <div className="card-header">
                    <h6 className="mb-0">Component Breakdown (Radar)</h6>
                  </div>
                  <div className="card-body" style={{ height: '300px' }}>
                    <Radar data={radarData} options={radarOptions} />
                  </div>
                </div>
              </div>

              <div className="col-md-6">
                <div className="card mb-4">
                  <div className="card-header">
                    <h6 className="mb-0">Component Scores</h6>
                  </div>
                  <div className="card-body">
                    {Object.entries(trustScore.components).map(([key, value]) => {
                      const status = getComponentStatus(value);
                      return (
                        <div key={key} className="mb-3">
                          <div className="d-flex justify-content-between align-items-center mb-1">
                            <span className="font-weight-bold text-capitalize">
                              <span className={status.color}>{status.icon}</span> {key}
                            </span>
                            <span className={`badge badge-${getScoreVariant(value)}`}>
                              {(value * 100).toFixed(0)}% - {status.label}
                            </span>
                          </div>
                          <ProgressBar now={value * 100} variant={getScoreVariant(value)} />
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            {/* Component Details */}
            <div className="card mb-4">
              <div className="card-header">
                <h6 className="mb-0">Component Analysis</h6>
              </div>
              <div className="card-body">
                <div className="accordion" id="componentAccordion">
                  {/* Genesis */}
                  <div className="card">
                    <div className="card-header" id="headingGenesis">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseGenesis"
                        >
                          <span className={getComponentStatus(trustScore.components.genesis).color}>
                            {getComponentStatus(trustScore.components.genesis).icon}
                          </span>{' '}
                          Genesis Stability ({(trustScore.components.genesis * 100).toFixed(0)}%)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseGenesis"
                      className="collapse"
                      data-parent="#componentAccordion"
                    >
                      <div className="card-body">
                        <ul>
                          <li>Measures stability of agent's core identity</li>
                          <li>Tracks code hash, model, and configuration consistency</li>
                          <li>Validates birth SCID (Self-Certifying Identifier)</li>
                          <li>Detects genesis drift over version history</li>
                        </ul>
                        {trustScore.components.genesis >= 0.8 ? (
                          <p className="text-success">
                            <i className="fas fa-check-circle"></i> <strong>Excellent:</strong> No
                            genesis drift detected
                          </p>
                        ) : (
                          <p className="text-warning">
                            <i className="fas fa-exclamation-triangle"></i>{' '}
                            <strong>Attention:</strong> Some variance in genesis fingerprint
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Behavioral */}
                  <div className="card">
                    <div className="card-header" id="headingBehavioral">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseBehavioral"
                        >
                          <span
                            className={getComponentStatus(trustScore.components.behavioral).color}
                          >
                            {getComponentStatus(trustScore.components.behavioral).icon}
                          </span>{' '}
                          Behavioral Consistency (
                          {(trustScore.components.behavioral * 100).toFixed(0)}%)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseBehavioral"
                      className="collapse"
                      data-parent="#componentAccordion"
                    >
                      <div className="card-body">
                        <ul>
                          <li>Monitors latency profile variance</li>
                          <li>Tracks token usage patterns</li>
                          <li>Validates challenge-response consistency</li>
                          <li>Detects behavioral anomalies</li>
                        </ul>
                        {trustScore.components.behavioral >= 0.7 ? (
                          <p className="text-success">
                            <i className="fas fa-check-circle"></i> <strong>Good:</strong>{' '}
                            Consistent behavioral patterns
                          </p>
                        ) : (
                          <p className="text-warning">
                            <i className="fas fa-exclamation-triangle"></i>{' '}
                            <strong>Recommendation:</strong> Enable challenge-response monitoring
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Operational */}
                  <div className="card">
                    <div className="card-header" id="headingOperational">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseOperational"
                        >
                          <span
                            className={getComponentStatus(trustScore.components.operational).color}
                          >
                            {getComponentStatus(trustScore.components.operational).icon}
                          </span>{' '}
                          Operational Security (
                          {(trustScore.components.operational * 100).toFixed(0)}%)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseOperational"
                      className="collapse"
                      data-parent="#componentAccordion"
                    >
                      <div className="card-body">
                        <ul>
                          <li>
                            Validates TEE attestation:{' '}
                            {trustScore.has_tee ? '✓ Present' : '✗ Not configured'}
                          </li>
                          <li>
                            Checks cloud attestation:{' '}
                            {trustScore.has_cloud_attestation ? '✓ Valid' : '✗ Not configured'}
                          </li>
                          <li>Verifies capability declarations</li>
                          <li>Ensures operational environment security</li>
                        </ul>
                        {trustScore.components.operational >= 0.8 ? (
                          <p className="text-success">
                            <i className="fas fa-check-circle"></i> <strong>Excellent:</strong> All
                            operational checks passed
                          </p>
                        ) : (
                          <p className="text-info">
                            <i className="fas fa-info-circle"></i> <strong>Tip:</strong> Configure
                            TEE and cloud attestation for higher scores
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Attestation */}
                  <div className="card">
                    <div className="card-header" id="headingAttestation">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseAttestation"
                        >
                          <span
                            className={getComponentStatus(trustScore.components.attestation).color}
                          >
                            {getComponentStatus(trustScore.components.attestation).icon}
                          </span>{' '}
                          Attestation Quality (
                          {(trustScore.components.attestation * 100).toFixed(0)}%)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseAttestation"
                      className="collapse"
                      data-parent="#componentAccordion"
                    >
                      <div className="card-body">
                        <ul>
                          <li>Validates Merkle root integrity</li>
                          <li>Counts attestation entries</li>
                          <li>Checks update frequency</li>
                          <li>Verifies attestation chain</li>
                        </ul>
                        {trustScore.components.attestation >= 0.8 ? (
                          <p className="text-success">
                            <i className="fas fa-check-circle"></i> <strong>Good:</strong>{' '}
                            Attestation quality is high
                          </p>
                        ) : (
                          <p className="text-info">
                            <i className="fas fa-info-circle"></i> <strong>Recommendation:</strong>{' '}
                            Increase attestation update frequency
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* History */}
                  <div className="card">
                    <div className="card-header" id="headingHistory">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseHistory"
                        >
                          <span className={getComponentStatus(trustScore.components.history).color}>
                            {getComponentStatus(trustScore.components.history).icon}
                          </span>{' '}
                          History Score ({(trustScore.components.history * 100).toFixed(0)}%)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseHistory"
                      className="collapse"
                      data-parent="#componentAccordion"
                    >
                      <div className="card-body">
                        <ul>
                          <li>Tracks version history stability</li>
                          <li>Monitors update frequency patterns</li>
                          <li>Detects tampering attempts</li>
                          <li>Validates version chain integrity</li>
                        </ul>
                        {trustScore.components.history >= 0.8 ? (
                          <p className="text-success">
                            <i className="fas fa-check-circle"></i> <strong>Excellent:</strong>{' '}
                            Clean version history
                          </p>
                        ) : (
                          <p className="text-info">
                            <i className="fas fa-info-circle"></i> Normal history variations
                            detected
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Metadata */}
            <div className="card mb-4">
              <div className="card-header">
                <h6 className="mb-0">Metadata</h6>
              </div>
              <div className="card-body">
                <div className="row">
                  <div className="col-md-4">
                    <p className="small mb-1">
                      <strong>DID:</strong>
                    </p>
                    <p className="font-monospace small">{trustScore.did}</p>
                  </div>
                  <div className="col-md-4">
                    <p className="small mb-1">
                      <strong>Version:</strong>
                    </p>
                    <p className="small">v{trustScore.version}</p>
                  </div>
                  <div className="col-md-4">
                    <p className="small mb-1">
                      <strong>Computed:</strong>
                    </p>
                    <p className="small">{new Date(trustScore.computed_at).toLocaleString()}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Agent DNA */}
            {agentDna && (
              <div className="card mb-4">
                <div className="card-header d-flex align-items-center">
                  <h6 className="mb-0 mr-2">
                    <i className="fas fa-dna mr-1"></i> Agent DNA
                  </h6>
                  <span className="badge badge-info">UAI</span>
                </div>
                <div className="card-body">
                  {/* UAI string */}
                  <div className="p-2 bg-light border rounded mb-3 d-flex justify-content-between align-items-start">
                    <div>
                      <small className="font-weight-bold text-muted d-block mb-1">
                        Universal Agent Identifier
                      </small>
                      <code style={{ fontSize: '0.8rem', wordBreak: 'break-all' }}>
                        {agentDna.uai}
                      </code>
                    </div>
                    <button
                      className="btn btn-sm btn-outline-secondary ml-2"
                      style={{ whiteSpace: 'nowrap' }}
                      onClick={() => navigator.clipboard.writeText(agentDna.uai)}
                      title="Copy UAI"
                    >
                      <i className="fas fa-copy"></i>
                    </button>
                  </div>

                  <div className="row">
                    {/* Genesis */}
                    <div className="col-md-6 mb-3">
                      <h6 className="small font-weight-bold text-primary mb-2">
                        <i className="fas fa-seedling mr-1"></i> Genesis
                      </h6>
                      <table className="table table-sm table-borderless mb-0 small">
                        <tbody>
                          <tr>
                            <td className="text-muted py-0 pr-2" style={{ width: '40%' }}>
                              Provider
                            </td>
                            <td className="py-0">
                              <code>{agentDna.genesis?.modelSpec?.provider}</code>
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Model</td>
                            <td className="py-0">
                              <code>
                                {agentDna.genesis?.modelSpec?.model}
                                {agentDna.genesis?.modelSpec?.version
                                  ? ` v${agentDna.genesis.modelSpec.version}`
                                  : ''}
                              </code>
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Code hash</td>
                            <td className="py-0">
                              <code title={agentDna.genesis?.codeHash}>
                                {agentDna.genesis?.codeHash?.slice(0, 16)}…
                              </code>
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Genesis hash</td>
                            <td className="py-0">
                              <code title={agentDna.genesis?.genesisHash}>
                                {agentDna.genesis?.genesisHash?.slice(0, 16)}…
                              </code>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Behavioral */}
                    <div className="col-md-6 mb-3">
                      <h6 className="small font-weight-bold text-primary mb-2">
                        <i className="fas fa-brain mr-1"></i> Behavioral
                      </h6>
                      <table className="table table-sm table-borderless mb-0 small">
                        <tbody>
                          <tr>
                            <td className="text-muted py-0 pr-2" style={{ width: '40%' }}>
                              Fingerprint
                            </td>
                            <td className="py-0">
                              <code title={agentDna.behavioral?.behavioralHash}>
                                {agentDna.behavioral?.behavioralHash?.slice(0, 16)}…
                              </code>
                            </td>
                          </tr>
                          {agentDna.behavioral?.latencyProfileHash && (
                            <tr>
                              <td className="text-muted py-0">Latency</td>
                              <td className="py-0">
                                <code>{agentDna.behavioral.latencyProfileHash.slice(0, 16)}…</code>
                              </td>
                            </tr>
                          )}
                          <tr>
                            <td className="text-muted py-0">Measured</td>
                            <td className="py-0">
                              {agentDna.behavioral?.measuredAt
                                ? new Date(agentDna.behavioral.measuredAt).toLocaleDateString()
                                : '—'}
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Operational */}
                    <div className="col-md-6 mb-3">
                      <h6 className="small font-weight-bold text-primary mb-2">
                        <i className="fas fa-server mr-1"></i> Operational
                      </h6>
                      <table className="table table-sm table-borderless mb-0 small">
                        <tbody>
                          <tr>
                            <td className="text-muted py-0 pr-2" style={{ width: '40%' }}>
                              TEE
                            </td>
                            <td className="py-0">
                              {agentDna.operational?.teeAttestation ? (
                                <span className="text-success">
                                  <i className="fas fa-check-circle mr-1"></i>
                                  {agentDna.operational.teeAttestation.type || 'Present'}
                                </span>
                              ) : (
                                <span className="text-muted">Not configured</span>
                              )}
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Cloud</td>
                            <td className="py-0">
                              {agentDna.operational?.cloudAttestation ? (
                                <span className="text-success">
                                  <i className="fas fa-check-circle mr-1"></i>
                                  {agentDna.operational.cloudAttestation.provider || 'Present'}
                                </span>
                              ) : (
                                <span className="text-muted">Not configured</span>
                              )}
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Op hash</td>
                            <td className="py-0">
                              <code title={agentDna.operational?.operationalHash}>
                                {agentDna.operational?.operationalHash?.slice(0, 16)}…
                              </code>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Attestations */}
                    <div className="col-md-6 mb-3">
                      <h6 className="small font-weight-bold text-primary mb-2">
                        <i className="fas fa-certificate mr-1"></i> Attestations
                      </h6>
                      <table className="table table-sm table-borderless mb-0 small">
                        <tbody>
                          <tr>
                            <td className="text-muted py-0 pr-2" style={{ width: '40%' }}>
                              Count
                            </td>
                            <td className="py-0">
                              <strong>{agentDna.attestations?.count ?? '—'}</strong>
                            </td>
                          </tr>
                          <tr>
                            <td className="text-muted py-0">Merkle root</td>
                            <td className="py-0">
                              <code title={agentDna.attestations?.merkleRoot}>
                                {agentDna.attestations?.merkleRoot?.slice(0, 16)}…
                              </code>
                            </td>
                          </tr>
                          {agentDna.attestations?.lastUpdated && (
                            <tr>
                              <td className="text-muted py-0">Updated</td>
                              <td className="py-0">
                                {new Date(agentDna.attestations.lastUpdated).toLocaleDateString()}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {/* Birth event */}
                  <div className="border-top pt-2 mt-2">
                    <small className="font-weight-bold text-muted d-block mb-1">
                      <i className="fas fa-baby mr-1"></i> Birth Event
                    </small>
                    <div className="row small">
                      <div className="col-md-4">
                        <span className="text-muted">SCID: </span>
                        <code style={{ fontSize: '0.72rem', wordBreak: 'break-all' }}>
                          {agentDna.birthEvent?.scid}
                        </code>
                      </div>
                      <div className="col-md-4">
                        <span className="text-muted">Born: </span>
                        {agentDna.birthEvent?.timestamp
                          ? new Date(agentDna.birthEvent.timestamp).toLocaleString()
                          : '—'}
                      </div>
                      <div className="col-md-4">
                        <span className="text-muted">Entry hash: </span>
                        <code title={agentDna.birthEvent?.birthEntryHash}>
                          {agentDna.birthEvent?.birthEntryHash?.slice(0, 12)}…
                        </code>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
        <Button variant="primary" onClick={loadTrustScore} disabled={loading}>
          <i className="fas fa-sync-alt"></i> Refresh
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default TrustScoreModal;
