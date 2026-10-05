import React, { useState, useEffect } from 'react';
import { apiClient } from '../../api';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';
import { Link } from '../shared/Link';

interface SelectMediatorStepProps {
  onNext: (mediatorId: string) => void;
  onCancel: () => void;
  initialMediatorId?: string | null;
}

const SelectMediatorStep: React.FC<SelectMediatorStepProps> = ({
  onNext,
  onCancel,
  initialMediatorId = null,
}) => {
  const [mediators, setMediators] = useState<any[]>([]);
  const [selectedMediator, setSelectedMediator] = useState<string>(initialMediatorId || '');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadMediators();
  }, []);

  const loadMediators = async () => {
    try {
      setLoading(true);
      setError('');
      const response = await apiClient.get('/mediators/compatible');
      // Backend returns array directly, not wrapped in object
      const mediatorsList = Array.isArray(response.data) ? response.data : [];
      setMediators(mediatorsList);

      // Auto-select the first mediator if there's only one and no initial value
      if (mediatorsList.length === 1 && !initialMediatorId) {
        setSelectedMediator(mediatorsList[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load mediators:', err);
      setError('Failed to load mediators. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleNext = () => {
    if (!selectedMediator) {
      setError('Please select a mediator');
      return;
    }
    onNext(selectedMediator);
  };

  if (loading) {
    return (
      <div className="card shadow">
        <div className="card-body text-center py-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden"></span>
          </div>
        </div>
      </div>
    );
  }

  if (mediators.length === 0) {
    return (
      <div className="card shadow">
        <div className="card-body text-center py-5">
          <div className="mb-3">
            <i className="fas fa-exclamation-triangle hero-status-icon warning"></i>
          </div>
          <h5>No Compatible Mediators Available</h5>
          <p className="text-muted">
            No mediators are compatible with this gateway. Please{' '}
            <Link href="/mediators/wizard" variant="inline">
              add a mediator
            </Link>{' '}
            or contact your administrator.
          </p>
          <AppButton
            variant="secondary"
            size="md"
            onClick={onCancel}
            iconStart={<i className="fas fa-arrow-left"></i>}
          >
            Back to Connections
          </AppButton>
        </div>
      </div>
    );
  }

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-project-diagram me-2"></i>
          Select Mediator
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-4">
          Choose which of your configured DIDComm v2.1 mediators to use for this Connection Point
        </p>

        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}

        <div className="mb-4">
          <label htmlFor="mediator-select" className="form-label">
            Mediator <span className="text-danger">*</span>
          </label>
          <select
            id="mediator-select"
            className="form-control dropdown-styling"
            value={selectedMediator}
            onChange={e => setSelectedMediator(e.target.value)}
          >
            <option value="">Select a mediator...</option>
            {mediators.map(mediator => (
              <option key={mediator.id} value={mediator.id}>
                {mediator.name || 'Unnamed Mediator'} - {topAndTail(mediator.did, 16, 16)}
              </option>
            ))}
          </select>

          {selectedMediator && (
            <div className="mt-3 p-3 border rounded bg-light">
              <h6 className="text-primary mb-2">
                <i className="fas fa-info-circle me-2"></i>
                Selected Mediator Details
              </h6>
              {(() => {
                const selected = mediators.find(m => m.id === selectedMediator);
                if (!selected) return null;
                return (
                  <>
                    <div className="mb-2">
                      <strong>Name:</strong> {selected.name || 'Unnamed Mediator'}
                    </div>
                    {selected.description && (
                      <div className="mb-2">
                        <strong>Description:</strong> {selected.description}
                      </div>
                    )}
                    <div className="mb-0">
                      <strong>DID:</strong>
                      <code className="ms-2">{topAndTail(selected.did, 16, 16)}</code>
                      <CopyButton text={selected.did} />
                    </div>
                  </>
                );
              })()}
            </div>
          )}
        </div>

        <div className="d-flex justify-content-between">
          <AppButton
            variant="secondary"
            size="md"
            onClick={onCancel}
            iconStart={<i className="fas fa-times"></i>}
          >
            Cancel
          </AppButton>
          <AppButton
            variant="primary"
            size="md"
            onClick={handleNext}
            disabled={!selectedMediator}
            iconEnd={<i className="fas fa-arrow-right"></i>}
          >
            Next
          </AppButton>
        </div>
      </div>
    </div>
  );
};

export default SelectMediatorStep;
