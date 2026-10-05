import React from 'react';
import { Form } from 'react-bootstrap';
import FieldHelp from '../../components/shared/FieldHelp';
import type { A2aProxyFormData } from './types';

interface OverviewTabProps {
  formData: A2aProxyFormData;
  isEditMode: boolean;
  onChange: (patch: Partial<A2aProxyFormData>) => void;
}

const OverviewTab: React.FC<OverviewTabProps> = ({ formData, isEditMode, onChange }) => (
  <div data-testid="a2a-proxy-overview-tab">
    <div className="row">
      <div className="col-lg-8">
        <Form.Group className="mb-3">
          <Form.Label>
            Name <span className="text-danger">*</span>
          </Form.Label>
          <Form.Control
            data-testid="a2a-proxy-name-input"
            value={formData.name}
            onChange={e => onChange({ name: e.target.value })}
            placeholder="Support Agent Adapter"
            required
          />
        </Form.Group>
      </div>
      <div className="col-lg-4">
        <Form.Group className="mb-3">
          <Form.Label>
            Status{' '}
            <FieldHelp testId="field-help-a2a-overview-status" ariaLabel="About Status">
              Switch to Disabled to stop routing calls through this proxy without deleting its
              configuration, useful while troubleshooting or during planned maintenance.
            </FieldHelp>
          </Form.Label>
          <Form.Select
            data-testid="a2a-proxy-status-select"
            value={formData.status}
            onChange={e => onChange({ status: e.target.value as A2aProxyFormData['status'] })}
            disabled={!isEditMode}
          >
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </Form.Select>
          <Form.Text className="text-muted">
            {isEditMode
              ? 'Active proxies accept and forward live traffic.'
              : 'New proxies start active.'}
          </Form.Text>
        </Form.Group>
      </div>
    </div>

    <Form.Group className="mb-3">
      <Form.Label>Description</Form.Label>
      <Form.Control
        data-testid="a2a-proxy-description-input"
        as="textarea"
        rows={3}
        value={formData.description}
        onChange={e => onChange({ description: e.target.value })}
        placeholder="Managed agent exposed through an A2A adapter"
      />
    </Form.Group>
  </div>
);

export default OverviewTab;
