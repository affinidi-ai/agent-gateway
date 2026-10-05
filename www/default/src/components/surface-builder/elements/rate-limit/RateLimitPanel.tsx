import React from 'react';
import { Form } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import FieldHelp from '../../../shared/FieldHelp';

const RateLimitPanel: React.FC<ConfigPanelProps> = ({ config, updateField }) => (
  <>
    <div className="config-section">
      <label>Requests</label>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Max requests per window</Form.Label>
          <FieldHelp
            testId="field-help-rate-limit-max-requests-per-window"
            ariaLabel="About Max requests per window"
          >
            <p>
              Together with Window below, sets how fast this route can steadily process requests
              before extra ones get rejected: e.g. 60 requests over a 60-second window means roughly
              1 request/second, sustained.
            </p>
            <p>
              This limit is shared across every caller of this route, not tracked per caller. It
              doesn't reset at a fixed point in time either; capacity refills continuously as time
              passes.
            </p>
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.requests ?? ''}
          onChange={e => updateField('requests', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Window (seconds)</Form.Label>
          <FieldHelp
            testId="field-help-rate-limit-window-seconds"
            ariaLabel="About Window (seconds)"
          >
            <p>
              Paired with Max requests above to set the steady rate: e.g. 60 requests / 60 seconds
              allows roughly 1 request/second, not "60 requests, then none until the minute rolls
              over."
            </p>
            <p>
              Capacity refills gradually the whole time, rather than resetting all at once at a
              fixed boundary.
            </p>
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="number"
          min="1"
          value={config.window_secs ?? ''}
          onChange={e => updateField('window_secs', e.target.value)}
        />
      </Form.Group>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">Burst allowance (optional)</Form.Label>
        <Form.Control
          size="sm"
          type="number"
          min="0"
          value={config.burst ?? ''}
          onChange={e => updateField('burst', e.target.value)}
        />
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Extra requests permitted in short bursts above the steady rate.
        </Form.Text>
      </Form.Group>
    </div>
  </>
);

export default RateLimitPanel;
