import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import '../index';
import RateLimitPanel from '../rate-limit/RateLimitPanel';
import { rateLimitDefinition } from '../rate-limit/definition';
import type { ConfigPanelProps } from '../types';

function showPanel(parent: { id: string; type: string } | null, config: Record<string, unknown>) {
  const updateField = jest.fn();
  const node = {
    id: 'rate-limit-1',
    type: 'rate-limit',
    label: '',
    configured: true,
    config,
    parentId: parent?.id,
  };
  const props = {
    node,
    config,
    updateField,
    updateFields: jest.fn(),
    allNodes: parent ? [parent, node] : [node],
  } as unknown as ConfigPanelProps;
  render(<RateLimitPanel {...props} />);
  return updateField;
}

describe('RateLimitPanel per-caller limit', () => {
  it('is offered on a Transit Point and written to the caller fields', () => {
    const updateField = showPanel(
      { id: 'tp-1', type: 'transit-point-a2a' },
      { requests: '100', window_secs: '60', caller_requests: '5' }
    );

    const section = screen.getByTestId('per-caller-rate-limit');
    expect(within(section).getAllByRole('spinbutton')).toHaveLength(3);
    expect(screen.getByTestId('rate-limit-caller-requests-input')).toHaveValue(5);
    expect(screen.getByTestId('rate-limit-caller-burst-input')).toHaveAttribute('min', '1');
    expect(within(section).getByTestId('field-help-rate-limit-per-caller')).toBeInTheDocument();

    fireEvent.change(screen.getByTestId('rate-limit-caller-window-secs-input'), {
      target: { value: '30' },
    });
    expect(updateField).toHaveBeenCalledWith('caller_window_secs', '30');
  });

  it('is not offered on the inbound limit', () => {
    showPanel({ id: 'access-point', type: 'access-point' }, { requests: '100', window_secs: '60' });

    expect(screen.queryByTestId('per-caller-rate-limit')).not.toBeInTheDocument();
  });
});

describe('rateLimitDefinition per-caller validation', () => {
  const validate = rateLimitDefinition.validate!;

  it('refuses a per-caller burst of 0, as the gateway does', () => {
    expect(validate({ caller_requests: '5', caller_window_secs: '60', caller_burst: '0' })).toEqual(
      [{ field: 'caller_burst', message: 'Per-caller burst must be a positive integer' }]
    );
  });

  it('accepts a positive per-caller burst or none', () => {
    expect(
      validate({ caller_requests: '5', caller_window_secs: '60', caller_burst: '10' })
    ).toEqual([]);
    expect(validate({ caller_requests: '5', caller_window_secs: '60' })).toEqual([]);
  });

  it('asks only for the per-caller fields when only a per-caller limit is set', () => {
    expect(rateLimitDefinition.incompleteReason({ caller_requests: '5' })).toBe(
      'Per-caller time window is required'
    );
    expect(
      rateLimitDefinition.incompleteReason({ caller_requests: '5', caller_window_secs: '60' })
    ).toBeNull();
    expect(rateLimitDefinition.incompleteReason({ requests: '5', caller_requests: '5' })).toBe(
      'Time window is required'
    );
  });
});
