import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import '../index';
import RateLimitPanel from '../rate-limit/RateLimitPanel';

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
  render(
    <RateLimitPanel
      {...({
        node,
        config,
        updateField,
        updateFields: jest.fn(),
        allNodes: parent ? [parent, node] : [node],
      } as any)}
    />
  );
  return updateField;
}

describe('RateLimitPanel per-caller limit', () => {
  it('is offered on a Transit Point and written to the caller fields', () => {
    const updateField = showPanel(
      { id: 'tp-1', type: 'transit-point-a2a' },
      { requests: '100', window_secs: '60', caller_requests: '5' }
    );

    const section = screen.getByTestId('per-caller-rate-limit');
    expect(section).toBeInTheDocument();
    const inputs = within(section).getAllByRole('spinbutton');
    expect(inputs).toHaveLength(3);
    expect(inputs[0]).toHaveValue(5);

    fireEvent.change(inputs[1], { target: { value: '30' } });
    expect(updateField).toHaveBeenCalledWith('caller_window_secs', '30');
  });

  it('is not offered on the inbound limit', () => {
    showPanel({ id: 'access-point', type: 'access-point' }, { requests: '100', window_secs: '60' });

    expect(screen.queryByTestId('per-caller-rate-limit')).not.toBeInTheDocument();
  });
});
