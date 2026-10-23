import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import A2aProxyEndpointFields from '../managed-agent/A2aProxyEndpointFields';

const renderFields = (selectedProxyId?: string, updateFields: jest.Mock = jest.fn()) =>
  render(
    <A2aProxyEndpointFields
      selectedProxyId={selectedProxyId}
      a2aProxies={[{ id: 'p1', name: 'Copilot', status: 'active' }]}
      updateFields={updateFields}
    />
  );

describe('Managed Agent A2A proxy fields', () => {
  it('sets the proxy id and endpoint when a proxy is selected', () => {
    const updateFields = jest.fn();
    renderFields(undefined, updateFields);

    fireEvent.change(screen.getByTestId('managed-agent-a2a-proxy-select'), {
      target: { value: 'p1' },
    });
    expect(updateFields).toHaveBeenCalledWith({
      a2a_proxy_id: 'p1',
      endpoint: 'a2a-proxy://p1',
    });
  });

  it('clears the endpoint when no proxy is selected', () => {
    const updateFields = jest.fn();
    renderFields('p1', updateFields);

    fireEvent.change(screen.getByTestId('managed-agent-a2a-proxy-select'), {
      target: { value: '' },
    });
    expect(updateFields).toHaveBeenCalledWith({ a2a_proxy_id: '', endpoint: '' });
  });

  it('shows no version or identity notes', () => {
    renderFields('p1');

    expect(screen.queryByTestId('managed-agent-a2a-proxy-protocol-hint')).not.toBeInTheDocument();
    expect(screen.queryByTestId('managed-agent-a2a-proxy-identity-hint')).not.toBeInTheDocument();
    expect(screen.queryByTestId('managed-agent-a2a-proxy-edit-link')).not.toBeInTheDocument();
  });
});
