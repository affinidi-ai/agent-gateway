import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import CustomMetadataPanel from '../custom-metadata/CustomMetadataPanel';

jest.mock('../../../../api', () => ({
  apiClient: {
    fetch: jest.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve([]) })),
  },
}));

function baseProps(overrides: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'custom-metadata',
      type: 'custom-metadata',
      label: 'Metadata Injection',
      configured: true,
      slotId: 'request:custom-metadata',
      config: {},
    },
    config: {},
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'a2a',
    allNodes: [
      {
        id: 'access-point',
        type: 'access-point',
        label: 'Access Point',
        configured: true,
        config: {},
      },
      { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config: {} },
    ],
    ...overrides,
  } as any;
}

describe('CustomMetadataPanel', () => {
  it('shows metadata injection controls and Dynamic Values only', () => {
    render(<CustomMetadataPanel {...baseProps()} />);

    expect(screen.getAllByText('Inject metadata')[0]).toBeInTheDocument();
    expect(screen.getByText('Dynamic Values')).toBeInTheDocument();
    expect(screen.getByText('$REQUEST_ID')).toBeInTheDocument();
    expect(screen.getByText('$SURFACE_ID')).toBeInTheDocument();
    expect(screen.queryByText('$CHANNEL_ID')).not.toBeInTheDocument();
    expect(screen.queryByText('$CALLER_DID')).not.toBeInTheDocument();
    expect(screen.queryByText('Header Metadata Mapping')).not.toBeInTheDocument();
    expect(screen.queryByTestId('metadata-extraction-section')).not.toBeInTheDocument();
  });

  it('shows injection controls on a response Metadata Injection node', () => {
    render(
      <CustomMetadataPanel
        {...baseProps({
          node: {
            id: 'custom-metadata-response',
            type: 'custom-metadata',
            label: 'Metadata Injection',
            configured: true,
            direction: 'response',
            slotId: 'response:custom-metadata',
            config: {},
          },
        })}
      />
    );

    expect(screen.getAllByText('Inject metadata')[0]).toBeInTheDocument();
    expect(screen.getByText('Dynamic Values')).toBeInTheDocument();
    expect(screen.queryByText('Header Metadata Mapping')).not.toBeInTheDocument();
  });
});
