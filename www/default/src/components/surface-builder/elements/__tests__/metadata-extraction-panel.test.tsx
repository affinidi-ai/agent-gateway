import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import MetadataExtractionPanel from '../metadata-extraction/MetadataExtractionPanel';

function baseProps(overrides: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'metadata-extraction',
      type: 'metadata-extraction',
      label: 'Metadata Extraction',
      configured: true,
      slotId: 'request:metadata-extraction',
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

describe('MetadataExtractionPanel', () => {
  it('shows a header-mapping summary and opens the fullscreen editor', () => {
    const openFullscreenEditor = jest.fn();
    render(<MetadataExtractionPanel {...baseProps({ openFullscreenEditor })} />);

    expect(screen.getByTestId('metadata-extraction-section')).toBeInTheDocument();
    expect(screen.getByText('No headers configured')).toBeInTheDocument();
    expect(
      screen.queryByTestId('metadata-extraction-header-mapping-section')
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('metadata-extraction-configure'));
    expect(openFullscreenEditor).toHaveBeenCalledTimes(1);
  });

  it('renders the header-mapping editor in an Identity-style fullscreen card', async () => {
    const closeFullscreenEditor = jest.fn();
    render(
      <MetadataExtractionPanel
        {...baseProps({
          closeFullscreenEditor,
          config: {
            header_metadata_mapping: {
              extension_uri: 'https://fabric.affinidi.io/extensions/header-metadata/v1',
              headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
              strip_mapped_headers: true,
            },
          },
        })}
      />
    );

    expect(screen.getByRole('heading', { name: /metadata extraction/i })).toBeInTheDocument();
    expect(screen.getByText('1 header configured')).toBeInTheDocument();
    expect(screen.getByTestId('metadata-extraction-header-mapping-section')).toBeInTheDocument();

    // The Namespace URI field's full explanation is behind a FieldHelp
    // tooltip rather than printed permanently — open it before asserting.
    fireEvent.focus(screen.getByTestId('field-help-header-metadata-mapping-editor-namespace-uri'));
    await waitFor(() => {
      expect(screen.getByText(/Use any absolute http\(s\) URI you own/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/configure it with the same URI/i)).toBeInTheDocument();
    expect(screen.queryByText('Dynamic Values')).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId('metadata-extraction-close-tab'));
    expect(closeFullscreenEditor).toHaveBeenCalledTimes(1);
  });

  it('preserves a cleared Namespace URI instead of re-filling the default', () => {
    const updateField = jest.fn();
    render(
      <MetadataExtractionPanel
        {...baseProps({
          closeFullscreenEditor: jest.fn(),
          updateField,
          config: {
            header_metadata_mapping: {
              extension_uri: 'https://fabric.affinidi.io/extensions/header-metadata/v1',
              headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
              strip_mapped_headers: true,
            },
          },
        })}
      />
    );

    fireEvent.change(screen.getByTestId('metadata-extraction-header-mapping-extension-uri'), {
      target: { value: '' },
    });

    expect(updateField).toHaveBeenCalledWith('header_metadata_mapping', {
      extension_uri: '',
      headers: [{ header: 'x-ms-entra-agent-id', field: 'entra_agent_id' }],
      strip_mapped_headers: true,
    });
  });

  it('shows extraction only on an A2A Transit Point request node', () => {
    render(
      <MetadataExtractionPanel
        {...baseProps({
          node: {
            id: 'metadata-extraction-tp-1',
            type: 'metadata-extraction',
            label: 'Metadata Extraction',
            configured: true,
            parentId: 'tp-1',
            slotId: 'request:metadata-extraction',
            config: {},
          },
          allNodes: [
            { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config: {} },
            {
              id: 'tp-1',
              type: 'transit-point-a2a',
              label: 'Transit Point',
              configured: true,
              config: {},
            },
          ],
        })}
      />
    );

    expect(screen.queryByRole('button', { name: /add entry/i })).not.toBeInTheDocument();
    expect(screen.queryByText('Dynamic Values')).not.toBeInTheDocument();
    expect(screen.getByTestId('metadata-extraction-section')).toBeInTheDocument();
    expect(screen.getByText('No headers configured')).toBeInTheDocument();
  });
});
