import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import IdentityPayloadFullscreenPanel from '../identity/IdentityPayloadFullscreenPanel';

function baseProps(overrides: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'identity-tp',
      type: 'identity',
      label: 'Identity',
      configured: true,
      parentId: 'tp-1',
      slotId: 'request:identity-managed_identity',
      config: {},
    },
    config: {},
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'a2a',
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
    ...overrides,
  } as any;
}

describe('IdentityPayloadFullscreenPanel', () => {
  it('shows the Copilot identity schema helper for A2A Transit Point managed identity', () => {
    render(<IdentityPayloadFullscreenPanel {...baseProps()} />);

    expect(
      screen.getByRole('button', { name: /use copilot identity schema/i })
    ).toBeInTheDocument();
  });

  it('does not show the Copilot identity schema helper for a non-A2A Transit Point identity', () => {
    render(
      <IdentityPayloadFullscreenPanel
        {...baseProps({
          allNodes: [
            { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config: {} },
            {
              id: 'tp-1',
              type: 'transit-point-mcp',
              label: 'Transit Point',
              configured: true,
              config: {},
            },
          ],
        })}
      />
    );

    expect(
      screen.queryByRole('button', { name: /use copilot identity schema/i })
    ).not.toBeInTheDocument();
  });

  it('hides the meta field control for A2A identities', () => {
    render(<IdentityPayloadFullscreenPanel {...baseProps({ protocol: 'a2a' })} />);

    expect(screen.queryByLabelText(/identity meta field name/i)).not.toBeInTheDocument();
    expect(screen.getByTestId('identity-a2a-extension-note')).toHaveTextContent(
      /identity extension payload/i
    );
  });

  it('shows the meta field control for MCP identities', () => {
    render(
      <IdentityPayloadFullscreenPanel
        {...baseProps({
          protocol: 'mcp',
          allNodes: [
            { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config: {} },
            {
              id: 'tp-1',
              type: 'transit-point-mcp',
              label: 'Transit Point',
              configured: true,
              config: {},
            },
          ],
        })}
      />
    );

    expect(screen.getByLabelText(/identity meta field name/i)).toBeInTheDocument();
    expect(screen.queryByTestId('identity-a2a-extension-note')).not.toBeInTheDocument();
  });
});
