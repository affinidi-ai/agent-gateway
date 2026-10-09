import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AccessPointPanel from '../access-point/AccessPointPanel';

// The route/listener section fetches the gateway's listeners; it is not under test here.
jest.mock('../_shared/RouteListenerSection', () => () => null);

function baseProps(
  overrides: Record<string, unknown> = {},
  targetEndpoint = 'https://agent.example'
) {
  return {
    node: {
      id: 'access-point',
      type: 'access-point',
      label: 'Access Point',
      configured: true,
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
      {
        id: 'target',
        type: 'target',
        label: 'Managed Agent',
        configured: true,
        config: { endpoint: targetEndpoint },
      },
    ],
    ...overrides,
  } as any;
}

const version = (v: string) => screen.getByTestId(`access-point-a2a-version-${v}`);
const validation = () => screen.getByTestId('access-point-a2a-validation') as HTMLSelectElement;

describe('AccessPointPanel A2A protocol settings', () => {
  it('defaults to both versions with JSON-RPC envelope validation', () => {
    render(<AccessPointPanel {...baseProps()} />);

    expect(screen.getByTestId('access-point-a2a-protocol')).toBeInTheDocument();
    expect(version('0.3')).toBeChecked();
    expect(version('1.0')).toBeChecked();
    expect(validation().value).toBe('envelope');
    expect(version('0.3')).toBeEnabled();
    expect(validation()).toBeEnabled();
    expect(screen.queryByTestId('access-point-a2a-proxy-locked')).not.toBeInTheDocument();
  });

  it('offers the three validation levels with short labels', () => {
    render(<AccessPointPanel {...baseProps()} />);

    expect(Array.from(validation().options).map(o => [o.value, o.textContent])).toEqual([
      ['off', 'Off'],
      ['envelope', 'JSON-RPC envelope'],
      ['full', 'Envelope + A2A fields'],
    ]);
  });

  it('shows the stored selection', () => {
    render(
      <AccessPointPanel
        {...baseProps({ config: { a2a_accepted_versions: ['1.0'], a2a_validation: 'full' } })}
      />
    );

    expect(version('0.3')).not.toBeChecked();
    expect(version('1.0')).toBeChecked();
    expect(validation().value).toBe('full');
  });

  it('updates the versions in A2A order when one is toggled', () => {
    const updateFields = jest.fn();
    render(
      <AccessPointPanel
        {...baseProps({ updateFields, config: { a2a_accepted_versions: ['1.0'] } })}
      />
    );

    fireEvent.click(version('0.3'));
    expect(updateFields).toHaveBeenCalledWith({ a2a_accepted_versions: ['0.3', '1.0'] });

    fireEvent.click(version('1.0'));
    expect(updateFields).toHaveBeenLastCalledWith({ a2a_accepted_versions: [] });
  });

  it('changes the validation level', () => {
    const updateFields = jest.fn();
    render(<AccessPointPanel {...baseProps({ updateFields })} />);

    fireEvent.change(validation(), { target: { value: 'off' } });
    expect(updateFields).toHaveBeenLastCalledWith({ a2a_validation: 'off' });
    fireEvent.change(validation(), { target: { value: 'full' } });
    expect(updateFields).toHaveBeenLastCalledWith({ a2a_validation: 'full' });
  });

  it('asks for at least one version when none is selected', () => {
    render(<AccessPointPanel {...baseProps({ config: { a2a_accepted_versions: [] } })} />);

    expect(screen.getByTestId('access-point-a2a-versions-error')).toHaveTextContent(
      'Select at least one supported A2A version.'
    );
  });

  it('locks an A2A proxy target to 1.0 with envelope validation, whatever is stored', () => {
    render(
      <AccessPointPanel
        {...baseProps(
          { config: { a2a_accepted_versions: ['0.3'], a2a_validation: 'off' } },
          'a2a-proxy://worker'
        )}
      />
    );

    expect(version('0.3')).not.toBeChecked();
    expect(version('1.0')).toBeChecked();
    expect(validation().value).toBe('envelope');
    expect(version('0.3')).toBeDisabled();
    expect(version('1.0')).toBeDisabled();
    expect(validation()).toBeDisabled();
    expect(screen.getByTestId('access-point-a2a-proxy-locked')).toHaveTextContent(
      'An A2A proxy target serves A2A 1.0 with JSON-RPC envelope validation only.'
    );
    expect(screen.queryByTestId('access-point-a2a-versions-error')).not.toBeInTheDocument();
  });

  it('explains both settings behind field help', async () => {
    render(<AccessPointPanel {...baseProps()} />);

    fireEvent.focus(screen.getByTestId('field-help-access-point-a2a-versions'));
    expect(await screen.findByText(/counts as version 0\.3/)).toBeInTheDocument();

    fireEvent.focus(screen.getByTestId('field-help-access-point-a2a-validation'));
    expect(
      await screen.findByText(/including batch requests\. Envelope \+ A2A fields/)
    ).toBeInTheDocument();
  });

  it('is shown on an AP2 surface, whose Access Point carries the same settings', () => {
    render(<AccessPointPanel {...baseProps({ protocol: 'ap2' })} />);

    expect(screen.getByTestId('access-point-a2a-protocol')).toBeInTheDocument();
    expect(version('0.3')).toBeChecked();
    expect(validation().value).toBe('envelope');
  });

  it('is not shown on an MCP surface', () => {
    render(<AccessPointPanel {...baseProps({ protocol: 'mcp' })} />);

    expect(screen.queryByTestId('access-point-a2a-protocol')).not.toBeInTheDocument();
  });
});
