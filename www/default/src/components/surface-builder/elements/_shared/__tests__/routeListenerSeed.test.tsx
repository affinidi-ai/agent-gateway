import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import RouteListenerSection from '../RouteListenerSection';
import { fetchRoutingConfig, type RoutingConfig } from '../../access-point/defaults';

// The real module, with only the fetch replaced: the prefix rules under test are
// the ones the picker and the save gate share.
jest.mock('../../access-point/defaults', () => ({
  ...jest.requireActual('../../access-point/defaults'),
  fetchRoutingConfig: jest.fn(),
}));

const SHARED = 'https://gateway.example.com:9443';
const OWN = 'https://own.example.net';

const routing = (overrides: Partial<RoutingConfig> = {}): RoutingConfig => ({
  available_listen_addresses: ['https://gateway.example.com'],
  available_outbound_listen_addresses: [SHARED],
  shared_hostname_outbound_addresses: [SHARED],
  channel_path_prefix: [{ id: 'agents', name: 'agents', prefix: '/agents' }],
  ...overrides,
});

/** The fields a Transit Point node holds, as the panel writes them. */
type NodeConfig = Record<string, unknown>;

/**
 * Renders the section on a Transit Point whose config starts as `config`, and
 * returns the config as the section leaves it, applying each update the way the
 * builder does.
 */
function renderTransitPoint(config: NodeConfig = {}) {
  const held: NodeConfig = { ...config };
  const updateFields = jest.fn();

  // The node's config is state here, as it is in the builder: an update
  // re-renders the section, so the picker reads the address just written.
  const Harness: React.FC = () => {
    const [node, setNode] = React.useState<NodeConfig>(held);
    const apply = (fields: Record<string, unknown>) => {
      updateFields(fields);
      Object.assign(held, fields);
      setNode(current => ({ ...current, ...fields }));
    };
    return (
      <RouteListenerSection
        config={node}
        updateField={(field, value) => apply({ [field]: value })}
        updateFields={apply}
        addressSource="outbound"
        routeFieldName="listen_path"
        bannerLabel="Listener URL"
        bannerTestId="transit-point-listener-url"
      />
    );
  };

  render(<Harness />);
  return { held, updateFields };
}

beforeEach(() => {
  (fetchRoutingConfig as jest.Mock).mockResolvedValue(routing());
});

describe('a new Transit Point on an address whose listener shares an inbound hostname', () => {
  it('seeds a Listen Path under /outbound, which is what the save accepts there', async () => {
    const { held, updateFields } = renderTransitPoint();

    await waitFor(() => expect(updateFields).toHaveBeenCalled());
    expect(held.listen_address).toBe(SHARED);
    expect(held.route_prefix).toBe('/outbound/agents');
    expect(String(held.listen_path)).toMatch(/^\/outbound\/agents\//);
  });

  it('shows the /outbound prefixes alone in the picker', async () => {
    renderTransitPoint();

    await waitFor(() => expect(screen.getAllByRole('option').length).toBeGreaterThan(1));
    const offered = screen
      .getAllByRole('option')
      .map(option => (option as HTMLOptionElement).value)
      .filter(Boolean);
    expect(offered).toEqual(['/outbound/agents']);
  });
});

describe('a Transit Point on an outbound address with a hostname of its own', () => {
  beforeEach(() => {
    (fetchRoutingConfig as jest.Mock).mockResolvedValue(
      routing({
        available_outbound_listen_addresses: [OWN],
        shared_hostname_outbound_addresses: [],
      })
    );
  });

  it('seeds a plain prefix, which that listener serves', async () => {
    const { held, updateFields } = renderTransitPoint();

    await waitFor(() => expect(updateFields).toHaveBeenCalled());
    expect(held.listen_address).toBe(OWN);
    expect(held.route_prefix).toBe('/agents');
  });

  // Clearing the path is how the dashboard asks for the derived route, and both
  // refusals tell the operator to do it, so the empty value has to be written.
  it('clears the stored listen_path when Custom Path is emptied', async () => {
    const { held, updateFields } = renderTransitPoint({
      listen_address: OWN,
      listen_path: '/agents/partner-a',
      route_prefix: '/agents',
      route_suffix: 'partner-a',
    });

    // Wait for the routing config, so the field is the one the loaded section renders.
    await waitFor(() => expect(screen.getAllByRole('option').length).toBeGreaterThan(1));
    fireEvent.change(screen.getByPlaceholderText('my-agent/v1'), { target: { value: '' } });

    expect(updateFields).toHaveBeenCalledWith(expect.objectContaining({ listen_path: '' }));
    expect(held.listen_path).toBe('');
    // The prefix is cleared with it, so the empty pair is not marked invalid after Save.
    expect(held.route_prefix).toBe('');
  });

  // A cleared path answers at the derived route: reopening the panel must not seed a
  // random one, nor move the point to the first listener on offer.
  it('keeps a cleared Listen Path unset, on its own listener, when the panel reopens', async () => {
    const second = 'https://second.example.net';
    (fetchRoutingConfig as jest.Mock).mockResolvedValue(
      routing({
        available_outbound_listen_addresses: [OWN, second],
        shared_hostname_outbound_addresses: [],
      })
    );
    const { held, updateFields } = renderTransitPoint({
      listen_address: second,
      listen_path: '',
      route_prefix: '/agents',
      route_suffix: '',
    });

    await waitFor(() => expect(screen.getAllByRole('option').length).toBeGreaterThan(1));
    expect(updateFields).not.toHaveBeenCalled();
    expect(held.listen_address).toBe(second);
    expect(held.listen_path).toBe('');
  });

  it('resolves a stored /outbound path, since the save accepts both forms there', async () => {
    renderTransitPoint({
      listen_address: OWN,
      listen_path: '/outbound/agents/partner-a',
    });

    await waitFor(() => expect(screen.getAllByRole('option').length).toBeGreaterThan(1));
    const select = screen.getAllByRole('combobox').at(-1) as HTMLSelectElement;
    expect(select.value).toBe('/outbound/agents');
  });
});
