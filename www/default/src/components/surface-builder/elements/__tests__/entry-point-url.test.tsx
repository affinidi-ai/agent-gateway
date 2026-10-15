import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import AccessPointPanel from '../access-point/AccessPointPanel';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import { RouteListenerBanner } from '../_shared/RouteListenerSection';
import { apiClient } from '../../../../api';
import { showToast } from '../../../../utils/toaster';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));
jest.mock('../../../../utils/toaster', () => ({ showToast: jest.fn() }));

const ENTRY_URL = 'https://gw.example.com/agents/helpdesk/v1';

const ROUTING = {
  available_listen_addresses: ['https://gw.example.com'],
  available_outbound_listen_addresses: [],
  channel_path_prefix: [{ id: 'agents', name: 'agents', prefix: '/agents' }],
};

const AP_CONFIG = {
  listen_address: 'https://gw.example.com',
  route_prefix: '/agents',
  route_suffix: 'helpdesk/v1',
  route: '/agents/helpdesk/v1',
};

beforeEach(() => {
  jest.clearAllMocks();
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: jest.fn().mockResolvedValue(undefined) },
  });
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve(url === '/api/v1/config/surface-routing' ? ROUTING : []),
    })
  );
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
});

function panelProps(
  type: 'access-point' | 'target',
  config: Record<string, unknown>,
  allNodes: CanvasNode[] = []
): ConfigPanelProps {
  return {
    node: { id: type, type, label: '', configured: true, config } as CanvasNode,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'a2a',
    allNodes,
  } as unknown as ConfigPanelProps;
}

describe('RouteListenerBanner', () => {
  const renderBanner = (props: Partial<React.ComponentProps<typeof RouteListenerBanner>> = {}) =>
    render(
      <RouteListenerBanner
        label="Entry point URL"
        help="The URL used to access this gateway"
        testId="banner"
        url={ENTRY_URL}
        {...props}
      />
    );

  it('shows the label, the URL and a help icon', () => {
    renderBanner();
    const banner = screen.getByTestId('banner');
    expect(banner).toHaveTextContent(`Entry point URL: ${ENTRY_URL}`);
    expect(screen.getByTestId('banner-help')).toHaveAccessibleName('About Entry point URL');
  });

  it('copies the URL and confirms it', async () => {
    renderBanner();
    const button = screen.getByTestId('banner-copy-button');
    expect(button).toBeEnabled();
    expect(button).toHaveAccessibleName('Copy Entry point URL');

    fireEvent.click(button);

    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(ENTRY_URL));
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    expect(showToast).not.toHaveBeenCalled();
  });

  it('tells the user to copy by hand when the clipboard refuses', async () => {
    (navigator.clipboard.writeText as jest.Mock).mockRejectedValueOnce(new Error('denied'));
    renderBanner();

    fireEvent.click(screen.getByTestId('banner-copy-button'));

    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith(
        'error',
        'Could not copy the Entry point URL: select it and copy it by hand.'
      )
    );
  });

  it('tells the user to copy by hand when the page has no clipboard API', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    renderBanner();

    fireEvent.click(screen.getByTestId('banner-copy-button'));

    await waitFor(() => expect(showToast).toHaveBeenCalledWith('error', expect.any(String)));
  });

  it('has no copy button until a URL is composed', () => {
    renderBanner({ url: '' });
    expect(screen.getByTestId('banner')).toHaveTextContent('(select address and prefix)');
    expect(screen.queryByTestId('banner-copy-button')).not.toBeInTheDocument();
  });

  it('shows the warning instead of the URL, without a copy button', () => {
    renderBanner({ warning: 'Path may not contain ".." segments' });
    const banner = screen.getByTestId('banner');
    expect(banner).toHaveClass('alert-warning');
    expect(banner).toHaveTextContent('Path may not contain ".." segments');
    expect(banner).not.toHaveTextContent(ENTRY_URL);
    expect(screen.queryByTestId('banner-copy-button')).not.toBeInTheDocument();
  });

  it('leaves out the help icon when no help is given', () => {
    renderBanner({ help: undefined });
    expect(screen.queryByTestId('banner-help')).not.toBeInTheDocument();
  });
});

describe('Access Point panel', () => {
  it('labels the composed URL Entry point URL and lets it be copied', async () => {
    render(<AccessPointPanel {...panelProps('access-point', AP_CONFIG)} />);

    const banner = await screen.findByTestId('access-point-entry-point-url');
    await waitFor(() => expect(banner).toHaveTextContent(`Entry point URL: ${ENTRY_URL}`));
    expect(screen.queryByText(/Channel Route/)).not.toBeInTheDocument();

    fireEvent.click(within(banner).getByTestId('access-point-entry-point-url-copy-button'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(ENTRY_URL);
  });

  it('explains how other agents use the URL', async () => {
    render(<AccessPointPanel {...panelProps('access-point', AP_CONFIG)} />);

    fireEvent.click(screen.getByRole('button', { name: /How routing works/ }));

    expect(
      await screen.findByText(/This URL is how other agents connect to this surface\./)
    ).toBeInTheDocument();
    expect(screen.queryByText(/auto-fills a random path/)).not.toBeInTheDocument();
  });
});

describe('Managed Agent panel', () => {
  it('does not repeat the Access Point URL', async () => {
    const accessPoint = {
      id: 'access-point',
      type: 'access-point',
      label: '',
      configured: true,
      config: AP_CONFIG,
    } as CanvasNode;
    render(<ManagedAgentPanel {...panelProps('target', {}, [accessPoint])} />);

    expect(await screen.findByText('Endpoint')).toBeInTheDocument();
    expect(screen.queryByText(/Reached at/)).not.toBeInTheDocument();
    expect(screen.queryByText(ENTRY_URL)).not.toBeInTheDocument();
    expect(screen.queryByTestId(/entry-point-url/)).not.toBeInTheDocument();
  });
});
