import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import DeclarationOutcomeChip from '../DeclarationOutcomeChip';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import type { Protocol } from '../../types';
import { apiClient } from '../../../../../api';

jest.mock('../../../../../api', () => ({ apiClient: { fetch: jest.fn() } }));

const mockFetch = apiClient.fetch as jest.Mock;

function answer(declarations: Array<Record<string, unknown>>) {
  mockFetch.mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ declarations, warnings: [] }),
  });
}

beforeEach(() => {
  jest.resetAllMocks();
  answer([{ variant: null, outcome: 'declare', reason: null, resource: 'https://gw/a' }]);
});

const inEditor = (
  meta: Partial<SurfaceMetaValue>,
  surfaceId: string | undefined,
  protocol?: Protocol
) => (
  <SurfaceMetaProvider value={meta as SurfaceMetaValue}>
    <DeclarationOutcomeChip surfaceId={surfaceId} protocol={protocol} />
  </SurfaceMetaProvider>
);

const chip = () => screen.getByTestId('caller-auth-outcome-chip');

describe('DeclarationOutcomeChip card link', () => {
  it('links to the Agent Cards tab beside the outcome', async () => {
    const onOpenAgentCard = jest.fn();
    render(inEditor({ onOpenAgentCard }, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Declares OAuth'));
    const link = screen.getByTestId('caller-auth-outcome-card-link');
    expect(link).toHaveTextContent('See the card');
    fireEvent.click(link);
    expect(onOpenAgentCard).toHaveBeenCalledTimes(1);
    expect(mockFetch.mock.calls[0][0]).toBe('/api/v1/surfaces/s-1/declarations');
  });

  it('shows no link when the tab is not offered or the surface is not saved', async () => {
    const view = render(inEditor({}, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Declares OAuth'));
    expect(screen.queryByTestId('caller-auth-outcome-card-link')).not.toBeInTheDocument();
    view.unmount();

    render(inEditor({ onOpenAgentCard: jest.fn() }, undefined, 'a2a'));
    expect(chip()).toHaveTextContent('Outcome shown after the first save');
    expect(screen.queryByTestId('caller-auth-outcome-card-link')).not.toBeInTheDocument();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('still renders outside a surface editor', async () => {
    render(<DeclarationOutcomeChip surfaceId="s-1" />);
    await waitFor(() => expect(chip()).toHaveTextContent('Declares OAuth'));
    expect(screen.getByText('Agent card:')).toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-outcome-card-link')).not.toBeInTheDocument();
  });
});

describe('DeclarationOutcomeChip outcome', () => {
  it('shows the outcome of the variant being edited, not the base', async () => {
    answer([
      { variant: null, outcome: 'declare', reason: null, resource: 'https://gw/a' },
      { variant: 'beta', outcome: 'strip', reason: 'not_declared', resource: 'https://gw/a$beta' },
    ]);
    render(inEditor({ activeVariantAlias: 'beta' }, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Not declared'));
    expect(screen.getByTestId('caller-auth-outcome-detail')).toHaveTextContent(
      'Authorization server discovery is off for this route.'
    );
  });

  it('says unavailable when the variant edited has no entry', async () => {
    render(inEditor({ activeVariantAlias: 'gamma' }, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Agent card outcome unavailable'));
  });

  it('labels an MCP outcome as metadata and offers no card link', async () => {
    answer([{ variant: null, outcome: 'strip', reason: 'not_declared', resource: null }]);
    render(inEditor({ onOpenAgentCard: jest.fn() }, 's-1', 'mcp'));
    await waitFor(() => expect(chip()).toHaveTextContent('Not declared'));
    expect(screen.getByText('Protected resource metadata:')).toBeInTheDocument();
    expect(screen.queryByText('Agent card:')).not.toBeInTheDocument();
    expect(screen.queryByTestId('caller-auth-outcome-card-link')).not.toBeInTheDocument();
  });

  it('explains a route that does not publish authorization server discovery, and that the card keeps the agent’s security', async () => {
    answer([{ variant: null, outcome: 'strip', reason: 'not_declared', resource: null }]);
    render(inEditor({}, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Not declared'));
    expect(screen.getByTestId('caller-auth-outcome-detail')).toHaveTextContent(
      'Authorization server discovery is off for this route. The agent card keeps the managed agent’s own security. This reflects the saved surface.'
    );
  });

  it('marks each outcome with an icon and a text label, not colour alone', async () => {
    render(inEditor({}, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Declares OAuth'));
    expect(chip()).toHaveClass('app-badge', 'text-bg-success', 'caller-auth-outcome-chip');
    const icon = within(chip()).getByTestId('caller-auth-outcome-icon');
    expect(icon).toHaveClass('fa-shield-halved');
    expect(icon).toHaveAttribute('aria-hidden', 'true');
  });

  it.each([
    ['declare', null, 'text-bg-success', 'fa-shield-halved'],
    ['strip', 'not_declared', 'text-bg-warning', 'fa-triangle-exclamation'],
    ['unservable', 'strategy_unavailable', 'text-bg-danger', 'fa-circle-xmark'],
  ])(
    'renders the %s outcome as a tinted app badge with readable text',
    async (outcome, reason, toneClass, iconClass) => {
      answer([{ variant: null, outcome, reason, resource: null }]);
      render(inEditor({}, 's-1', 'a2a'));
      await waitFor(() => expect(chip()).toHaveClass(toneClass));
      expect(chip()).toHaveClass('app-badge');
      expect(within(chip()).getByTestId('caller-auth-outcome-icon')).toHaveClass(iconClass);
    }
  );

  it('renders a neutral app badge before the first save', () => {
    render(inEditor({}, undefined, 'a2a'));
    expect(chip()).toHaveClass('app-badge', 'text-bg-secondary');
    expect(within(chip()).getByTestId('caller-auth-outcome-icon')).toHaveClass('fa-circle-info');
  });

  it('says unavailable on a gateway without the declarations endpoint', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 404, json: async () => ({}) });
    render(inEditor({}, 's-1', 'a2a'));
    await waitFor(() => expect(chip()).toHaveTextContent('Agent card outcome unavailable'));
    expect(screen.queryByTestId('caller-auth-outcome-detail')).not.toBeInTheDocument();
  });

  it('says unavailable when the read fails outright', async () => {
    mockFetch.mockRejectedValue(new Error('offline'));
    render(inEditor({}, 's-1', 'mcp'));
    await waitFor(() =>
      expect(chip()).toHaveTextContent('Protected resource metadata outcome unavailable')
    );
  });
});
