import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import AgentCardTab from '../AgentCardTab';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import { apiClient } from '../../../../api';
import { showToast } from '../../../../utils/toaster';
import {
  AFTER_CARD,
  BEFORE_CARD,
  failedBody,
  previewBody,
  unsupportedBody,
} from '../../../../utils/agentCardTestFixtures';

jest.mock('../../../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../../../utils/toaster', () => ({ showToast: jest.fn() }));

const mockFetch = apiClient.fetch as jest.Mock;
const SCRIPT_URL = ['javascript', 'alert(1)'].join(':');
const reply = (status: number, body: unknown = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
});

type Props = Partial<React.ComponentProps<typeof AgentCardTab>>;
const tab = (props: Props = {}) => (
  <AgentCardTab
    surfaceId="s-123"
    isCreate={false}
    isDirty={false}
    canEdit
    hasVariants={false}
    {...props}
  />
);
const renderTab = (props: Props = {}) => render(tab(props));

const showBody = async (body: unknown, props: Props = {}) => {
  mockFetch.mockResolvedValue(reply(200, body));
  renderTab(props);
  await screen.findByTestId('agent-card-header');
};

const rowStatus = (key: string) =>
  screen.getByTestId(`agent-card-row-${key}`).getAttribute('data-status');

const rowCells = (key: string) => {
  const cells = within(screen.getByTestId(`agent-card-row-${key}`)).getAllByRole('cell');
  return { managed: cells[0], served: cells[cells.length - 1] };
};

const itemFor = (cell: HTMLElement, text: string) => {
  const item = within(cell)
    .getAllByRole('listitem')
    .find(li => within(li).queryByText(text) !== null);
  if (!item) throw new Error(`no item for ${text}`);
  return item;
};

beforeEach(() => {
  jest.resetAllMocks();
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: jest.fn().mockResolvedValue(undefined) },
  });
});

describe('AgentCardTab, states without a card', () => {
  it('asks for a save in create mode and fetches nothing', () => {
    renderTab({ isCreate: true, surfaceId: undefined });
    expect(screen.getByTestId('agent-card-unsaved')).toHaveTextContent(
      'Save the surface to see its agent cards.'
    );
    expect(screen.queryByTestId('agent-card-unsaved-changes')).not.toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('asks for a save when an edited surface has no id yet', () => {
    renderTab({ surfaceId: undefined });
    expect(screen.getByTestId('agent-card-unsaved')).toBeInTheDocument();
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('titles the tab Agent Cards', () => {
    renderTab({ isCreate: true, surfaceId: undefined });
    expect(screen.getByTestId('agent-card-tab')).toHaveTextContent('Agent Cards');
  });

  it('shows a loading status while the cards are fetched', async () => {
    mockFetch.mockReturnValue(new Promise(() => undefined));
    renderTab();
    expect(screen.getByTestId('agent-card-loading')).toHaveTextContent('Fetching the agent cards…');
    expect(screen.getByTestId('agent-card-loading')).toHaveAttribute('role', 'status');
  });

  it('offers a retry when the status cannot be read', async () => {
    mockFetch.mockResolvedValueOnce(reply(500));
    renderTab();
    const error = await screen.findByTestId('agent-card-error');
    expect(error).toHaveTextContent('Agent card status unavailable.');
    expect(error).toHaveAttribute('role', 'alert');

    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-retry-button'));
    await screen.findByTestId('agent-card-header');
    expect(screen.queryByTestId('agent-card-error')).not.toBeInTheDocument();
  });

  it('moves focus to the tab heading when Retry replaces itself with the loading status', async () => {
    mockFetch.mockResolvedValueOnce(reply(500));
    renderTab();
    const retry = await screen.findByTestId('agent-card-retry-button');
    mockFetch.mockReturnValueOnce(new Promise(() => undefined));
    retry.focus();
    fireEvent.click(retry);
    await screen.findByTestId('agent-card-loading');
    expect(screen.queryByTestId('agent-card-retry-button')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-heading')).toHaveFocus();
    expect(screen.getByTestId('agent-card-heading')).toHaveAttribute('tabindex', '-1');
  });

  it('keeps working on a gateway without the preview endpoint', async () => {
    mockFetch.mockResolvedValue(reply(404, { error: 'not found' }));
    renderTab();
    expect(await screen.findByTestId('agent-card-error')).toBeInTheDocument();
    expect(screen.getByTestId('agent-card-retry-button')).toBeEnabled();
  });

  it('shows the read-failed state when the request throws', async () => {
    mockFetch.mockRejectedValue(new Error('network'));
    renderTab();
    expect(await screen.findByTestId('agent-card-error')).toBeInTheDocument();
  });

  it('shows the read-failed state for a body it cannot parse', async () => {
    mockFetch.mockResolvedValue(reply(200, previewBody({ fetch: { status: 'exploded' } })));
    renderTab();
    expect(await screen.findByTestId('agent-card-error')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-header')).not.toBeInTheDocument();
  });

  it.each([
    ['not_a2a', 'Only A2A and AP2 surfaces have agent cards.'],
    [
      'not_running',
      'This surface is not running on this gateway, so its card cannot be fetched. Check that it is active.',
    ],
  ] as const)('explains an unsupported surface (%s)', async (reason, copy) => {
    mockFetch.mockResolvedValue(reply(200, unsupportedBody(reason)));
    renderTab();
    expect(await screen.findByTestId('agent-card-unsupported')).toHaveTextContent(copy);
    expect(screen.queryByTestId('agent-card-header')).not.toBeInTheDocument();
  });

  it('banners unsaved changes above the content', async () => {
    await showBody(previewBody(), { isDirty: true });
    expect(screen.getByTestId('agent-card-unsaved-changes')).toHaveTextContent(
      'You have unsaved changes. The cards show the saved surface.'
    );
  });
});

describe('AgentCardTab, link to the Surface', () => {
  it('links to the Surface view, which holds the Entry point URL', async () => {
    mockFetch.mockResolvedValue(reply(200, previewBody()));
    const onOpenSurfaceView = jest.fn();
    render(
      <SurfaceMetaProvider value={{ onOpenSurfaceView } as unknown as SurfaceMetaValue}>
        {tab()}
      </SurfaceMetaProvider>
    );
    await screen.findByTestId('agent-card-header');
    expect(screen.getByTestId('agent-card-surface-link')).toHaveTextContent(
      'The Entry point URL and the rest of the surface settings are in the Surface view.'
    );
    const open = screen.getByRole('button', { name: 'Open the Surface view' });
    fireEvent.click(open);
    expect(onOpenSurfaceView).toHaveBeenCalledTimes(1);
  });

  it('shows no Surface link outside a surface editor', async () => {
    await showBody(previewBody());
    expect(screen.queryByTestId('agent-card-surface-link')).not.toBeInTheDocument();
  });
});

describe('AgentCardTab, failed fetches', () => {
  it('explains a missing token and shows the cause with the HTTP status', async () => {
    await showBody(failedBody('needs_token', 401));
    const failed = screen.getByTestId('agent-card-failed');
    expect(failed).toHaveAttribute('role', 'alert');
    expect(failed).toHaveTextContent(
      "The gateway could not fetch the agent's card. Callers get no card until this is fixed."
    );
    expect(screen.getByTestId('agent-card-failed-cause')).toHaveTextContent(
      'The agent asked for a token (HTTP 401) and the gateway sent none. Set Target Authentication on the Managed Agent.'
    );
    expect(screen.getByTestId('agent-card-fetch-status')).toHaveTextContent('Failing');
    const cause = screen.getByTestId('agent-card-fetch-cause');
    expect(cause).toHaveAttribute('data-cause', 'needs_token');
    expect(cause).toHaveTextContent('Needs a token — HTTP 401');
    expect(screen.getByTestId('agent-card-auth')).toHaveTextContent('No Target Authentication');
    expect(screen.queryByTestId('agent-card-row-signin')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-summary')).not.toBeInTheDocument();
  });

  it('shows both raw panels open with why each card is missing', async () => {
    await showBody(failedBody('needs_token', 401));
    expect(screen.getByTestId('agent-card-raw-toggle')).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByTestId('agent-card-raw-before-missing')).toHaveTextContent(
      'Not available: Needs a token — HTTP 401.'
    );
    expect(screen.getByTestId('agent-card-raw-after-missing')).toHaveTextContent(
      'The gateway serves no card while the fetch fails.'
    );
    expect(screen.queryByTestId('agent-card-raw-after')).not.toBeInTheDocument();
  });

  it('says sign-in failed with the HTTP status when the agent rejects the credential', async () => {
    await showBody(failedBody('auth_failed', 401, { kind: 'credential_provider', result: 'sent' }));
    expect(screen.getByTestId('agent-card-fetch-cause')).toHaveTextContent(
      'Sign-in failed — HTTP 401'
    );
    expect(screen.getByTestId('agent-card-failed-cause')).toHaveTextContent(
      "The agent rejected the gateway's credential (HTTP 401). Check the provider's scopes and audience."
    );
  });

  it('names the failing credential when the gateway could not get it', async () => {
    await showBody(
      failedBody('auth_failed', null, {
        kind: 'credential_provider',
        result: 'failed',
        failure: 'secret_unavailable',
      })
    );
    expect(screen.getByTestId('agent-card-fetch-cause')).toHaveTextContent('Sign-in failed');
    expect(screen.getByTestId('agent-card-fetch-cause')).not.toHaveTextContent('HTTP');
    expect(screen.getByTestId('agent-card-failed-cause')).toHaveTextContent(
      'The gateway could not get its credential, so it did not ask the agent. A secret the credential needs is missing. Check Target Authentication on the Managed Agent.'
    );
    expect(screen.getByTestId('agent-card-auth')).toHaveTextContent('Credential not obtained');
    expect(screen.getByTestId('agent-card-auth')).not.toHaveTextContent('fallback');
  });

  it('shows the status code for an upstream error', async () => {
    await showBody(failedBody('upstream_error', 503));
    expect(screen.getByTestId('agent-card-failed-cause')).toHaveTextContent(
      'The agent answered HTTP 503. Check the agent logs, then Refresh.'
    );
    expect(screen.getByTestId('agent-card-fetch-cause')).toHaveTextContent(
      'Agent error — HTTP 503'
    );
  });

  it('says the gateway will not serve a card it fetched and shows the managed card', async () => {
    await showBody(
      previewBody({
        fetch: { status: 'not_served', cause: 'rewrite_failed', http_status: null, duration_ms: 5 },
        after: null,
        after_bytes: null,
      })
    );
    expect(screen.getByTestId('agent-card-failed')).toHaveTextContent(
      "The gateway fetched the agent's card but will not serve it."
    );
    expect(screen.getByTestId('agent-card-failed-cause')).toHaveTextContent(
      "The gateway could not rewrite the card's URLs and security. Check the gateway logs, then Refresh."
    );
    expect(screen.getByTestId('agent-card-fetch-status')).toHaveTextContent('Not served');
    expect(JSON.parse(screen.getByTestId('agent-card-raw-before').textContent ?? '')).toEqual(
      BEFORE_CARD
    );
    expect(screen.queryByTestId('agent-card-row-signin')).not.toBeInTheDocument();
  });
});

describe('AgentCardTab, the served card on a failed fetch', () => {
  const failedWithServed = (served: Record<string, unknown> = AFTER_CARD) => ({
    ...failedBody('needs_token', 401),
    after: served,
    after_bytes: 2950,
  });
  const SERVED_NOTE =
    'The card the gateway last served for this surface, before the latest fetch failed. Callers do not get it until this is fixed.';

  it('shows the card the gateway serves when the first load fails', async () => {
    await showBody(failedWithServed());
    expect(screen.getByTestId('agent-card-failed')).toHaveAttribute('role', 'alert');
    expect(screen.getByTestId('agent-card-raw-toggle')).toHaveAttribute('aria-expanded', 'true');
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      AFTER_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(SERVED_NOTE);
    expect(screen.getByTestId('agent-card-copy-after-button')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-raw-after-missing')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-raw-before-missing')).toHaveTextContent(
      'Not available: Needs a token — HTTP 401.'
    );
  });

  it('marks nothing as added when there is no managed card to compare', async () => {
    await showBody(failedWithServed());
    expect(screen.queryByTestId('agent-card-summary')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-row-signin')).not.toBeInTheDocument();
    expect(screen.queryByText('Added')).not.toBeInTheDocument();
    expect(screen.queryAllByTestId(/^agent-card-row-/)).toHaveLength(0);
    expect(screen.queryByTestId('agent-card-legend')).not.toBeInTheDocument();
  });

  it('prefers the served card a failed Refresh returns over the one the dashboard saw', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(reply(200, failedWithServed(BEFORE_CARD)));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await screen.findByTestId('agent-card-failed');
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      BEFORE_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(SERVED_NOTE);
    expect(screen.getByTestId('agent-card-raw-after-note')).not.toHaveTextContent('fetched');
    expect(screen.getByTestId('agent-card-refresh-status')).toHaveTextContent(
      'Card refreshed. The card fetch is failing.'
    );
  });

  it('still shows the served card when the tab mounts again after a failure', async () => {
    mockFetch.mockResolvedValue(reply(200, failedWithServed()));
    const view = renderTab();
    await screen.findByTestId('agent-card-raw-after');
    view.unmount();
    renderTab();
    await screen.findByTestId('agent-card-header');
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      AFTER_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(SERVED_NOTE);
  });

  it('says the served card is from before the gateway refused the new one', async () => {
    await showBody(
      previewBody({
        fetch: { status: 'not_served', cause: 'rewrite_failed', http_status: null, duration_ms: 5 },
      })
    );
    expect(JSON.parse(screen.getByTestId('agent-card-raw-before').textContent ?? '')).toEqual(
      BEFORE_CARD
    );
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      AFTER_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(
      'The card the gateway last served for this surface, before the gateway refused to serve the card it fetched. Callers do not get it until this is fixed.'
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).not.toHaveTextContent('gateway serves');
    expect(screen.queryByTestId('agent-card-summary')).not.toBeInTheDocument();
  });

  it('says the gateway serves no card when a failed fetch returns none', async () => {
    await showBody(
      previewBody({
        fetch: { status: 'not_served', cause: 'rewrite_failed', http_status: null, duration_ms: 5 },
        after: null,
        after_bytes: null,
      })
    );
    expect(screen.getByTestId('agent-card-raw-after-missing')).toHaveTextContent(
      'The gateway serves no card while the fetch fails.'
    );
    expect(screen.queryByTestId('agent-card-raw-after')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-raw-after-note')).not.toBeInTheDocument();
  });

  it('points at the card URL when the served card is over the display limit', async () => {
    await showBody({ ...failedBody('needs_token', 401), after_bytes: 300000 });
    expect(screen.getByTestId('agent-card-raw-after-missing')).toHaveTextContent(
      'The card the gateway last served is 293 KB, more than the 256 KB the dashboard shows. Open the card URL to read it.'
    );
    expect(screen.queryByTestId('agent-card-raw-after')).not.toBeInTheDocument();
  });

  it('keeps the card the dashboard saw on a gateway that returns no served card', async () => {
    await showBody(previewBody());
    const withoutAfter = failedBody('auth_failed', 401, {
      kind: 'credential_provider',
      result: 'sent',
    });
    delete withoutAfter.after;
    mockFetch.mockResolvedValueOnce(reply(200, withoutAfter));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await screen.findByTestId('agent-card-failed');
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      AFTER_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(
      'The last card the gateway served, fetched'
    );
  });
});

describe('AgentCardTab, comparison', () => {
  it('shows the Managed Agent Card beside the Gateway-Served Agent Card', async () => {
    await showBody(previewBody());
    expect(screen.getByTestId('agent-card-before')).toHaveTextContent('Managed Agent Card');
    expect(screen.getByTestId('agent-card-before')).toHaveTextContent("The agent's own card");
    expect(screen.getByTestId('agent-card-after')).toHaveTextContent('Gateway-Served Agent Card');
    expect(screen.getByTestId('agent-card-after')).toHaveTextContent('What callers see');
    const part = (side: string, text: string) =>
      within(screen.getByTestId(`agent-card-${side}`)).getByText(text, { exact: true });
    expect(part('before', 'Managed Agent Card')).toHaveClass('agent-card-column-title');
    expect(part('before', "The agent's own card")).toHaveClass('agent-card-column-hint');
    expect(part('after', 'Gateway-Served Agent Card')).toHaveClass('agent-card-column-title');
    expect(part('after', 'What callers see')).toHaveClass('agent-card-column-hint');
    expect(screen.getByTestId('agent-card-era-before')).toHaveTextContent('A2A 0.3');
    expect(screen.getByTestId('agent-card-era-after')).toHaveTextContent('A2A 0.3');
    const endpoint = rowCells('endpoint');
    expect(within(endpoint.managed).getByText('https://agent.internal/a2a')).toBeInTheDocument();
    expect(within(endpoint.served).getByText('https://gw.example/mock-agent')).toBeInTheDocument();
  });

  it('summarises the differences by kind and marks each row', async () => {
    await showBody(previewBody());
    expect(screen.getByTestId('agent-card-summary')).toHaveTextContent(
      'The gateway changed 7 parts of the card: 2 added, 2 modified, 3 removed.'
    );
    expect(screen.getByTestId('agent-card-change-count')).toHaveTextContent('7');
    expect(rowStatus('signin')).toBe('changed');
    expect(rowStatus('scope')).toBe('changed');
    expect(rowStatus('signature')).toBe('removed');
    expect(rowStatus('endpoint')).toBe('changed');
    expect(rowStatus('other')).toBe('same');
  });

  it('says so when the gateway changed nothing', async () => {
    await showBody(previewBody({ after: BEFORE_CARD }));
    expect(screen.getByTestId('agent-card-summary')).toHaveTextContent(
      "The gateway serves the agent's card unchanged."
    );
    expect(screen.queryByTestId('agent-card-change-count')).not.toBeInTheDocument();
    expect(rowStatus('signin')).toBe('same');
    for (const li of screen.queryAllByRole('listitem')) {
      expect(li).not.toHaveClass('agent-card-item-added');
      expect(li).not.toHaveClass('agent-card-item-removed');
      expect(li).not.toHaveClass('agent-card-item-changed');
    }
  });
});

describe('AgentCardTab, highlighted differences', () => {
  it('has a legend where every kind carries an icon and a text label', async () => {
    await showBody(previewBody());
    const legend = screen.getByRole('list', { name: 'Legend' });
    expect(legend).toBe(screen.getByTestId('agent-card-legend'));
    const expected = [
      ['added', 'Added', 'fa-plus'],
      ['changed', 'Modified', 'fa-pen'],
      ['removed', 'Removed', 'fa-minus'],
      ['same', 'Unchanged', 'fa-equals'],
    ] as const;
    for (const [status, label, icon] of expected) {
      const tag = screen.getByTestId(`agent-card-legend-${status}`);
      expect(tag).toHaveTextContent(label);
      expect(tag).toHaveClass(`agent-card-status-${status}`);
      const glyph = within(tag).getByTestId('agent-card-status-icon');
      expect(glyph).toHaveClass(icon);
      expect(glyph).toHaveAttribute('aria-hidden', 'true');
    }
  });

  it('marks an added field on the served card with its own colour class and label', async () => {
    await showBody(previewBody());
    const scope = rowCells('scope');
    const added = itemFor(scope.served, 'gw.invoke');
    expect(added).toHaveClass('agent-card-item-added');
    expect(added).toHaveAttribute('data-status', 'added');
    expect(within(added).getByText('Added')).toBeInTheDocument();
    expect(itemFor(scope.managed, 'gw.invoke')).not.toHaveClass('agent-card-item-added');
  });

  it('marks a removed field on the managed card with its own colour class and label', async () => {
    await showBody(previewBody());
    const scope = rowCells('scope');
    const removed = itemFor(scope.managed, 'agent.read');
    expect(removed).toHaveClass('agent-card-item-removed');
    expect(within(removed).getByText('Removed')).toBeInTheDocument();
    expect(itemFor(scope.served, 'agent.read')).not.toHaveClass('agent-card-item-removed');
  });

  it('marks a modified field on both cards', async () => {
    await showBody(previewBody());
    const endpoint = rowCells('endpoint');
    const managed = itemFor(endpoint.managed, 'https://agent.internal/a2a');
    const served = itemFor(endpoint.served, 'https://gw.example/mock-agent');
    for (const item of [managed, served]) {
      expect(item).toHaveClass('agent-card-item-changed');
      expect(item).toHaveAttribute('data-status', 'changed');
      expect(within(item).getByText('Modified')).toBeInTheDocument();
    }
  });

  it('exposes the compare table with column and row headers', async () => {
    await showBody(previewBody());
    const table = screen.getByRole('table', {
      name: 'The Managed Agent Card beside the Gateway-Served Agent Card',
    });
    expect(within(table).getAllByRole('columnheader')).toHaveLength(3);
    expect(within(table).getAllByRole('rowheader')).toHaveLength(5);
  });
});

describe('AgentCardTab, header facts and notes', () => {
  it('shows the header facts', async () => {
    await showBody(
      previewBody({
        source_url_query_hidden: true,
        last_caller_fetch: {
          status: 'failed',
          cause: 'needs_token',
          http_status: 401,
          at: '2026-10-23T09:58:12Z',
        },
      })
    );
    expect(screen.getByTestId('agent-card-header')).toHaveTextContent('Served card discovery URL');
    expect(screen.getByTestId('agent-card-header')).toHaveTextContent('Target Authentication');
    expect(screen.getByTestId('agent-card-header')).not.toHaveTextContent('Signed in as');
    expect(screen.getByTestId('agent-card-served-url')).toHaveTextContent(
      'https://gw.example/mock-agent/.well-known/agent-card.json'
    );
    expect(screen.getByTestId('agent-card-source-url')).toHaveTextContent(
      'https://agent.internal/.well-known/agent-card.json'
    );
    expect(screen.getByTestId('agent-card-header')).toHaveTextContent('(query hidden)');
    expect(screen.getByTestId('agent-card-fetch-status')).toHaveTextContent('OK');
    expect(screen.queryByTestId('agent-card-fetch-cause')).not.toBeInTheDocument();
    const expires = new Date('2026-10-23T10:55:00Z').toLocaleString();
    expect(screen.getByTestId('agent-card-auth')).toHaveTextContent(
      `oidc-e2e jwt bearer, token valid until ${expires}`
    );
    expect(screen.getByTestId('agent-card-fetched-at')).toHaveAttribute(
      'datetime',
      '2026-10-23T10:00:00Z'
    );
    const caller = screen.getByTestId('agent-card-last-caller-fetch');
    expect(caller).toHaveTextContent('Failing: Needs a token — HTTP 401');
    expect(caller).toHaveTextContent('on this gateway');
  });

  it('notes payment and surface variants', async () => {
    await showBody(previewBody({ payment_required: true }), { hasVariants: true });
    expect(screen.getByTestId('agent-card-payment')).toHaveTextContent(
      'Callers pay before they get this card.'
    );
    expect(screen.getByTestId('agent-card-variant-note')).toHaveTextContent(
      'This shows the base route. A Surface Variant may serve a different card.'
    );
  });

  it('omits those notes when they do not apply', async () => {
    await showBody(previewBody());
    expect(screen.queryByTestId('agent-card-payment')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-variant-note')).not.toBeInTheDocument();
  });

  it('shows only the served card for a generated card', async () => {
    await showBody(previewBody({ generated: true, before: null, source_url: null }));
    expect(screen.getByTestId('agent-card-generated')).toHaveTextContent(
      'The gateway generates this card for an A2A proxy, so there is no agent card to compare.'
    );
    expect(screen.getByTestId('agent-card-after')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-before')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-summary')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-source-url')).toHaveTextContent(
      'Generated by the gateway'
    );
    fireEvent.click(screen.getByTestId('agent-card-raw-toggle'));
    expect(screen.getByTestId('agent-card-raw-after')).toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-raw-before')).not.toBeInTheDocument();
  });

  it('points at the card URL when a card is over the display limit', async () => {
    await showBody(
      previewBody({ before: null, after: null, before_bytes: 300000, after_bytes: 310000 })
    );
    expect(screen.getByTestId('agent-card-too-large')).toHaveTextContent(
      'This card is 303 KB, more than the 256 KB the dashboard shows. Open the card URL to read it.'
    );
    expect(screen.queryByTestId('agent-card-row-signin')).not.toBeInTheDocument();
  });

  it('reports a status error for a card that is missing without a reason', async () => {
    await showBody(previewBody({ before: null }));
    expect(screen.getByTestId('agent-card-error')).toBeInTheDocument();
  });
});

describe('AgentCardTab, caller authentication in the served card', () => {
  it('shows the authorization server and scopes the gateway declares', async () => {
    await showBody(previewBody());
    const signin = rowCells('signin');
    const scheme = itemFor(signin.served, 'agent_gateway');
    expect(scheme).toHaveClass('agent-card-item-added');
    expect(scheme).toHaveTextContent('https://as.example/authorize');
    expect(within(rowCells('scope').served).getByText('gw.invoke')).toBeInTheDocument();
    expect(screen.getByTestId('agent-card-outcome')).toHaveTextContent('Declares OAuth');
    expect(screen.getByTestId('agent-card-outcome-reason')).toHaveTextContent(
      'The agent card and the protected resource metadata name the authorization server of the selected strategy and the required scopes, and callers without a valid token are challenged.'
    );
  });

  it('gives the reason a card is not declared and says it keeps the agent’s security', async () => {
    await showBody(
      previewBody({
        outcome: { variant: null, outcome: 'strip', reason: 'not_declared', resource: null },
      })
    );
    expect(screen.getByTestId('agent-card-outcome')).toHaveTextContent('Not declared');
    expect(screen.getByTestId('agent-card-outcome-reason')).toHaveTextContent(
      'Authorization server discovery is off for this route. The agent card keeps the managed agent’s own security.'
    );
  });

  it('omits the outcome when the gateway sends none', async () => {
    await showBody(previewBody({ outcome: null }));
    expect(screen.queryByTestId('agent-card-outcome')).not.toBeInTheDocument();
  });
});

describe('AgentCardTab, secret protection', () => {
  it('never shows a token or secret that reaches the preview outside the cards', async () => {
    mockFetch.mockResolvedValue(
      reply(
        200,
        previewBody({
          access_token: 'at-SECRET-1',
          auth: {
            kind: 'credential_provider',
            result: 'sent',
            provider_name: 'oidc-e2e jwt bearer',
            token_expires_at: null,
            failure: null,
            token: 'tok-SECRET-2',
            client_secret: 'cs-SECRET-3',
          },
          fetch: {
            status: 'ok',
            cause: null,
            http_status: 200,
            duration_ms: 3,
            error_body: 'body-SECRET-4',
          },
        })
      )
    );
    renderTab();
    await screen.findByTestId('agent-card-header');
    fireEvent.click(screen.getByTestId('agent-card-raw-toggle'));
    expect(screen.getByTestId('agent-card-raw-after')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('SECRET');
    expect(document.body.innerHTML).not.toContain('SECRET');
  });
});

describe('AgentCardTab, Refresh', () => {
  it('fetches the cards again on Refresh and shows the new snapshot', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(
      reply(200, previewBody({ fetched_at: '2026-10-23T10:05:00Z', after: BEFORE_CARD }))
    );
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() =>
      expect(screen.getByTestId('agent-card-fetched-at')).toHaveAttribute(
        'datetime',
        '2026-10-23T10:05:00Z'
      )
    );
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/surfaces/s-123/agent-card/refresh', {
      method: 'POST',
    });
    expect(screen.getByTestId('agent-card-summary')).toHaveTextContent('unchanged');
  });

  it('recovers from a failed fetch after Refresh', async () => {
    await showBody(failedBody('auth_failed', 401, { kind: 'credential_provider', result: 'sent' }));
    expect(screen.getByTestId('agent-card-failed')).toBeInTheDocument();
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() => expect(screen.queryByTestId('agent-card-failed')).not.toBeInTheDocument());
    expect(screen.getByTestId('agent-card-fetch-status')).toHaveTextContent('OK');
    expect(screen.queryByTestId('agent-card-fetch-cause')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-summary')).toHaveTextContent(
      'The gateway changed 7 parts of the card'
    );
  });

  it('keeps the Gateway-Served Agent Card visible when a Refresh fails, then recovers', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(
      reply(200, failedBody('auth_failed', 401, { kind: 'credential_provider', result: 'sent' }))
    );
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await screen.findByTestId('agent-card-failed');
    expect(screen.getByTestId('agent-card-fetch-cause')).toHaveTextContent(
      'Sign-in failed — HTTP 401'
    );
    expect(JSON.parse(screen.getByTestId('agent-card-raw-after').textContent ?? '')).toEqual(
      AFTER_CARD
    );
    expect(screen.getByTestId('agent-card-raw-after-note')).toHaveTextContent(
      'The last card the gateway served, fetched'
    );
    expect(screen.getByTestId('agent-card-raw-before-missing')).toHaveTextContent(
      'Not available: Sign-in failed — HTTP 401.'
    );

    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() => expect(screen.queryByTestId('agent-card-failed')).not.toBeInTheDocument());
    expect(screen.getByTestId('agent-card-row-signin')).toBeInTheDocument();
  });

  it('shows a toast and keeps the card when refreshes are rate limited', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(reply(429));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith(
        'warning',
        'Too many card refreshes. Try again in a minute.'
      )
    );
    expect(screen.getByTestId('agent-card-summary')).toBeInTheDocument();
    expect(screen.getByTestId('agent-card-refresh-button')).toBeEnabled();
  });

  it('shows an error toast when a refresh fails', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(reply(500));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', 'Could not refresh the agent card.')
    );
    expect(screen.getByTestId('agent-card-summary')).toBeInTheDocument();
  });

  it('shows a permission toast when the gateway refuses the refresh', async () => {
    await showBody(previewBody());
    mockFetch.mockResolvedValueOnce(reply(403));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith(
        'error',
        'You need permission to edit surfaces to refresh the card.'
      )
    );
  });

  it('announces a refresh that leaves the status unchanged', async () => {
    await showBody(previewBody());
    const announcer = screen.getByTestId('agent-card-refresh-status');
    expect(announcer).toHaveAttribute('role', 'status');
    expect(announcer).toHaveClass('visually-hidden');
    expect(announcer).toBeEmptyDOMElement();
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() =>
      expect(announcer).toHaveTextContent('Card refreshed. The card fetch is OK.')
    );
    expect(screen.getByTestId('agent-card-refresh-status')).toBe(announcer);
  });

  it('announces a failing refresh once, leaving the cause to the alert', async () => {
    await showBody(previewBody());
    expect(screen.getByTestId('agent-card-fetch')).not.toHaveAttribute('aria-live');
    mockFetch.mockResolvedValueOnce(
      reply(200, failedBody('auth_failed', 401, { kind: 'credential_provider', result: 'sent' }))
    );
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await screen.findByTestId('agent-card-failed');
    const announcer = screen.getByTestId('agent-card-refresh-status');
    expect(announcer).toHaveTextContent('Card refreshed. The card fetch is failing.');
    expect(announcer).not.toHaveTextContent('HTTP 401');
    expect(screen.getByTestId('agent-card-fetch')).not.toHaveAttribute('aria-live');
  });

  it('tells the surface editor only about a refresh that worked', async () => {
    const onRefreshed = jest.fn();
    await showBody(previewBody(), { onRefreshed });
    mockFetch.mockResolvedValueOnce(reply(500));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() => expect(showToast).toHaveBeenCalledTimes(1));
    expect(onRefreshed).not.toHaveBeenCalled();
    expect(screen.getByTestId('agent-card-refresh-status')).toBeEmptyDOMElement();

    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    await waitFor(() => expect(onRefreshed).toHaveBeenCalledTimes(1));
  });

  it('shows no toast for a refresh that fails after the tab closed', async () => {
    mockFetch.mockResolvedValueOnce(reply(200, previewBody()));
    const view = renderTab();
    await screen.findByTestId('agent-card-header');
    let answer: (value: unknown) => void = () => undefined;
    mockFetch.mockReturnValueOnce(
      new Promise(resolve => {
        answer = resolve;
      })
    );
    fireEvent.click(screen.getByTestId('agent-card-refresh-button'));
    view.unmount();
    await act(async () => {
      answer(reply(500));
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    expect(mockFetch).toHaveBeenLastCalledWith('/api/v1/surfaces/s-123/agent-card/refresh', {
      method: 'POST',
    });
    expect(showToast).not.toHaveBeenCalled();
  });

  it('disables Refresh without permission to edit surfaces', async () => {
    await showBody(previewBody(), { canEdit: false });
    const refresh = screen.getByTestId('agent-card-refresh-button');
    expect(refresh).toBeDisabled();
    expect(refresh).toHaveAttribute(
      'title',
      'You need permission to edit surfaces to refresh the card.'
    );
    expect(refresh).toHaveAccessibleDescription(
      'You need permission to edit surfaces to refresh the card.'
    );
    fireEvent.click(refresh);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});

describe('AgentCardTab, discovery URL, raw JSON and untrusted content', () => {
  it('opens the served card in a new tab and copies its discovery URL', async () => {
    await showBody(previewBody());
    const open = screen.getByTestId('agent-card-open-button');
    expect(open).toHaveAttribute(
      'href',
      'https://gw.example/mock-agent/.well-known/agent-card.json'
    );
    expect(open).toHaveAttribute('target', '_blank');
    expect(open).toHaveAttribute('rel', 'noopener noreferrer');
    const copy = screen.getByRole('button', { name: 'Copy the served card discovery URL' });
    expect(copy).toBe(screen.getByTestId('agent-card-url-copy-button'));
    fireEvent.click(copy);
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        'https://gw.example/mock-agent/.well-known/agent-card.json'
      )
    );
  });

  it('never links a served URL that is not http or https', async () => {
    await showBody(previewBody({ served_url: SCRIPT_URL }));
    expect(screen.queryByTestId('agent-card-open-button')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-served-url')).toHaveTextContent(SCRIPT_URL);
    for (const link of screen.queryAllByRole('link')) {
      expect(link.getAttribute('href')).not.toContain('javascript');
    }
  });

  it('has no URL buttons when no listener serves the card', async () => {
    await showBody(previewBody({ served_url: null }));
    expect(screen.queryByTestId('agent-card-open-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('agent-card-url-copy-button')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-served-url')).toHaveTextContent(
      'No listener serves this surface.'
    );
  });

  it('toggles the raw JSON of both cards and copies each one', async () => {
    await showBody(previewBody());
    const toggle = screen.getByTestId('agent-card-raw-toggle');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('agent-card-raw-before')).not.toBeInTheDocument();

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const before = screen.getByTestId('agent-card-raw-before');
    expect(JSON.parse(before.textContent ?? '')).toEqual(BEFORE_CARD);
    expect(before).toHaveAccessibleName('Managed Agent Card');
    const after = screen.getByTestId('agent-card-raw-after');
    expect(JSON.parse(after.textContent ?? '')).toEqual(AFTER_CARD);
    expect(after).toHaveAccessibleName('Gateway-Served Agent Card');

    fireEvent.click(screen.getByRole('button', { name: 'Copy the Managed Agent Card JSON' }));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        JSON.stringify(BEFORE_CARD, null, 2)
      )
    );
    fireEvent.click(screen.getByTestId('agent-card-copy-after-button'));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        JSON.stringify(AFTER_CARD, null, 2)
      )
    );

    fireEvent.click(toggle);
    expect(screen.queryByTestId('agent-card-raw-before')).not.toBeInTheDocument();
  });

  it('shows an error toast when the clipboard refuses', async () => {
    (navigator.clipboard.writeText as jest.Mock).mockRejectedValue(new Error('denied'));
    await showBody(previewBody());
    fireEvent.click(screen.getByTestId('agent-card-url-copy-button'));
    await waitFor(() =>
      expect(showToast).toHaveBeenCalledWith('error', 'Could not copy to the clipboard.')
    );
  });

  it('renders card content as text, never as markup or links', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const before = {
      ...BEFORE_CARD,
      name: hostile,
      iconUrl: SCRIPT_URL,
      documentationUrl: 'https://evil.example/phish',
      provider: { organization: '<b>bold</b>', url: 'https://evil.example/' },
    };
    const after = { ...AFTER_CARD, name: `${hostile} (gateway)`, iconUrl: SCRIPT_URL };
    mockFetch.mockResolvedValue(reply(200, previewBody({ before, after })));
    renderTab();
    await screen.findByTestId('agent-card-header');
    fireEvent.click(screen.getByTestId('agent-card-raw-toggle'));

    expect(screen.queryByRole('img')).not.toBeInTheDocument();
    expect(screen.queryByText('bold')).not.toBeInTheDocument();
    expect(screen.getByTestId('agent-card-row-other')).toHaveTextContent(hostile);
    expect(screen.getByTestId('agent-card-raw-before')).toHaveTextContent(hostile);
    expect(screen.getAllByRole('link').map(a => a.getAttribute('href'))).toEqual([
      'https://gw.example/mock-agent/.well-known/agent-card.json',
    ]);
  });
});
