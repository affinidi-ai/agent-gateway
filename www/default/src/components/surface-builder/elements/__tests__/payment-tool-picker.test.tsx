import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { apiClient } from '../../../../api';
import PaymentTriggersEditor from '../payment/PaymentTriggersEditor';
import {
  buildMcpTriggers,
  exactToolPattern,
  mcpSelectionCharged,
  selectedToolNames,
  setMcpSelectionCharged,
  setToolsSelected,
  storedMcpPatterns,
  toolCharge,
  toolFromExactPattern,
  uncheckedMcpPatterns,
} from '../payment/triggers';
import { mcpToolDiscoverySource } from '../_shared/mcpToolDiscovery';
import type { PaymentNodeConfig } from '../payment/types';
import type { CanvasNode } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { post: jest.fn() } }));

const mockPost = apiClient.post as jest.Mock;

const node: CanvasNode = { id: 'pay', type: 'payment', label: 'Payment', configured: true };

const targetNode = (config: Record<string, unknown>): CanvasNode => ({
  id: 'target',
  type: 'target',
  label: 'Target',
  configured: true,
  config,
});

const PROXY_TARGET = targetNode({ endpoint_type: 'mcp-proxy', mcp_proxy_id: 'billing' });
const LOCAL_TARGET = targetNode({ endpoint_type: 'url', endpoint: 'http://localhost:9000/mcp' });

const TOOLS = [
  { name: 'export.csv', description: 'Export rows' },
  { name: 'health_check' },
  { name: 'premium_search', description: 'Deep search', read_only: true },
];

let latest: PaymentNodeConfig = {};

const Harness: React.FC<{ initial?: PaymentNodeConfig; nodes?: CanvasNode[] }> = ({
  initial = {},
  nodes = [PROXY_TARGET],
}) => {
  const [config, setConfig] = useState<PaymentNodeConfig>(initial);
  latest = config;
  const apply = (fields: Record<string, unknown>) => setConfig(c => ({ ...c, ...fields }));
  return (
    <PaymentTriggersEditor
      node={node}
      config={config}
      updateField={(field, value) => apply({ [field]: value })}
      updateFields={apply}
      protocol="mcp"
      allNodes={[node, ...nodes]}
    />
  );
};

const SavedSurface: React.FC<{ nodes: CanvasNode[] }> = ({ nodes }) => (
  <MemoryRouter initialEntries={['/surfaces/s-1']}>
    <Routes>
      <Route path="/surfaces/:surfaceId" element={<Harness nodes={nodes} />} />
    </Routes>
  </MemoryRouter>
);

const discover = async () => {
  const button = screen.getByTestId('payment-triggers-mcp-discover-button');
  fireEvent.click(button);
  await waitFor(() => expect(button).toHaveTextContent('Refresh'));
};

beforeEach(() => {
  mockPost.mockReset();
  mockPost.mockResolvedValue({ data: { tools: TOOLS } });
  latest = {};
});

describe('exact tool patterns', () => {
  it.each(['health_check', 'export.csv', 'a+b(c)|[d]{e}^$\\', 'with-dash'])(
    'round-trips %s and matches only that name',
    name => {
      const pattern = exactToolPattern(name);
      expect(toolFromExactPattern(pattern)).toBe(name);
      expect(new RegExp(pattern).test(name)).toBe(true);
      expect(new RegExp(pattern).test(`${name}x`)).toBe(false);
    }
  );

  it.each(['^premium_', 'health_check', '^a.*$', '^$', '^a\\$', ' ^a$'])(
    'does not read %s as one tool',
    pattern => {
      expect(toolFromExactPattern(pattern)).toBeNull();
    }
  );
});

describe('toolCharge', () => {
  it('charges every tool while no trigger or Charge all is set', () => {
    expect(toolCharge(undefined, 'x')).toEqual({ charged: true });
    expect(toolCharge({ mode: 'all' }, 'x')).toEqual({ charged: true });
  });

  it('follows exact and custom patterns for match and exclude', () => {
    const match = { mode: 'match', patterns: ['^paid$', '^premium_'] };
    expect(toolCharge(match, 'paid')).toEqual({ charged: true });
    expect(toolCharge(match, 'premium_search')).toEqual({ charged: true, decidedBy: '^premium_' });
    expect(toolCharge(match, 'free')).toEqual({ charged: false });

    const exclude = { mode: 'exclude', patterns: ['^health_check$', 'debug'] };
    expect(toolCharge(exclude, 'health_check')).toEqual({ charged: false });
    expect(toolCharge(exclude, 'run_debug')).toEqual({ charged: false, decidedBy: 'debug' });
    expect(toolCharge(exclude, 'search')).toEqual({ charged: true });
  });

  it('ignores a pattern the browser cannot read the way the gateway does', () => {
    expect(toolCharge({ mode: 'match', patterns: ['(?i)^PAID'] }, 'paid')).toEqual({
      charged: false,
    });
    expect(uncheckedMcpPatterns({ mode: 'match', patterns: ['(?i)^PAID', '^ok$', 'x'] })).toEqual([
      '(?i)^PAID',
    ]);
    expect(uncheckedMcpPatterns({ mode: 'all' })).toEqual([]);
  });
});

describe('buildMcpTriggers', () => {
  it('saves a charged selection as Match, or All when empty, and a free one as Exclude', () => {
    expect(buildMcpTriggers(true, ['^a$'])).toEqual({ mode: 'match', patterns: ['^a$'] });
    expect(buildMcpTriggers(true, [])).toEqual({ mode: 'all' });
    expect(buildMcpTriggers(true, [''])).toEqual({ mode: 'match', patterns: [''] });
    expect(buildMcpTriggers(false, ['^a$'])).toEqual({ mode: 'exclude', patterns: ['^a$'] });
    expect(buildMcpTriggers(false, [])).toEqual({ mode: 'exclude', patterns: [] });
  });

  it('reads no trigger, All and Match as a charged selection and only Exclude as free', () => {
    expect(mcpSelectionCharged(undefined)).toBe(true);
    expect(mcpSelectionCharged({ mode: 'all' })).toBe(true);
    expect(mcpSelectionCharged({ mode: 'match', patterns: ['^a$'] })).toBe(true);
    expect(mcpSelectionCharged({ mode: 'exclude', patterns: [] })).toBe(false);
  });
});

describe('storedMcpPatterns and selectedToolNames', () => {
  it('list every stored row, blanks included, and the tools exact rows select', () => {
    const raw = { mode: 'exclude', patterns: ['^a$', '^debug_', '', '^b\\.c$', 7] };
    expect(storedMcpPatterns(raw)).toEqual(['^a$', '^debug_', '', '^b\\.c$']);
    expect(selectedToolNames(raw)).toEqual(['a', 'b.c']);
    expect(storedMcpPatterns({ mode: 'all' })).toEqual([]);
    expect(storedMcpPatterns(undefined)).toEqual([]);
  });
});

describe('setToolsSelected', () => {
  it('adds the exact pattern of each selected tool and keeps every other row', () => {
    expect(setToolsSelected({ mode: 'match', patterns: ['^premium_', ''] }, ['b.c'], true)).toEqual(
      {
        mode: 'match',
        patterns: ['^premium_', '', '^b\\.c$'],
      }
    );
    expect(setToolsSelected(undefined, ['a', 'b'], true)).toEqual({
      mode: 'match',
      patterns: ['^a$', '^b$'],
    });
    expect(setToolsSelected({ mode: 'exclude', patterns: [] }, ['a'], true)).toEqual({
      mode: 'exclude',
      patterns: ['^a$'],
    });
    expect(setToolsSelected({ mode: 'match', patterns: ['^a$'] }, ['a'], true)).toEqual({
      mode: 'match',
      patterns: ['^a$'],
    });
  });

  it('removes only the exact patterns of cleared tools', () => {
    expect(
      setToolsSelected({ mode: 'match', patterns: ['^a$', '^premium_', '^b$'] }, ['a'], false)
    ).toEqual({ mode: 'match', patterns: ['^premium_', '^b$'] });
    expect(setToolsSelected({ mode: 'match', patterns: ['^a$'] }, ['a'], false)).toEqual({
      mode: 'all',
    });
    expect(setToolsSelected({ mode: 'exclude', patterns: ['^a$'] }, ['a'], false)).toEqual({
      mode: 'exclude',
      patterns: [],
    });
    expect(setToolsSelected({ mode: 'all' }, ['a'], false)).toEqual({ mode: 'all' });
  });
});

describe('setMcpSelectionCharged', () => {
  it('keeps the patterns and changes only what they mean', () => {
    const exclude = { mode: 'exclude', patterns: ['^a$', '^debug_'] };
    expect(setMcpSelectionCharged(exclude, true)).toEqual({
      mode: 'match',
      patterns: ['^a$', '^debug_'],
    });
    expect(setMcpSelectionCharged({ mode: 'match', patterns: ['^a$'] }, false)).toEqual({
      mode: 'exclude',
      patterns: ['^a$'],
    });
    expect(setMcpSelectionCharged({ mode: 'all' }, false)).toEqual({
      mode: 'exclude',
      patterns: [],
    });
    expect(setMcpSelectionCharged({ mode: 'exclude', patterns: [] }, true)).toEqual({
      mode: 'all',
    });
  });
});

describe('mcpToolDiscoverySource', () => {
  it('asks an MCP Proxy Target by id', () => {
    expect(mcpToolDiscoverySource({ endpoint_type: 'mcp-proxy', mcp_proxy_id: ' p1 ' })).toEqual({
      request: { mcp_proxy_id: 'p1' },
      label: 'MCP Proxy p1',
    });
    expect(mcpToolDiscoverySource({ endpoint: 'proxy://p2' })).toEqual({
      request: { mcp_proxy_id: 'p2' },
      label: 'MCP Proxy p2',
    });
  });

  it('asks a Direct URL Target with its auth secret reference, never a secret value', () => {
    expect(
      mcpToolDiscoverySource({
        endpoint_type: 'url',
        endpoint: 'https://tools.example/mcp',
        target_auth_enabled: true,
        target_auth_secret_id: 'tools-key',
        target_auth_header_name: 'X-API-Key',
      })
    ).toEqual({
      request: {
        target_endpoint: 'https://tools.example/mcp',
        target_auth: {
          enabled: true,
          method: 'static_secret',
          secret_id: 'tools-key',
          header_name: 'X-API-Key',
          header_format: '{value}',
          fallback: 'reject',
        },
      },
      label: 'https://tools.example/mcp',
    });
    expect(
      mcpToolDiscoverySource({ endpoint: 'https://t.example', target_auth_enabled: false })
    ).toEqual({ request: { target_endpoint: 'https://t.example' }, label: 'https://t.example' });
  });

  it("asks a saved surface's Direct URL Target by surface id, and a proxy by its id", () => {
    expect(mcpToolDiscoverySource({ endpoint: ' http://localhost:9000/mcp ' }, 's-1')).toEqual({
      request: { surface_id: 's-1', target_endpoint: 'http://localhost:9000/mcp' },
      label: 'http://localhost:9000/mcp',
    });
    expect(
      mcpToolDiscoverySource({ endpoint_type: 'mcp-proxy', mcp_proxy_id: 'p1' }, 's-1')
    ).toEqual({ request: { mcp_proxy_id: 'p1' }, label: 'MCP Proxy p1' });
    expect(mcpToolDiscoverySource({ endpoint: 'fabric://gw/surface' }, 's-1')).toEqual({
      unavailable:
        'Tools cannot be discovered through a gateway connection. Enter patterns instead.',
    });
  });

  it.each([
    [{ endpoint_type: 'gateway', gateway_id: 'g' }, 'through a gateway connection'],
    [{ endpoint: 'fabric://gw/surface' }, 'through a gateway connection'],
    [{ endpoint_type: 'mcp-proxy' }, 'Choose the MCP Proxy'],
    [{ endpoint: '  ' }, 'Set the Target endpoint first.'],
    [undefined, 'Set the Target endpoint first.'],
    [{ endpoint_type: 'a2a-proxy' }, 'Direct URL or MCP Proxy'],
  ])('says why %j cannot be asked', (target, reason) => {
    const source = mcpToolDiscoverySource(target);
    expect('unavailable' in source && source.unavailable).toContain(reason);
  });
});

describe('PaymentTriggersEditor — MCP tool picker', () => {
  it('discovers tools only when asked and lists them with their charge', async () => {
    render(<Harness />);
    expect(mockPost).not.toHaveBeenCalled();

    await discover();
    expect(mockPost).toHaveBeenCalledWith('/mcp-proxies/discover-tools', {
      mcp_proxy_id: 'billing',
    });
    expect(screen.getByTestId('payment-triggers-mcp-tool-count')).toHaveTextContent(
      '0 selected · 3 of 3 charged'
    );
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-premium_search')).toHaveTextContent(
      'read-only'
    );
    expect(screen.getByText('Deep search')).toBeInTheDocument();
    expect(screen.getByTestId('payment-triggers-mcp-tool-health_check')).not.toBeChecked();
    expect(screen.getByTestId('payment-triggers-mcp-selection-charged-button')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(screen.getByTestId('payment-triggers-mcp-others')).toHaveTextContent(
      'Nothing is selected yet, so every tool is charged.'
    );
    expect(latest).toEqual({});
  });

  it('adds a selected tool to the patterns and removes it when cleared', async () => {
    render(
      <Harness initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] } }} />
    );
    await discover();

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-export.csv'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^premium_', '^export\\.csv$'],
    });
    expect(screen.getByTestId('payment-triggers-mcp-pattern-1')).toHaveValue('^export\\.csv$');
    expect(screen.getByTestId('payment-triggers-mcp-tool-export.csv')).toBeChecked();
    expect(screen.getByTestId('payment-triggers-mcp-tool-count')).toHaveTextContent(
      '1 selected · 2 of 3 charged'
    );

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-export.csv'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['^premium_'] });
    expect(screen.queryByTestId('payment-triggers-mcp-pattern-1')).not.toBeInTheDocument();
  });

  it('clears a tool when its pattern row is removed or edited', async () => {
    render(
      <Harness
        initial={{
          mcp_payment_triggers: { mode: 'match', patterns: ['^health_check$', '^ping$'] },
        }}
      />
    );
    await discover();
    expect(screen.getByTestId('payment-triggers-mcp-tool-health_check')).toBeChecked();

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-remove-pattern-button-0'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['^ping$'] });
    expect(screen.getByTestId('payment-triggers-mcp-tool-health_check')).not.toBeChecked();

    fireEvent.change(screen.getByTestId('payment-triggers-mcp-pattern-0'), {
      target: { value: '^premium_search$' },
    });
    expect(screen.getByTestId('payment-triggers-mcp-tool-premium_search')).toBeChecked();

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-remove-pattern-button-0'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
    expect(screen.getByTestId('payment-triggers-mcp-add-pattern-button')).toBeInTheDocument();
  });

  it('charges a selected tool and frees the rest, and clearing it charges every tool again', async () => {
    render(<Harness />);
    await discover();

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-health_check'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['^health_check$'] });
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-health_check')).toHaveTextContent(
      'charged'
    );
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-export.csv')).toHaveTextContent(
      'free'
    );
    expect(screen.getByTestId('payment-triggers-mcp-others')).toHaveTextContent(
      'Every other tool, including tools the Target adds later, is free.'
    );

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-health_check'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
  });

  it('frees a selected tool while the selection is free, and charges every other tool', async () => {
    render(<Harness initial={{ mcp_payment_triggers: { mode: 'exclude', patterns: [] } }} />);
    await discover();
    expect(screen.getByTestId('payment-triggers-mcp-selection-free-button')).toHaveAttribute(
      'aria-pressed',
      'true'
    );

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-health_check'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'exclude', patterns: ['^health_check$'] });
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-health_check')).toHaveTextContent(
      'free'
    );
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-export.csv')).toHaveTextContent(
      'charged'
    );
  });

  it('switches what the selection means without changing the patterns', async () => {
    render(
      <Harness initial={{ mcp_payment_triggers: { mode: 'exclude', patterns: ['^ping$'] } }} />
    );
    await discover();

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-selection-charged-button'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['^ping$'] });
    expect(screen.getByTestId('payment-triggers-mcp-selection-charged-button')).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    expect(screen.getByTestId('payment-triggers-mcp-tool-ping')).toBeChecked();
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-ping')).toHaveTextContent('charged');
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-health_check')).toHaveTextContent(
      'free'
    );
    expect(screen.getByTestId('payment-triggers-mcp-patterns')).toHaveTextContent(
      'A tool whose name matches a pattern is charged.'
    );
  });

  it('selects and clears every tool with the buttons and the select-all box', async () => {
    render(
      <Harness
        initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['^health_check$'] } }}
      />
    );
    await discover();
    const selectAll = screen.getByTestId('payment-triggers-mcp-select-all') as HTMLInputElement;
    expect(selectAll.indeterminate).toBe(true);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-select-all-button'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^health_check$', '^export\\.csv$', '^premium_search$'],
    });
    expect(selectAll).toBeChecked();
    expect(selectAll.indeterminate).toBe(false);

    fireEvent.click(selectAll);
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
    expect(screen.getByTestId('payment-triggers-mcp-clear-button')).toBeDisabled();

    fireEvent.click(selectAll);
    fireEvent.click(screen.getByTestId('payment-triggers-mcp-clear-button'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
  });

  it('applies select and clear only to the tools the filter shows', async () => {
    render(<Harness />);
    await discover();

    fireEvent.change(screen.getByTestId('payment-triggers-mcp-tool-filter'), {
      target: { value: 'SEARCH' },
    });
    expect(
      screen.queryByTestId('payment-triggers-mcp-tool-row-health_check')
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-triggers-mcp-select-all-button')).toHaveTextContent(
      'Select shown'
    );
    fireEvent.click(screen.getByTestId('payment-triggers-mcp-select-all-button'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^premium_search$'],
    });
  });

  it('shows a tool a pattern matches as ticked and leaves it out of select all', async () => {
    render(
      <Harness initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['^premium_'] } }} />
    );
    await discover();

    const box = screen.getByTestId('payment-triggers-mcp-tool-premium_search');
    expect(box).toBeChecked();
    expect(box).toBeDisabled();
    expect(screen.getByTestId('payment-triggers-mcp-tool-row-premium_search')).toHaveTextContent(
      'Matched by the pattern ^premium_'
    );

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-select-all-button'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^premium_', '^export\\.csv$', '^health_check$'],
    });
  });

  it('adds a tool by name to the patterns', () => {
    render(<Harness nodes={[targetNode({ endpoint_type: 'gateway', gateway_id: 'g' })]} />);

    expect(screen.getByTestId('payment-triggers-mcp-add-tool-button')).toBeDisabled();
    fireEvent.change(screen.getByTestId('payment-triggers-mcp-add-tool-input'), {
      target: { value: ' health_check ' },
    });
    fireEvent.click(screen.getByTestId('payment-triggers-mcp-add-tool-button'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^health_check$'],
    });
    expect(screen.getByTestId('payment-triggers-mcp-add-tool-input')).toHaveValue('');
    expect(screen.getByTestId('payment-triggers-mcp-tool-health_check')).toBeChecked();
    expect(screen.getByTestId('payment-triggers-mcp-pattern-0')).toHaveValue('^health_check$');

    fireEvent.change(screen.getByTestId('payment-triggers-mcp-add-tool-input'), {
      target: { value: 'ping' },
    });
    fireEvent.keyDown(screen.getByTestId('payment-triggers-mcp-add-tool-input'), { key: 'Enter' });
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'match',
      patterns: ['^health_check$', '^ping$'],
    });
  });

  it('warns at once when a charged selection has only a blank row', () => {
    render(<Harness />);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-add-pattern-button'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: [''] });
    expect(screen.getByTestId('payment-triggers-mcp-none-charged')).toHaveTextContent(
      'No tool is charged: the pattern list has only blank rows.'
    );

    fireEvent.change(screen.getByTestId('payment-triggers-mcp-pattern-0'), {
      target: { value: '^paid_' },
    });
    expect(screen.queryByTestId('payment-triggers-mcp-none-charged')).not.toBeInTheDocument();
  });

  it('badges a selected tool the Target no longer lists, and clearing it removes its row', async () => {
    render(
      <Harness
        initial={{
          mcp_payment_triggers: { mode: 'exclude', patterns: ['^gone$', '^health_check$'] },
        }}
      />
    );
    expect(screen.queryByTestId('payment-triggers-mcp-tool-missing-gone')).not.toBeInTheDocument();
    await discover();

    expect(screen.getByTestId('payment-triggers-mcp-tool-missing-gone')).toHaveTextContent(
      'not on the Target'
    );
    fireEvent.click(screen.getByTestId('payment-triggers-mcp-tool-gone'));
    expect(latest.mcp_payment_triggers).toEqual({
      mode: 'exclude',
      patterns: ['^health_check$'],
    });
    expect(screen.queryByTestId('payment-triggers-mcp-tool-row-gone')).not.toBeInTheDocument();
  });

  it('shows the gateway error and keeps the config unchanged', async () => {
    mockPost.mockRejectedValue(new Error('Insufficient permissions'));
    render(<Harness initial={{ mcp_payment_triggers: { mode: 'all' } }} />);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-discover-button'));
    expect(await screen.findByTestId('payment-triggers-mcp-discover-error')).toHaveTextContent(
      'Insufficient permissions'
    );
    expect(screen.queryByTestId('payment-triggers-mcp-tool-filter')).not.toBeInTheDocument();
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
  });

  it("discovers a saved surface's local Target through the surface", async () => {
    render(<SavedSurface nodes={[LOCAL_TARGET]} />);
    await discover();

    expect(mockPost).toHaveBeenCalledWith('/mcp-proxies/discover-tools', {
      surface_id: 's-1',
      target_endpoint: 'http://localhost:9000/mcp',
    });
  });

  it('says a local Target of an unsaved surface can be discovered once saved', async () => {
    mockPost.mockRejectedValue(new Error('Invalid MCP target endpoint'));
    render(<Harness nodes={[LOCAL_TARGET]} />);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-discover-button'));
    expect(await screen.findByTestId('payment-triggers-mcp-discover-save-hint')).toHaveTextContent(
      'A local or private Target can be discovered once the surface is saved.'
    );
    expect(mockPost).toHaveBeenCalledWith('/mcp-proxies/discover-tools', {
      target_endpoint: 'http://localhost:9000/mcp',
    });
  });

  it('gives no save hint once the surface is saved', async () => {
    mockPost.mockRejectedValue(new Error('The Target differs from the saved surface.'));
    render(<SavedSurface nodes={[LOCAL_TARGET]} />);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-discover-button'));
    expect(await screen.findByTestId('payment-triggers-mcp-discover-error')).toHaveTextContent(
      'The Target differs from the saved surface.'
    );
    expect(screen.queryByTestId('payment-triggers-mcp-discover-save-hint')).not.toBeInTheDocument();
  });

  it('says when the Target lists no tools', async () => {
    mockPost.mockResolvedValue({ data: { tools: [] } });
    render(<Harness />);

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-discover-button'));
    expect(await screen.findByTestId('payment-triggers-mcp-no-tools')).toBeInTheDocument();
  });

  it('offers no discovery for a gateway Target, leaving patterns editable', async () => {
    render(<Harness nodes={[targetNode({ endpoint_type: 'gateway', gateway_id: 'g' })]} />);

    expect(screen.getByTestId('payment-triggers-mcp-discover-button')).toBeDisabled();
    expect(screen.getByTestId('payment-triggers-mcp-discover-unavailable')).toHaveTextContent(
      'Tools cannot be discovered through a gateway connection.'
    );
    await waitFor(() => expect(mockPost).not.toHaveBeenCalled());
  });
});
