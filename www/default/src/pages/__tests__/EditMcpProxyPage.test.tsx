import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
import EditMcpProxyPage from '../EditMcpProxyPage';
import { apiClient } from '../../api';

jest.mock('../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => false, loading: false }),
}));
jest.mock(
  '../EditMcpProxyPage/tabs/OverviewTab',
  () =>
    ({ handleChange }: { handleChange: React.ChangeEventHandler<HTMLInputElement> }) => (
      <input aria-label="Description" name="description" onChange={handleChange} />
    )
);
jest.mock('../EditMcpProxyPage/tabs/RoutingTab', () => () => null);
jest.mock('../EditMcpProxyPage/tabs/RestApiTab', () => () => null);
jest.mock('../../components/McpSandbox', () => () => null);

const mockGet = apiClient.get as jest.Mock;
const mockPut = apiClient.put as jest.Mock;
const mockFetch = apiClient.fetch as jest.Mock;

const proxy = (id: string) => ({
  id,
  name: `Proxy ${id}`,
  description: '',
  channel_prefix: '/mcp',
  base_url: 'https://api.example',
  openapi_spec: 'openapi: 3.1.0',
  status: 'active',
  endpoint_path: `/${id}`,
  flatten_post_params: false,
  created_at: '',
  updated_at: '',
});

const WARNING =
  'OpenAPI spec is unavailable to the MCP 2024-11-05 tool catalog, so 2024-11-05 clients cannot use this proxy: bad $ref';

const OpenOther: React.FC = () => {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/proxies/mcp-proxies/p2')}>open p2</button>;
};

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/proxies/mcp-proxies/p1']}>
      <OpenOther />
      <Routes>
        <Route path="/proxies/mcp-proxies/:id" element={<EditMcpProxyPage />} />
      </Routes>
    </MemoryRouter>
  );

const save = async (description: string) => {
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: description } });
  fireEvent.click(screen.getByRole('button', { name: /Save/ }));
  await waitFor(() => expect(screen.getByRole('button', { name: /Save/ })).toBeDisabled());
};

describe('EditMcpProxyPage write warnings', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFetch.mockResolvedValue({ ok: false });
    mockGet.mockImplementation((url: string) =>
      Promise.resolve({ data: proxy(url.split('/').pop() as string) })
    );
  });

  it('shows the warnings a save returns and clears them on the next clean save', async () => {
    renderPage();
    await screen.findByText('Edit MCP Proxy: Proxy p1');
    expect(screen.queryByTestId('mcp-proxy-write-warnings')).not.toBeInTheDocument();

    mockPut.mockResolvedValueOnce({ data: { ...proxy('p1'), warnings: [WARNING] } });
    await save('first');
    expect(mockPut).toHaveBeenCalledWith('/mcp-proxies/p1', expect.anything());
    expect(await screen.findByTestId('mcp-proxy-write-warnings')).toHaveTextContent(WARNING);

    mockPut.mockResolvedValueOnce({ data: proxy('p1') });
    await save('second');
    await waitFor(() =>
      expect(screen.queryByTestId('mcp-proxy-write-warnings')).not.toBeInTheDocument()
    );
  });

  it('drops the warnings when another proxy opens in the same editor', async () => {
    renderPage();
    await screen.findByText('Edit MCP Proxy: Proxy p1');
    mockPut.mockResolvedValueOnce({ data: { ...proxy('p1'), warnings: [WARNING] } });
    await save('first');
    expect(await screen.findByTestId('mcp-proxy-write-warnings')).toBeInTheDocument();

    fireEvent.click(screen.getByText('open p2'));
    await screen.findByText('Edit MCP Proxy: Proxy p2');
    expect(screen.queryByTestId('mcp-proxy-write-warnings')).not.toBeInTheDocument();
  });
});
