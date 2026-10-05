import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import {
  DirectAccessSwitch,
  ExposureBadge,
  ManagedByBanner,
  SurfaceOnlyNotice,
  surfacesFronting,
} from '../exposure';

jest.mock('../../../api', () => ({ apiClient: { fetch: jest.fn() } }));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => true, loading: false }),
}));

describe('surfacesFronting', () => {
  const surfaces = [
    { surface_id: 's1', name: 'One', target: { endpoint: 'proxy://p1' } },
    { surface_id: 's2', name: 'Two', target: { endpoint: 'https://x', mcp_proxy_id: 'p1' } },
    { surface_id: 's3', name: 'Three', target: { endpoint: 'proxy://p10' } },
    { surface_id: 's4', target: { endpoint: 'proxy://p2' } },
  ];

  it('matches the proxy by endpoint or id, exactly', () => {
    expect(surfacesFronting(surfaces, 'p1').map(s => s.surface_id)).toEqual(['s1', 's2']);
  });

  it('falls back to the id when a surface has no name', () => {
    expect(surfacesFronting(surfaces, 'p2')).toEqual([{ surface_id: 's4', name: 's4' }]);
  });

  it('is empty when nothing targets the proxy', () => {
    expect(surfacesFronting(surfaces, 'nope')).toEqual([]);
  });
});

describe('DirectAccessSwitch', () => {
  it('warns while the open route is on and reports a change', () => {
    const onChange = jest.fn();
    render(<DirectAccessSwitch id="d" checked onChange={onChange} />);
    expect(screen.getByTestId('mcp-proxy-direct-warning')).toHaveTextContent('no sign-in');
    fireEvent.click(screen.getByTestId('mcp-proxy-direct-access'));
    expect(onChange).toHaveBeenCalledWith(false);
  });

  it('drops the warning once the proxy is surface-only', () => {
    render(<DirectAccessSwitch id="d" checked={false} onChange={jest.fn()} />);
    expect(screen.queryByTestId('mcp-proxy-direct-warning')).not.toBeInTheDocument();
    expect(screen.getByText(/Served only through surfaces/)).toBeInTheDocument();
  });
});

describe('SurfaceOnlyNotice', () => {
  it('links every surface fronting the proxy', () => {
    render(
      <MemoryRouter>
        <SurfaceOnlyNotice surfaces={[{ surface_id: 's 1', name: 'Front' }]} />
      </MemoryRouter>
    );
    expect(screen.getByRole('link', { name: 'Front' })).toHaveAttribute('href', '/surfaces/s%201');
  });

  it('says nothing can call a proxy no surface targets', () => {
    render(
      <MemoryRouter>
        <SurfaceOnlyNotice surfaces={[]} />
      </MemoryRouter>
    );
    expect(screen.getByText(/nothing can call it/)).toBeInTheDocument();
  });

  it('claims nothing about surfaces it could not list', () => {
    render(
      <MemoryRouter>
        <SurfaceOnlyNotice surfaces={null} />
      </MemoryRouter>
    );
    expect(screen.queryByText(/nothing can call it/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Fronted by/)).not.toBeInTheDocument();
  });
});

describe('labels', () => {
  it('names the managing product', () => {
    render(<ManagedByBanner managedBy="Boris" />);
    expect(screen.getByTestId('mcp-proxy-managed-by')).toHaveTextContent('Managed by Boris.');
  });

  it('shows how a proxy can be reached', () => {
    const { rerender } = render(<ExposureBadge directAccess />);
    expect(screen.getByText('Direct + surfaces')).toBeInTheDocument();
    rerender(<ExposureBadge directAccess={false} />);
    expect(screen.getByText('Surfaces only')).toBeInTheDocument();
  });
});
