import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { registry } from '../index';
import type { PayloadContext } from '../types';
import AccessPointPanel, {
  CLOSE_ACCESS_POINT_LABEL,
  CLOSING_ACCESS_POINT_TEXT,
  LEGACY_ACCESS_POINT_TEXT,
} from '../access-point/AccessPointPanel';
import { SurfaceMetaProvider } from '../../SurfaceMetaContext';
import { nodesFromSurface } from '../../nodesFromSurface';
import { showSurfaceSaveToast } from '../saveWarnings';
import { withCallerAccessSettled } from '../access-point/publicAccess';
import { showToast } from '../../../../utils/toaster';
import type { AgentSurface } from '../../../../api';

// The Public access switch is the URL banner's footer, so the stub renders only that.
jest.mock(
  '../_shared/RouteListenerSection',
  () =>
    ({ bannerFooter }: { bannerFooter?: unknown }) =>
      bannerFooter ?? null
);
jest.mock('../../../../utils/toaster', () => ({
  ...jest.requireActual('../../../../utils/toaster'),
  showToast: jest.fn(),
}));

const toast = showToast as jest.Mock;

const PUBLIC_MESSAGE =
  'This Access Point is public. Anyone who can reach it can call your agent without credentials.';

function makeCtx(nodes: any[]): PayloadContext {
  return {
    protocol: 'mcp',
    surfaceMeta: { name: 'orders', tags: [], status: 'active', surface_id: 'srf-1' },
    allNodes: nodes,
    nodesOfType: type => nodes.filter(n => n.type === type),
    firstNodeOfType: type => nodes.find(n => n.type === type),
  };
}

function storedSurface(
  accessPoint: Record<string, unknown>,
  canvasApConfig?: object
): AgentSurface {
  return {
    surface_id: 'srf-1',
    name: 'orders',
    description: '',
    status: 'active',
    tags: [],
    access_point: {
      listen_address: 'https://gw.example',
      route: '/agents/orders',
      protocol: 'mcp',
      ...accessPoint,
    },
    target: { endpoint: 'https://agent.example' },
    ...(canvasApConfig
      ? {
          canvas: {
            nodes: [{ id: 'access-point', type: 'access-point', config: canvasApConfig }],
          },
        }
      : {}),
  } as unknown as AgentSurface;
}

const roundTrip = (surface: AgentSurface): any =>
  (registry.buildPayload(makeCtx(nodesFromSurface(surface))) as any).access_point;

const API_KEY_AUTH = {
  methods: [
    {
      type: 'api_key',
      extraction: { source: 'http_header', field: 'X-Api-Key' },
      secret_id: 'sec-1',
    },
  ],
};

describe('Access Point public access and caller auth on_failure round trip', () => {
  it('keeps public and on_failure on a surface created closed', () => {
    const ap = roundTrip(
      storedSurface({
        public: false,
        caller_authentication: { ...API_KEY_AUTH, on_failure: 'reject' },
      })
    );
    expect(ap.public).toBe(false);
    expect(ap.caller_authentication).toEqual({ ...API_KEY_AUTH, on_failure: 'reject' });
  });

  it('keeps public: true', () => {
    expect(roundTrip(storedSurface({ public: true })).public).toBe(true);
  });

  it('adds neither field to a surface stored without them, even with a stale canvas copy', () => {
    const ap = roundTrip(
      storedSurface(
        { caller_authentication: API_KEY_AUTH },
        { route: '/agents/orders', public: true }
      )
    );
    expect(ap).not.toHaveProperty('public');
    expect(ap.caller_authentication).toEqual(API_KEY_AUTH);
  });
});

describe('AccessPointPanel Public access switch', () => {
  const props = (config: Record<string, unknown>, updateField = jest.fn()) =>
    ({
      node: {
        id: 'access-point',
        type: 'access-point',
        label: 'Access Point',
        configured: true,
        config,
      },
      config,
      updateField,
      updateFields: jest.fn(),
      protocol: 'mcp',
      allNodes: [],
    }) as any;

  it('is off by default and writes access_point.public', () => {
    const updateField = jest.fn();
    render(<AccessPointPanel {...props({}, updateField)} />);

    const sw = screen.getByTestId('access-point-public-switch');
    expect(sw).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: /^Public access/ })).toBe(sw);
    expect(screen.queryByTestId('access-point-public-warning')).not.toBeInTheDocument();

    fireEvent.click(sw);
    expect(updateField).toHaveBeenCalledWith('public', true);
  });

  it('has no Access heading above the switch', () => {
    render(<AccessPointPanel {...props({})} />);
    expect(screen.queryByText(/^Access$/)).not.toBeInTheDocument();
    expect(screen.getByTestId('access-point-public-switch')).toBeInTheDocument();
  });

  it('shows the warning while on and can be turned off', () => {
    const updateField = jest.fn();
    render(<AccessPointPanel {...props({ public: true }, updateField)} />);

    expect(screen.getByTestId('access-point-public-warning')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('access-point-public-switch'));
    expect(updateField).toHaveBeenCalledWith('public', false);
  });

  describe('on a surface stored without public', () => {
    const showLegacyPanel = (config: Record<string, unknown>, readOnly = false) => {
      const updateField = jest.fn();
      render(
        <SurfaceMetaProvider value={{ legacyAccessPoint: true, readOnly } as any}>
          <AccessPointPanel {...props(config, updateField)} />
        </SurfaceMetaProvider>
      );
      return updateField;
    };

    it('shows the legacy state and closes the Access Point on request', () => {
      const updateField = showLegacyPanel({});

      expect(screen.getByTestId('access-point-public-switch')).not.toBeChecked();
      expect(screen.getByTestId('access-point-legacy-notice')).toHaveTextContent(
        LEGACY_ACCESS_POINT_TEXT
      );
      fireEvent.click(screen.getByRole('button', { name: CLOSE_ACCESS_POINT_LABEL }));
      expect(updateField).toHaveBeenCalledWith('public', false);
    });

    it('offers no close action when read-only', () => {
      showLegacyPanel({}, true);
      expect(screen.getByTestId('access-point-legacy-notice')).toBeInTheDocument();
      expect(screen.queryByTestId('access-point-close-button')).not.toBeInTheDocument();
    });

    it('says it will be closed once the operator closes it', () => {
      showLegacyPanel({ public: false });
      expect(screen.queryByTestId('access-point-legacy-notice')).not.toBeInTheDocument();
      expect(screen.getByTestId('access-point-closing-notice')).toHaveTextContent(
        CLOSING_ACCESS_POINT_TEXT
      );
    });

    it('returns to the legacy state when Public access is turned off', () => {
      const updateField = showLegacyPanel({ public: true });
      fireEvent.click(screen.getByTestId('access-point-public-switch'));
      expect(updateField).toHaveBeenCalledWith('public', undefined);
    });
  });

  it('shows no legacy state on a closed or new surface', () => {
    render(<AccessPointPanel {...props({})} />);
    expect(screen.queryByTestId('access-point-legacy-notice')).not.toBeInTheDocument();
  });

  it('writes the field into the payload once set', () => {
    const nodes = [
      { id: 'access-point', type: 'access-point', config: { route: '/a', public: true } },
    ];
    expect((registry.buildPayload(makeCtx(nodes)) as any).access_point.public).toBe(true);
  });
});

describe('withCallerAccessSettled', () => {
  const legacy = storedSurface({ caller_authentication: API_KEY_AUTH });

  // The loaded surface with the Access Point's `public` set on the canvas.
  const withPublic = (stored: AgentSurface, value: boolean | undefined): any => {
    const nodes = nodesFromSurface(stored).map(n =>
      n.id === 'access-point' ? { ...n, config: { ...n.config, public: value } } : n
    );
    return withCallerAccessSettled(registry.buildPayload(makeCtx(nodes)) as any).access_point;
  };

  it('sends no public for a surface stored without it until the operator sets it', () => {
    expect(withPublic(legacy, undefined)).not.toHaveProperty('public');
  });

  it('sends public: false once the operator closes a surface stored without it', () => {
    const ap = withPublic(legacy, false);
    expect(ap.public).toBe(false);
    expect(ap.caller_authentication).toEqual(API_KEY_AUTH);
  });

  it('leaves out on_failure once public is sent, so the gateway derives it', () => {
    const payload = {
      access_point: {
        public: true,
        caller_authentication: { ...API_KEY_AUTH, on_failure: 'reject' },
      },
      variants: [
        {
          id: 'v1',
          alias: 'beta',
          name: 'Beta',
          overrides: {
            access_point: { caller_authentication: { ...API_KEY_AUTH, on_failure: 'reject' } },
          },
        },
      ],
    } as unknown as Partial<AgentSurface>;
    const settled = withCallerAccessSettled(payload);
    expect(settled.access_point?.caller_authentication).toEqual(API_KEY_AUTH);
    expect(settled.variants?.[0].overrides.access_point.caller_authentication).toEqual(
      API_KEY_AUTH
    );
  });

  it('keeps on_failure on a surface stored without public that sends none', () => {
    const ap = withCallerAccessSettled({
      access_point: { caller_authentication: { ...API_KEY_AUTH, on_failure: 'continue' } },
    } as unknown as Partial<AgentSurface>).access_point;
    expect(ap?.caller_authentication?.on_failure).toBe('continue');
  });
});

describe('showSurfaceSaveToast', () => {
  beforeEach(() => toast.mockReset());

  it("shows the save response's Warning headers, each once", () => {
    const saved = storedSurface({ public: true, caller_authentication: API_KEY_AUTH });
    showSurfaceSaveToast('Saved', saved, { headerWarnings: [PUBLIC_MESSAGE, PUBLIC_MESSAGE] });

    expect(toast.mock.calls).toEqual([
      ['warning', `Saved, with warnings:\n${PUBLIC_MESSAGE}`, expect.anything()],
    ]);
  });

  it('adds no public warning of its own', () => {
    showSurfaceSaveToast('Saved', storedSurface({ public: true }));
    expect(toast.mock.calls).toEqual([['success', 'Saved']]);
  });

  it('leaves the warning about a stored surface with no Caller Context to the gateway', () => {
    showSurfaceSaveToast('Saved', storedSurface({}));
    expect(toast.mock.calls).toEqual([['success', 'Saved']]);
  });

  it('shows every Warning header in one toast, in order', () => {
    showSurfaceSaveToast(
      'Saved',
      storedSurface({ public: true, caller_authentication: API_KEY_AUTH }),
      {
        headerWarnings: ['from the gateway', PUBLIC_MESSAGE],
      }
    );
    expect(toast).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(
      'warning',
      `Saved, with warnings:\nfrom the gateway\n${PUBLIC_MESSAGE}`,
      expect.anything()
    );
  });

  it('shows success alone for a closed surface with a Caller Context', () => {
    showSurfaceSaveToast(
      'Saved',
      storedSurface({ public: false, caller_authentication: API_KEY_AUTH })
    );
    expect(toast).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith('success', 'Saved');
  });
});
