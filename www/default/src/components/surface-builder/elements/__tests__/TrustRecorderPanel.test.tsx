import React from 'react';
import { act, render, screen, waitFor, within, fireEvent } from '@testing-library/react';
import TrustRecorderPanel from '../trust-recorder/TrustRecorderPanel';
import { getIssuers } from '../../../../utils/issuersCache';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import { SURFACE_ISSUER_DID_TEMPLATE } from '../trust-recorder/definition';

const flushPromises = () => act(() => new Promise<void>(resolve => setTimeout(resolve, 0)));

jest.mock('../../../../utils/issuersCache', () => ({ getIssuers: jest.fn() }));
const getIssuersMock = getIssuers as jest.Mock;

const AP_SLOT = 'response:trust-recorder';

function baseProps(config: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'tr-1',
      type: 'trust-recorder',
      label: '',
      configured: true,
      config,
      parentId: 'access-point',
      slotId: AP_SLOT,
    } as any,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    openFullscreenEditor: jest.fn(),
  };
}

describe('TrustRecorderPanel — sidebar context block', () => {
  it('renders the collapsible context block collapsed by default', () => {
    render(<TrustRecorderPanel {...(baseProps() as any)} />);

    const ctx = screen.getByTestId('trust-recorder-panel-context');
    expect(ctx).toBeInTheDocument();
    expect(within(ctx).getByText(/managed agents discoverable/i)).toBeInTheDocument();

    // Body is absent because the block is collapsed by default.
    expect(screen.queryByTestId('trust-recorder-panel-context-body')).toBeNull();

    const toggle = screen.getByTestId('trust-recorder-panel-context-toggle');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
  });

  it('expands the body when the toggle is clicked, keeping the title visible', () => {
    render(<TrustRecorderPanel {...(baseProps() as any)} />);

    const toggle = screen.getByTestId('trust-recorder-panel-context-toggle');
    fireEvent.click(toggle);

    // Body visible after expand.
    expect(screen.getByTestId('trust-recorder-panel-context-body')).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'true');

    // Title row stays.
    expect(screen.getByText(/managed agents discoverable/i)).toBeInTheDocument();
  });

  it('renders an empty state when no entries are configured', () => {
    render(<TrustRecorderPanel {...(baseProps() as any)} />);

    const empty = screen.getByTestId('trust-recorder-panel-empty-state');
    expect(empty).toBeInTheDocument();
    expect(within(empty).getByText(/No registries yet/i)).toBeInTheDocument();
  });

  it('renders the entries list preview when entries exist', () => {
    const props = baseProps({
      entries: [
        {
          trust_registry_id: 'tr-a',
          issuer_did: 'did:key:z6Mkw...',
          authority_did: 'did:key:z6MkAuth...',
          include_owned_agent: true,
          custom_resources: [],
        },
      ],
    });
    render(<TrustRecorderPanel {...(props as any)} />);

    expect(screen.getByTestId('trust-recorder-panel-list')).toBeInTheDocument();
    expect(screen.queryByTestId('trust-recorder-panel-empty-state')).toBeNull();
  });

  it('renders the Configure button as a solid primary AppButton with 8px top margin', () => {
    render(<TrustRecorderPanel {...(baseProps() as any)} />);

    const button = screen.getByTestId('trust-recorder-panel-configure');
    expect(button).toBeInTheDocument();
    // Solid primary variant (AppButton with variant="primary" renders `btn-primary`).
    expect(button).toHaveClass('btn-primary');
    expect(button).not.toHaveClass('btn-outline-primary');
    // Full width + 8px top margin (Bootstrap `w-100 mt-2`).
    expect(button).toHaveClass('w-100');
    expect(button).toHaveClass('mt-2');
    // AppButton marker class.
    expect(button).toHaveClass('app-button');
  });

  it('opens the fullscreen editor when the Configure button is clicked', () => {
    const props = baseProps();
    render(<TrustRecorderPanel {...(props as any)} />);

    fireEvent.click(screen.getByTestId('trust-recorder-panel-configure'));
    expect(props.openFullscreenEditor).toHaveBeenCalledTimes(1);
  });
});

describe('TrustRecorderPanel — surface Issuer warning', () => {
  const WARNING = 'trust-recorder-panel-no-surface-issuer-warning';

  beforeEach(() => {
    getIssuersMock.mockReset();
    getIssuersMock.mockResolvedValue([{ id: 'issuer-1' }]);
  });

  function entry(authority_did: string) {
    return {
      trust_registry_id: 'tr-1',
      issuer_did: 'did:web:issuer.example',
      authority_did,
      include_owned_agent: true,
      custom_resources: [],
    };
  }

  function renderWithSurface(config: Record<string, unknown>, issuerId?: string) {
    const meta = { issuerId } as unknown as SurfaceMetaValue;
    const props = baseProps(config) as any;
    return render(
      issuerId === undefined ? (
        <TrustRecorderPanel {...props} />
      ) : (
        <SurfaceMetaProvider value={meta}>
          <TrustRecorderPanel {...props} />
        </SurfaceMetaProvider>
      )
    );
  }

  async function settled() {
    await waitFor(() => expect(getIssuersMock).toHaveBeenCalled());
    await flushPromises();
  }

  it('warns that records are skipped when an entry uses the surface Issuer and none is selected', () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, '');

    const warning = screen.getByTestId(WARNING);
    expect(warning).toHaveTextContent('No Issuer is selected for this surface');
    expect(warning).toHaveTextContent('no records are written');
    expect(getIssuersMock).not.toHaveBeenCalled();
  });

  it('stays quiet once the surface has an Issuer that exists', async () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-1');
    await settled();
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('warns that the Issuer no longer exists when the surface points at a deleted one', async () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-gone');

    const warning = await screen.findByTestId(WARNING);
    expect(warning).toHaveTextContent("This surface's Issuer no longer exists");
    expect(warning).toHaveTextContent('Select an existing Issuer');
    expect(warning).toHaveTextContent('no records are written');
  });

  it('stays quiet while the Issuer list is loading and warns once it has loaded without the Issuer', async () => {
    let resolveList!: (issuers: unknown[]) => void;
    getIssuersMock.mockReturnValue(new Promise(resolve => (resolveList = resolve)));
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-gone');

    await waitFor(() => expect(getIssuersMock).toHaveBeenCalled());
    expect(screen.queryByTestId(WARNING)).toBeNull();

    await act(async () => resolveList([]));
    expect(await screen.findByTestId(WARNING)).toHaveTextContent('no longer exists');
  });

  it('stays quiet when the Issuer list cannot be loaded', async () => {
    getIssuersMock.mockRejectedValue(new Error('forbidden'));
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-gone');

    await settled();
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('rechecks with a fresh list before calling an Issuer deleted, so one created elsewhere is not flagged', async () => {
    getIssuersMock.mockResolvedValueOnce([]).mockResolvedValueOnce([{ id: 'issuer-new' }]);
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-new');

    await waitFor(() => expect(getIssuersMock).toHaveBeenCalledWith({ refresh: true }));
    await flushPromises();
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet when every entry names an explicit Authority, since the surface Issuer is not needed', async () => {
    renderWithSurface({ entries: [entry('did:web:authority.example')] }, '');
    expect(screen.queryByTestId(WARNING)).toBeNull();

    renderWithSurface({ entries: [entry('did:web:authority.example')] }, 'issuer-gone');
    await settled();
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet with no entries', () => {
    renderWithSurface({ entries: [] }, '');
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet outside a surface editor, where the Issuer is unknown', () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] });
    expect(screen.queryByTestId(WARNING)).toBeNull();
    expect(getIssuersMock).not.toHaveBeenCalled();
  });
});
