import React from 'react';
import { render, screen, within, fireEvent } from '@testing-library/react';
import TrustRecorderPanel from '../trust-recorder/TrustRecorderPanel';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import { SURFACE_ISSUER_DID_TEMPLATE } from '../trust-recorder/definition';

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

  it('warns that records are skipped when an entry uses the surface Issuer and none is selected', () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, '');

    const warning = screen.getByTestId(WARNING);
    expect(warning).toHaveTextContent('No Issuer is selected for this surface');
    expect(warning).toHaveTextContent('no records are written');
  });

  it('stays quiet once the surface has an Issuer', () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] }, 'issuer-1');
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet when every entry names an explicit Authority, since the surface Issuer is not needed', () => {
    renderWithSurface({ entries: [entry('did:web:authority.example')] }, '');
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet with no entries', () => {
    renderWithSurface({ entries: [] }, '');
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });

  it('stays quiet outside a surface editor, where the Issuer is unknown', () => {
    renderWithSurface({ entries: [entry(SURFACE_ISSUER_DID_TEMPLATE)] });
    expect(screen.queryByTestId(WARNING)).toBeNull();
  });
});
