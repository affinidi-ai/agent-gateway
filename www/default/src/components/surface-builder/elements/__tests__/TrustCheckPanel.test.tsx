import React from 'react';
import { render, screen, within, fireEvent } from '@testing-library/react';
import TrustCheckPanel from '../trust-check/TrustCheckPanel';

const AP_SLOT = 'request:trust-check-access_point_trust_check_list';
const TP_SLOT = 'request:trust-check-target_trust_check_list';

function baseProps(slotId: string, config: Record<string, unknown> = {}) {
  return {
    node: {
      id: 'tc-1',
      type: 'trust-check',
      label: '',
      configured: true,
      config,
      parentId: slotId.includes('access_point') ? 'access-point' : 'target',
      slotId,
    } as any,
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    openFullscreenEditor: jest.fn(),
  };
}

describe('TrustCheckPanel — sidebar context block', () => {
  it('renders the per-leg context block on the caller (AP→MA) leg', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    const ctx = screen.getByTestId('trust-check-panel-context');
    expect(ctx).toBeInTheDocument();
    expect(within(ctx).getByText(/sender of an incoming request/i)).toBeInTheDocument();
  });

  it('renders the per-leg context block on the target (MA→TP) leg', () => {
    render(<TrustCheckPanel {...(baseProps(TP_SLOT) as any)} />);

    const ctx = screen.getByTestId('trust-check-panel-context');
    expect(ctx).toBeInTheDocument();
    expect(within(ctx).getByText(/destination entity before sending/i)).toBeInTheDocument();
  });

  it('preserves a JSON-API-authored query name in the preview list (no editor, but still visible)', () => {
    const props = baseProps(AP_SLOT, {
      queries: [
        {
          id: 'q-1',
          trust_registry_id: 'tr-1',
          query_type: 'authorization',
          name: 'issuer-accreditation',
          query: { authority_id: 'a', entity_id: 'e', action: 'issue', resource: 'r' },
        },
      ],
    });
    render(<TrustCheckPanel {...(props as any)} />);

    expect(screen.getByText(/issuer-accreditation/)).toBeInTheDocument();
    // With at least one query the empty-state block must not render.
    expect(screen.queryByTestId('trust-check-panel-empty-state')).toBeNull();
  });

  it('renders an enriched empty state with leg-aware copy on the caller leg', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    const empty = screen.getByTestId('trust-check-panel-empty-state');
    expect(empty).toBeInTheDocument();
    expect(within(empty).getByText(/No trust checks yet/i)).toBeInTheDocument();
    // Caller-leg copy: "verify the caller" + "reaches the agent".
    expect(within(empty).getByText(/verify the caller/i)).toBeInTheDocument();
    expect(within(empty).getByText(/reaches the agent/i)).toBeInTheDocument();
  });

  it('renders an enriched empty state with leg-aware copy on the target leg', () => {
    render(<TrustCheckPanel {...(baseProps(TP_SLOT) as any)} />);

    const empty = screen.getByTestId('trust-check-panel-empty-state');
    expect(empty).toBeInTheDocument();
    expect(within(empty).getByText(/No trust checks yet/i)).toBeInTheDocument();
    // Target-leg copy swaps "caller" → "upstream agent" and "reaches the agent" → "leaves the gateway".
    expect(within(empty).getByText(/verify the upstream agent/i)).toBeInTheDocument();
    expect(within(empty).getByText(/leaves the gateway/i)).toBeInTheDocument();
  });

  it('renders the Configure Queries button as a solid primary with 8px top margin', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    const button = screen.getByTestId('trust-check-panel-configure');
    expect(button).toBeInTheDocument();
    // Solid primary (not outline) — the outline variant would fail this assertion.
    expect(button).toHaveClass('btn-primary');
    expect(button).not.toHaveClass('btn-outline-primary');
    // 8px top margin (Bootstrap's `mt-2`) separates the button from the queries preview above.
    expect(button).toHaveClass('mt-2');
    // Rendered by the shared `AppButton` component — marker class distinguishes
    // it from a raw Bootstrap `<button className="btn">`.
    expect(button).toHaveClass('app-button');
  });

  it('renders the context block collapsed by default with an aria-expanded toggle', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    // Body is absent because the block is collapsed by default.
    expect(screen.queryByTestId('trust-check-panel-context-body')).toBeNull();

    const toggle = screen.getByTestId('trust-check-panel-context-toggle');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
  });

  it('expands the body when the toggle is clicked, keeping the title visible', () => {
    render(<TrustCheckPanel {...(baseProps(AP_SLOT) as any)} />);

    const toggle = screen.getByTestId('trust-check-panel-context-toggle');
    fireEvent.click(toggle);

    // Body visible after expand.
    expect(screen.getByTestId('trust-check-panel-context-body')).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'true');

    // Title row stays visible.
    expect(screen.getByText(/sender of an incoming request/i)).toBeInTheDocument();
  });
});
