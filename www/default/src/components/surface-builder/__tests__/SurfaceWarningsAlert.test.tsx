import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SurfaceWarningsAlert from '../SurfaceWarningsAlert';
import {
  DENY_FAILED_CALLERS_CONDITION,
  DENY_FAILED_CALLERS_REGO,
  GATEWAY_DENY_FAILED_CALLERS_REGO,
} from '../../../utils/denyRule';

const warning = (code: string, variant: string | null = null) => ({
  code,
  message: `message for ${code}`,
  path: null,
  variant,
});

describe('SurfaceWarningsAlert', () => {
  it('keeps an empty live container without warnings', () => {
    render(<SurfaceWarningsAlert warnings={[]} />);
    const live = screen.getByTestId('surface-warnings-live');
    expect(live).toHaveAttribute('aria-live', 'polite');
    expect(live).toBeEmptyDOMElement();
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
  });

  it('puts warnings that arrive later into the live container already in the page', () => {
    const view = render(<SurfaceWarningsAlert warnings={[]} />);
    const live = screen.getByTestId('surface-warnings-live');
    view.rerender(<SurfaceWarningsAlert warnings={[warning('fail_open_policy')]} />);
    expect(screen.getByTestId('surface-warnings-live')).toBe(live);
    expect(live).toContainElement(screen.getByTestId('surface-warnings-alert'));
    expect(live).toHaveTextContent('message for fail_open_policy');
  });

  it('lists each warning in a labelled live region with its variant', () => {
    render(
      <SurfaceWarningsAlert
        warnings={[warning('fail_open_policy'), warning('protected_resource_dropped', 'beta')]}
      />
    );
    const region = screen.getByRole('region', { name: 'Surface warnings' });
    expect(region).not.toHaveAttribute('aria-live');
    expect(screen.getByTestId('surface-warnings-live')).toContainElement(region);
    expect(region).toHaveTextContent('2 warnings');
    expect(screen.getByTestId('surface-warning-fail_open_policy')).toHaveTextContent(
      'message for fail_open_policy'
    );
    expect(screen.getByTestId('surface-warning-protected_resource_dropped')).toHaveTextContent(
      'message for protected_resource_dropped (variant beta)'
    );
  });

  it('offers the deny rule to copy when a warning says a failed caller gets through', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(<SurfaceWarningsAlert warnings={[warning('fail_open_policy')]} />);
    expect(screen.getByRole('region')).toHaveTextContent('1 warning');
    const copy = screen.getByRole('button', { name: /Copy deny rule/ });
    expect(copy).toHaveAttribute('data-testid', 'surface-warnings-copy-rule');
    fireEvent.click(copy);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(DENY_FAILED_CALLERS_REGO));
    const hint = screen.getByTestId('surface-warnings-copy-rule-hint');
    expect(hint).toHaveTextContent(
      'If the Managed Agent has no policy, save this as a policy definition and attach it to the Managed Agent (target.policy), so callers arriving over Fabric are denied too.'
    );
    expect(hint).toHaveTextContent(
      `If it already has a policy, do not paste this whole policy: add ${DENY_FAILED_CALLERS_CONDITION} to each of its allow rules.`
    );
    expect(hint).not.toHaveTextContent("this surface's policy");
    expect(screen.queryByTestId('surface-warnings-copy-gateway-rule')).not.toBeInTheDocument();
  });

  it('points at Authorization server discovery beside a fail-open warning when the surface can publish it', () => {
    render(<SurfaceWarningsAlert warnings={[warning('fail_open_policy')]} offersDiscovery />);
    const hint = screen.getByTestId('surface-warnings-discovery-hint');
    expect(hint).toHaveTextContent(
      'Or turn on Authorization server discovery in the Caller Context editor: the gateway then refuses a caller without a valid token itself, before any policy runs, for direct and Fabric callers alike.'
    );
    expect(screen.getByTestId('surface-warnings-copy-rule')).toBeInTheDocument();
  });

  it('does not point at discovery without a fail-open warning or when the surface cannot publish it', () => {
    const view = render(
      <SurfaceWarningsAlert warnings={[warning('payment_before_policy')]} offersDiscovery />
    );
    expect(screen.queryByTestId('surface-warnings-discovery-hint')).not.toBeInTheDocument();
    view.unmount();
    render(<SurfaceWarningsAlert warnings={[warning('fail_open_policy')]} />);
    expect(screen.queryByTestId('surface-warnings-discovery-hint')).not.toBeInTheDocument();
    render(
      <SurfaceWarningsAlert
        warnings={[warning('fail_open_undetermined')]}
        offersDiscovery={false}
      />
    );
    expect(screen.queryByTestId('surface-warnings-discovery-hint')).not.toBeInTheDocument();
  });

  it('offers the surface deny rule for fail_open_undetermined', () => {
    render(<SurfaceWarningsAlert warnings={[warning('fail_open_undetermined')]} />);
    expect(screen.getByTestId('surface-warnings-copy-rule')).toBeInTheDocument();
    expect(screen.queryByTestId('surface-warnings-copy-gateway-rule')).not.toBeInTheDocument();
  });

  it('offers only the gateway deny rule when payment runs before surface policy', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    render(<SurfaceWarningsAlert warnings={[warning('payment_before_policy')]} />);
    expect(screen.queryByTestId('surface-warnings-copy-rule')).not.toBeInTheDocument();
    const copy = screen.getByRole('button', { name: /Copy gateway deny rule/ });
    expect(copy).toHaveAttribute('data-testid', 'surface-warnings-copy-gateway-rule');
    expect(screen.getAllByRole('button')).toHaveLength(1);
    fireEvent.click(copy);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(GATEWAY_DENY_FAILED_CALLERS_REGO));
    expect(screen.getByTestId('surface-warnings-copy-gateway-rule-hint')).toHaveTextContent(
      'Payment runs before surface policy, so deny failed callers in the gateway policy.'
    );
  });

  it('offers both rules when one variant fails open and another takes payment first', () => {
    render(
      <SurfaceWarningsAlert
        warnings={[warning('fail_open_policy', 'beta'), warning('payment_before_policy')]}
      />
    );
    expect(screen.getByTestId('surface-warnings-copy-rule')).toHaveTextContent('Copy deny rule');
    expect(screen.getByTestId('surface-warnings-copy-gateway-rule')).toHaveTextContent(
      'Copy gateway deny rule'
    );
  });

  it('offers no deny rule for a warning that is not about failed callers', () => {
    render(
      <SurfaceWarningsAlert
        warnings={[warning('forwards_caller_token'), warning('fabric_delegated_credentials')]}
      />
    );
    expect(screen.getByRole('region')).toHaveTextContent('2 warnings');
    expect(screen.queryByTestId('surface-warnings-copy-rule')).not.toBeInTheDocument();
    expect(screen.queryByTestId('surface-warnings-copy-gateway-rule')).not.toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('never puts a deny rule that admits a failed caller on the clipboard', () => {
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/^package surface\.policy$/m);
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/^default allow := false$/m);
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/deny if input\.source_auth\.method == "failed"/);
    expect(GATEWAY_DENY_FAILED_CALLERS_REGO).toMatch(/^package gateway\.policy$/m);
    expect(GATEWAY_DENY_FAILED_CALLERS_REGO).not.toMatch(/surface\.policy/);
    expect(GATEWAY_DENY_FAILED_CALLERS_REGO).toMatch(/^default allow := false$/m);
    expect(GATEWAY_DENY_FAILED_CALLERS_REGO).toMatch(
      /deny if input\.source_auth\.method == "failed"/
    );
    expect(DENY_FAILED_CALLERS_CONDITION).toBe('not input.source_auth.method == "failed"');
  });
});
