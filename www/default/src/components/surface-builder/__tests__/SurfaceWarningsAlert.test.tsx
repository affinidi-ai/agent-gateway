import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SurfaceWarningsAlert from '../SurfaceWarningsAlert';
import { DENY_FAILED_CALLERS_REGO } from '../../../utils/denyRule';

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
        warnings={[warning('declaration_stripped'), warning('additional_audiences', 'beta')]}
      />
    );
    const region = screen.getByRole('region', { name: 'Surface warnings' });
    expect(region).not.toHaveAttribute('aria-live');
    expect(screen.getByTestId('surface-warnings-live')).toContainElement(region);
    expect(region).toHaveTextContent('2 warnings');
    expect(screen.getByTestId('surface-warning-declaration_stripped')).toHaveTextContent(
      'message for declaration_stripped'
    );
    expect(screen.getByTestId('surface-warning-additional_audiences')).toHaveTextContent(
      'message for additional_audiences (variant beta)'
    );
    expect(screen.queryByTestId('surface-warnings-copy-rule')).not.toBeInTheDocument();
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
    expect(screen.getByTestId('surface-warnings-copy-rule-hint')).toHaveTextContent(
      "Add it to this surface's policy to deny callers whose authentication failed."
    );
  });

  it.each(['fail_open_undetermined', 'payment_before_policy'])(
    'offers the deny rule for %s',
    code => {
      render(<SurfaceWarningsAlert warnings={[warning(code)]} />);
      expect(screen.getByTestId('surface-warnings-copy-rule')).toBeInTheDocument();
    }
  );

  it('offers no deny rule for a warning that is not about failed callers', () => {
    render(
      <SurfaceWarningsAlert
        warnings={[warning('forwards_caller_token'), warning('fabric_delegated_credentials')]}
      />
    );
    expect(screen.getByRole('region')).toHaveTextContent('2 warnings');
    expect(screen.queryByTestId('surface-warnings-copy-rule')).not.toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('never puts a deny rule that admits a failed caller on the clipboard', () => {
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/^package surface\.policy$/m);
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/^default allow := false$/m);
    expect(DENY_FAILED_CALLERS_REGO).toMatch(/deny if input\.source_auth\.method == "failed"/);
  });
});
