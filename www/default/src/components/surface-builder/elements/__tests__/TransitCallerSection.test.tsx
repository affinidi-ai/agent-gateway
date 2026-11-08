import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import TransitCallerSection from '../transit-point/TransitCallerSection';
import { SurfaceMetaProvider } from '../../SurfaceMetaContext';
import { apiClient } from '../../../../api';
import { callerAuthProblems, callerAuthToWire } from '../transit-point/callerAuth';

jest.mock('../../../../api', () => ({
  apiClient: { get: jest.fn(), fetch: jest.fn() },
}));

const mockedApi = apiClient as unknown as { get: jest.Mock; fetch: jest.Mock };

beforeEach(() => {
  // The project resets mocks between tests, so the answers are set here.
  mockedApi.get.mockResolvedValue({
    data: [{ id: 'k1', name: 'Partner keys', secret_id: 'partner-keys', secret_type: 'ApiKey' }],
  });
  mockedApi.fetch.mockResolvedValue({
    ok: true,
    json: () => Promise.resolve([{ id: 'idp', name: 'Corporate IdP' }]),
  });
});

let latest: Record<string, any> = {};

function Harness({
  initial,
  meta = {},
}: {
  initial: Record<string, any>;
  meta?: Record<string, unknown>;
}) {
  const [config, setConfig] = useState<Record<string, any>>(initial);
  latest = config;
  return (
    <SurfaceMetaProvider value={{ surfaceId: 'surface-1', ...meta } as any}>
      <TransitCallerSection
        config={config}
        alias="crm"
        updateField={(f, v) => setConfig(c => ({ ...c, [f]: v }))}
        updateFields={fields => setConfig(c => ({ ...c, ...fields }))}
      />
    </SurfaceMetaProvider>
  );
}

const open = { require_transit_token: false, allow_unauthenticated_callers: true };

describe('Who can call this Transit Point', () => {
  it('shows the transit token on by default and no open marking', () => {
    render(<Harness initial={{ id: 'tp' }} />);
    expect(screen.getByTestId('transit-point-require-transit-token-switch')).toBeChecked();
    expect(screen.queryByTestId('transit-point-allow-unauthenticated-callers-switch')).toBeNull();
    expect(screen.queryByTestId('transit-point-caller-auth-problem')).toBeNull();
  });

  it('says in plain words that a Transit Point with no way to authenticate cannot be saved', () => {
    render(<Harness initial={{ id: 'tp' }} />);
    fireEvent.click(screen.getByTestId('transit-point-require-transit-token-switch'));
    expect(screen.getByTestId('transit-point-caller-auth-problem')).toHaveTextContent(
      /would serve anyone who can reach it/
    );
    expect(
      screen.getByTestId('transit-point-allow-unauthenticated-callers-switch')
    ).not.toBeChecked();
  });

  it('configures an API key and clears the problem', async () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false }} />);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'api_key' },
    });
    expect(latest.source_auth).toEqual({
      type: 'api_key',
      extraction: { source: 'http_header', field: 'X-API-Key' },
      secret_id: '',
    });
    expect(screen.getByTestId('transit-point-caller-auth-problem')).toHaveTextContent(/secret/);
    expect(await screen.findByText('Partner keys')).toBeInTheDocument();
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-secret'), {
      target: { value: 'partner-keys' },
    });
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-header'), {
      target: { value: 'X-Partner-Key' },
    });
    expect(latest.source_auth.secret_id).toBe('partner-keys');
    expect(latest.source_auth.extraction).toEqual({
      source: 'http_header',
      field: 'X-Partner-Key',
    });
    expect(screen.queryByTestId('transit-point-caller-auth-problem')).toBeNull();
    expect(callerAuthProblems(latest)).toEqual([]);
  });

  it("warns that the API Key Provider accepts the Access Point's keys too", () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false }} />);
    expect(screen.queryByTestId('transit-point-caller-auth-provider-scope')).toBeNull();
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'api_key_provider' },
    });
    expect(latest.source_auth.agent_id).toBe('surface-1');
    expect(screen.getByTestId('transit-point-caller-auth-provider-scope')).toHaveTextContent(
      /same keys an Access Point using the API Key Provider accepts/
    );
  });

  it("names the surface being edited, not a copied Transit Point's stored agent", () => {
    render(
      <Harness
        initial={{
          id: 'tp',
          require_transit_token: false,
          source_auth: {
            type: 'api_key_provider',
            extraction: { source: 'http_header', field: 'X-API-Key' },
            agent_id: 'original-surface',
          },
        }}
      />
    );
    const scope = screen.getByTestId('transit-point-caller-auth-provider-scope');
    expect(scope).toHaveTextContent('surface-1');
    expect(scope).not.toHaveTextContent('original-surface');
  });

  it('configures a JWT: strategy, audiences, and no forwarding', async () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false }} />);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'jwt_bearer' },
    });
    expect(latest.source_auth.forward_header).toBe(false);
    expect(await screen.findByText('Corporate IdP')).toBeInTheDocument();
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-strategy'), {
      target: { value: 'idp' },
    });
    expect(screen.getByTestId('transit-point-caller-auth-problem')).toHaveTextContent(/audience/);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-audience-input'), {
      target: { value: 'https://crm.example.com' },
    });
    fireEvent.click(screen.getByTestId('transit-point-caller-auth-audience-add'));
    expect(latest.source_auth.audiences).toEqual(['https://crm.example.com']);
    expect(callerAuthProblems(latest)).toEqual([]);
    fireEvent.click(screen.getByLabelText('Remove audience https://crm.example.com'));
    expect(latest.source_auth.audiences).toEqual([]);
  });

  it('turns caller authentication off with an explicit null, so the save removes it', () => {
    render(
      <Harness
        initial={{
          id: 'tp',
          require_transit_token: false,
          source_auth: {
            type: 'api_key',
            extraction: { source: 'http_header', field: 'X-API-Key' },
            secret_id: 'partner-keys',
          },
        }}
      />
    );
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'none' },
    });
    expect(latest.source_auth).toBeNull();
  });

  it('asks before marking a Transit Point open, and changes nothing on cancel', () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false }} />);
    fireEvent.click(screen.getByTestId('transit-point-allow-unauthenticated-callers-switch'));
    expect(screen.getByTestId('transit-point-open-confirm')).toHaveTextContent(
      /anyone who can reach it/
    );
    fireEvent.click(screen.getByTestId('transit-point-open-cancel'));
    expect(latest.allow_unauthenticated_callers).toBeUndefined();
  });

  it('marks it open once confirmed, with a standing warning', () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false }} />);
    fireEvent.click(screen.getByTestId('transit-point-allow-unauthenticated-callers-switch'));
    fireEvent.click(screen.getByTestId('transit-point-open-confirm-button'));
    expect(latest.allow_unauthenticated_callers).toBe(true);
    expect(
      screen.getByTestId('transit-point-allow-unauthenticated-callers-warning')
    ).toBeInTheDocument();
    expect(screen.queryByTestId('transit-point-caller-auth-problem')).toBeNull();
  });

  it('clears the open marking when the transit token or a method is chosen', () => {
    render(<Harness initial={{ id: 'tp', ...open }} />);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'api_key' },
    });
    expect(latest.allow_unauthenticated_callers).toBe(false);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'none' },
    });
    fireEvent.click(screen.getByTestId('transit-point-allow-unauthenticated-callers-switch'));
    expect(latest.allow_unauthenticated_callers).toBe(false);
    fireEvent.click(screen.getByTestId('transit-point-require-transit-token-switch'));
    expect(latest.require_transit_token).toBe(true);
  });

  it('hides the open switch while a resource access token authenticates callers', () => {
    render(
      <Harness
        initial={{ id: 'tp', require_transit_token: false, mcp_http: { authorization: { a: 1 } } }}
      />
    );
    expect(screen.queryByTestId('transit-point-allow-unauthenticated-callers-switch')).toBeNull();
    expect(screen.queryByTestId('transit-point-caller-auth-problem')).toBeNull();
  });

  it('shows a stored mTLS method as set through the API and keeps it', () => {
    const mtls = { type: 'mtls', trust: { type: 'pinned', certificate_ids: ['c'] } };
    render(<Harness initial={{ id: 'tp', require_transit_token: false, source_auth: mtls }} />);
    expect(screen.getByTestId('transit-point-caller-auth-mtls')).toBeInTheDocument();
    expect(latest.source_auth).toEqual(mtls);
  });
});

describe('a stored method the dashboard cannot show', () => {
  const didAuth = { type: 'did_auth', allowed_dids: ['did:web:a.example'] };

  it('names it as a disabled option and keeps it until removed', () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: false, source_auth: didAuth }} />);
    const select = screen.getByTestId('transit-point-caller-auth-method') as HTMLSelectElement;
    expect(select.value).toBe('unsupported');
    const named = screen.getByRole('option', { name: 'did_auth (not supported here)' });
    expect(named).toBeDisabled();
    expect(latest.source_auth).toEqual(didAuth);
  });

  it('removes it with the Remove control, sending an explicit null', () => {
    render(<Harness initial={{ id: 'tp', require_transit_token: true, source_auth: didAuth }} />);
    fireEvent.click(screen.getByTestId('transit-point-caller-auth-remove'));
    expect(latest.source_auth).toBeNull();
    expect(callerAuthToWire(latest)).toMatchObject({ source_auth: null });
    expect(screen.queryByTestId('transit-point-caller-auth-unsupported')).toBeNull();
  });

  it('also lets None replace it', () => {
    render(<Harness initial={{ id: 'tp', source_auth: didAuth }} />);
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-method'), {
      target: { value: 'none' },
    });
    expect(latest.source_auth).toBeNull();
  });

  it('shows one without a readable type as set by the API and kept, not as none', () => {
    const odd = { extraction: { source: 'http_header', field: 'X' } };
    render(<Harness initial={{ id: 'tp', require_transit_token: false, source_auth: odd }} />);
    expect(screen.getByTestId('transit-point-caller-auth-unsupported')).toHaveTextContent(
      /set through the API.*kept/
    );
    expect(screen.getByRole('option', { name: 'Set through the API (kept)' })).toBeInTheDocument();
    expect(latest.source_auth).toEqual(odd);
    expect(screen.queryByTestId('transit-point-caller-auth-problem')).toBeNull();
  });
});

describe('what the section tells a screen reader', () => {
  it('marks a blocking problem and a refusal as alerts', () => {
    render(
      <Harness
        initial={{ id: 'tp', require_transit_token: false }}
        meta={{ saveError: "transit.points[0]: Transit Point 'crm' authenticates no caller (400)" }}
      />
    );
    expect(screen.getByTestId('transit-point-caller-auth-problem')).toHaveAttribute(
      'role',
      'alert'
    );
    expect(screen.getByTestId('transit-point-save-error')).toHaveAttribute('role', 'alert');
  });

  it('ties the section title and the help text to the controls', () => {
    render(<Harness initial={{ id: 'tp' }} />);
    const group = screen.getByRole('group', { name: 'Who can call this Transit Point' });
    expect(group).toHaveAccessibleDescription(/must authenticate its callers/);
    expect(screen.getByTestId('transit-point-caller-auth-method')).toHaveAccessibleDescription(
      /presents its own credential/
    );
  });
});

describe('header and scheme fields', () => {
  it('trims the API key header on write', () => {
    render(
      <Harness
        initial={{
          id: 'tp',
          require_transit_token: false,
          source_auth: {
            type: 'api_key',
            extraction: { source: 'http_header', field: 'X' },
            secret_id: 's',
          },
        }}
      />
    );
    fireEvent.change(screen.getByTestId('transit-point-caller-auth-header'), {
      target: { value: ' X-Key ' },
    });
    expect(latest.source_auth.extraction.field).toBe('X-Key');
  });
});

describe('the exposure warning', () => {
  const exposed = { id: 'tp', ...open, listen_address: 'https://gateway.example.com' };

  it('shows before saving when an open Transit Point is on an address other hosts reach', () => {
    render(<Harness initial={exposed} />);
    expect(screen.getByTestId('transit-point-exposure-warning')).toHaveTextContent(
      "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: https://gateway.example.com"
    );
  });

  it('is absent on loopback, and once the Transit Point authenticates callers', () => {
    const { unmount } = render(
      <Harness initial={{ ...exposed, listen_address: 'http://localhost:8080' }} />
    );
    expect(screen.queryByTestId('transit-point-exposure-warning')).toBeNull();
    unmount();
    render(<Harness initial={exposed} />);
    fireEvent.click(screen.getByTestId('transit-point-require-transit-token-switch'));
    expect(screen.queryByTestId('transit-point-exposure-warning')).toBeNull();
  });

  it('shows what a save answered with, only for this Transit Point, and keeps it until the Transit Point changes', () => {
    const warnings = [
      "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: 0.0.0.0:8080, https://gateway.example.com",
      "Transit Point 'hr' serves callers it does not authenticate and is reachable from other hosts: 0.0.0.0:8080",
    ];
    render(<Harness initial={exposed} meta={{ saveWarnings: warnings }} />);
    const shown = screen.getAllByTestId('transit-point-save-warning');
    expect(shown).toHaveLength(1);
    expect(shown[0]).toHaveTextContent(/0\.0\.0\.0:8080, https:\/\/gateway\.example\.com/);
    // The gateway's own text replaces the prediction.
    expect(screen.queryByTestId('transit-point-exposure-warning')).toBeNull();
    // Unrelated edits keep it.
    expect(screen.getAllByTestId('transit-point-save-warning')).toHaveLength(1);
    // Changing who can call it removes it.
    fireEvent.click(screen.getByTestId('transit-point-require-transit-token-switch'));
    expect(screen.queryByTestId('transit-point-save-warning')).toBeNull();
  });
});

describe('a save warning after the save rehydrates the canvas', () => {
  const warning =
    "Transit Point 'crm' serves callers it does not authenticate and is reachable from other hosts: 0.0.0.0:8080";

  const section = (config: Record<string, any>, saveWarnings: string[] | null) => (
    <SurfaceMetaProvider value={{ surfaceId: 's', saveWarnings } as any}>
      <TransitCallerSection
        config={config}
        alias="crm"
        updateField={() => {}}
        updateFields={() => {}}
      />
    </SurfaceMetaProvider>
  );

  it('keeps the warning when the saved config arrives in the same render as it', () => {
    const before = { id: 'tp', ...open, listen_address: 'http://localhost:8080' };
    const { rerender } = render(section(before, null));
    rerender(section({ ...before, listen_address: 'https://gateway.example.com' }, [warning]));
    expect(screen.getAllByTestId('transit-point-save-warning')).toHaveLength(1);
    rerender(section({ ...before, listen_address: 'https://gateway.example.com' }, [warning]));
    expect(screen.getAllByTestId('transit-point-save-warning')).toHaveLength(1);
  });
});

describe('a save warning for a variant', () => {
  const base = "Transit Point 'crm' serves callers it does not authenticate and is reachable: a";
  const inVariant =
    "Transit Point 'crm' in variant 'candidate' serves callers it does not authenticate and is reachable: b";

  function WithVariant({ variant }: { variant?: string }) {
    return (
      <SurfaceMetaProvider
        value={
          { surfaceId: 's', activeVariantAlias: variant, saveWarnings: [base, inVariant] } as any
        }
      >
        <TransitCallerSection
          config={{ id: 'tp', ...open }}
          alias="crm"
          updateField={() => {}}
          updateFields={() => {}}
        />
      </SurfaceMetaProvider>
    );
  }

  it('shows only the base surface warning on the base', () => {
    render(<WithVariant />);
    const shown = screen.getAllByTestId('transit-point-save-warning');
    expect(shown).toHaveLength(1);
    expect(shown[0]).toHaveTextContent(/reachable: a$/);
  });

  it('shows only the variant warning in that variant', () => {
    render(<WithVariant variant="candidate" />);
    const shown = screen.getAllByTestId('transit-point-save-warning');
    expect(shown).toHaveLength(1);
    expect(shown[0]).toHaveTextContent(/in variant 'candidate'.*reachable: b$/);
  });
});

describe('a refused save', () => {
  it('shows the gateway reason in plain words on the Transit Point it names', () => {
    render(
      <Harness
        initial={{ id: 'tp' }}
        meta={{
          saveError:
            "transit.points[0]: Transit Point 'crm' sets both source_auth and mcp_http.authorization; keep one (400)",
        }}
      />
    );
    expect(screen.getByTestId('transit-point-save-error')).toHaveTextContent(
      "The gateway refused the last save: Transit Point 'crm' sets both source_auth and mcp_http.authorization; keep one"
    );
  });

  it('shows nothing for another Transit Point', () => {
    render(
      <Harness
        initial={{ id: 'tp' }}
        meta={{ saveError: "transit.points[0]: Transit Point 'hr' authenticates no caller" }}
      />
    );
    expect(screen.queryByTestId('transit-point-save-error')).toBeNull();
  });

  it('shows a variant refusal only in that variant, and a base refusal only on the base', () => {
    const variantError = "variant 'beta' transit.points[0]: Transit Point 'crm' sets x (400)";
    const { unmount } = render(
      <Harness
        initial={{ id: 'tp' }}
        meta={{ saveError: variantError, activeVariantAlias: 'beta' }}
      />
    );
    expect(screen.getByTestId('transit-point-save-error')).toHaveTextContent(
      "The gateway refused the last save: Transit Point 'crm' sets x"
    );
    unmount();
    const { unmount: unmountBase } = render(
      <Harness initial={{ id: 'tp' }} meta={{ saveError: variantError }} />
    );
    expect(screen.queryByTestId('transit-point-save-error')).toBeNull();
    unmountBase();
    render(
      <Harness
        initial={{ id: 'tp' }}
        meta={{
          saveError: "transit.points[0]: Transit Point 'crm' sets x",
          activeVariantAlias: 'other',
        }}
      />
    );
    expect(screen.queryByTestId('transit-point-save-error')).toBeNull();
  });
});
