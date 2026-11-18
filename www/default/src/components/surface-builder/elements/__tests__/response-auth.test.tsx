import React from 'react';
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import ResponseAuthSection from '../managed-agent/ResponseAuthSection';
import {
  isHttpsTarget,
  isResponseAuthTarget,
  responseAuthProblems,
  responseAuthSaveError,
  responseAuthToWire,
  responseAuthWarnings,
  variantsWithoutResponseAuth,
  withResponseAuth,
} from '../managed-agent/responseAuth';
import { useVariantSnapshots } from '../../variants/useVariantSnapshots';
import { managedAgentDefinition } from '../managed-agent/definition';
import { apiClient } from '../../../../api';
import { registry } from '../index';
import { computeOverridesFromPayload, resolveVariant } from '../../variants/resolve';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../SurfaceMetaContext';
import type { CanvasNode, ConfigPanelProps, PayloadContext } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

const CERTIFICATES = [
  { id: 'bravo-cert', name: 'Bravo server', kind: 'client_leaf', active: true },
  { id: 'bravo-ca', name: 'Bravo CA', kind: 'ca', active: true },
  { id: 'gateway-cert', name: 'Gateway client', kind: 'client_leaf', active: true },
  { id: 'old-cert', name: 'Old', kind: 'client_leaf', active: false },
];

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });
  (apiClient.get as jest.Mock).mockImplementation((path: string) =>
    Promise.resolve({
      data:
        path === '/certificates'
          ? CERTIFICATES
          : path === '/secrets/'
            ? [{ id: 'bravo-key', name: 'Bravo key', secret_type: 'ApiKey' }]
            : [],
    })
  );
});

const T = 'managed-agent-response-auth';
const API_KEY = { api_key: { header_name: 'X-Agent-Key', secret_id: 'bravo-key' } };
const MTLS = {
  mtls: {
    server_trust: { type: 'pinned', certificate_ids: ['bravo-cert'] },
    client_certificate_id: 'gateway-cert',
  },
};

function panelProps(
  config: Record<string, unknown>
): ConfigPanelProps & { updateField: jest.Mock } {
  return {
    node: { id: 'target', type: 'target', label: 'Managed Agent', configured: true, config },
    config,
    updateField: jest.fn(),
    updateFields: jest.fn(),
    protocol: 'a2a',
    allNodes: [],
  } as unknown as ConfigPanelProps & { updateField: jest.Mock };
}

describe('Response Authentication section', () => {
  it('shows on an http or https Target only', () => {
    for (const endpoint of ['https://agent.example', 'http://agent.example']) {
      const { unmount } = render(<ManagedAgentPanel {...panelProps({ endpoint })} />);
      expect(screen.getByTestId(`${T}-method`)).toHaveValue('off');
      unmount();
    }
    for (const endpoint of ['fabric://gw-2/surface-2', 'proxy://tools', 'a2a-proxy://worker']) {
      const { unmount } = render(<ManagedAgentPanel {...panelProps({ endpoint })} />);
      expect(screen.queryByTestId(`${T}-section`)).not.toBeInTheDocument();
      unmount();
    }
  });

  it('shows on an http or https Target with an upper-case scheme or surrounding spaces', () => {
    for (const endpoint of ['HTTPS://agent.example', '  http://agent.example  ']) {
      const { unmount } = render(<ManagedAgentPanel {...panelProps({ endpoint })} />);
      expect(screen.getByTestId(`${T}-method`)).toHaveValue('off');
      unmount();
    }
  });

  it('does not offer mTLS on an http:// Target', () => {
    render(<ManagedAgentPanel {...panelProps({ endpoint: 'http://agent.example' })} />);
    const mtls = screen.getByRole('option', { name: /mTLS/ });
    expect(mtls).toBeDisabled();
    expect(mtls).toHaveTextContent('mTLS (needs an https:// Target)');
  });

  it('offers mTLS on an https:// Target', () => {
    render(<ManagedAgentPanel {...panelProps({ endpoint: 'https://agent.example' })} />);
    expect(screen.getByRole('option', { name: 'mTLS' })).toBeEnabled();
  });

  it('writes a new setting for the chosen method and null for Off', () => {
    const props = panelProps({ endpoint: 'https://agent.example', response_auth: API_KEY });
    render(<ManagedAgentPanel {...props} />);
    fireEvent.change(screen.getByTestId(`${T}-method`), { target: { value: 'mtls' } });
    expect(props.updateField).toHaveBeenLastCalledWith('response_auth', {
      mtls: { server_trust: { type: 'pinned', certificate_ids: [] } },
    });
    fireEvent.change(screen.getByTestId(`${T}-method`), { target: { value: 'off' } });
    expect(props.updateField).toHaveBeenLastCalledWith('response_auth', null);
  });

  it('starts an API key with the default header and no secret', () => {
    const props = panelProps({ endpoint: 'https://agent.example' });
    render(<ManagedAgentPanel {...props} />);
    fireEvent.change(screen.getByTestId(`${T}-method`), { target: { value: 'api_key' } });
    expect(props.updateField).toHaveBeenLastCalledWith('response_auth', {
      api_key: { header_name: 'X-Agent-Key', secret_id: '' },
    });
  });

  it.each(['HTTP://agent.example', '  http://agent.example  '])(
    'warns about the API key in clear for %p',
    endpoint => {
      render(<ResponseAuthSection endpoint={endpoint} value={API_KEY} onChange={jest.fn()} />);
      expect(screen.getByTestId(`${T}-http-warning`)).toHaveTextContent(/unencrypted/);
    }
  );

  it.each(['https://agent.example', 'HTTPS://agent.example'])(
    'does not warn for an https Target %p',
    endpoint => {
      render(<ResponseAuthSection endpoint={endpoint} value={API_KEY} onChange={jest.fn()} />);
      expect(screen.queryByTestId(`${T}-http-warning`)).not.toBeInTheDocument();
    }
  );

  it('edits an API key and warns about an http:// Target', async () => {
    const onChange = jest.fn();
    render(
      <ResponseAuthSection endpoint="http://agent.example" value={API_KEY} onChange={onChange} />
    );
    expect(screen.getByTestId(`${T}-http-warning`)).toHaveTextContent(/unencrypted/);
    fireEvent.change(screen.getByTestId(`${T}-header`), { target: { value: 'X-Bravo' } });
    expect(onChange).toHaveBeenLastCalledWith({
      api_key: { header_name: 'X-Bravo', secret_id: 'bravo-key' },
    });
    await screen.findByRole('option', { name: 'Bravo key' });
    expect(screen.getByTestId(`${T}-secret`)).toHaveValue('bravo-key');
  });

  it('lists only active certificates of the kind the trust takes, and clients for the client certificate', async () => {
    const onChange = jest.fn();
    render(
      <ResponseAuthSection endpoint="https://agent.example" value={MTLS} onChange={onChange} />
    );
    expect(await screen.findByTestId(`${T}-trust-cert-bravo-cert`)).toBeInTheDocument();
    expect(screen.queryByTestId(`${T}-trust-cert-bravo-ca`)).not.toBeInTheDocument();
    expect(screen.queryByTestId(`${T}-trust-cert-old-cert`)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Bravo server')).toBeChecked();
    expect(screen.getByTestId(`${T}-client-cert`)).toHaveValue('gateway-cert');
    expect(screen.queryByRole('option', { name: 'Bravo CA' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Gateway client'));
    expect(onChange).toHaveBeenLastCalledWith({
      mtls: {
        server_trust: { type: 'pinned', certificate_ids: ['bravo-cert', 'gateway-cert'] },
        client_certificate_id: 'gateway-cert',
      },
    });

    fireEvent.change(screen.getByTestId(`${T}-client-cert`), { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith({
      mtls: { server_trust: { type: 'pinned', certificate_ids: ['bravo-cert'] } },
    });

    fireEvent.change(screen.getByTestId(`${T}-trust-mode`), { target: { value: 'ca' } });
    expect(onChange).toHaveBeenLastCalledWith({
      mtls: {
        server_trust: { type: 'ca', ca_certificate_ids: [] },
        client_certificate_id: 'gateway-cert',
      },
    });
  });

  it('keeps a stored certificate the store no longer lists selected, so it can be cleared', async () => {
    const onChange = jest.fn();
    const stored = { mtls: { server_trust: { type: 'pinned', certificate_ids: ['gone'] } } };
    render(
      <ResponseAuthSection endpoint="https://agent.example" value={stored} onChange={onChange} />
    );
    const gone = await screen.findByTestId(`${T}-trust-cert-gone`);
    expect(gone).toBeChecked();
    expect(screen.getByLabelText('gone (not in the certificate store)')).toBe(gone);
    fireEvent.click(gone);
    expect(onChange).toHaveBeenLastCalledWith({
      mtls: { server_trust: { type: 'pinned', certificate_ids: [] } },
    });
  });

  it('says when the certificate store cannot be read', async () => {
    (apiClient.get as jest.Mock).mockRejectedValue(new Error('403'));
    render(
      <ResponseAuthSection endpoint="https://agent.example" value={MTLS} onChange={jest.fn()} />
    );
    expect(await screen.findByTestId(`${T}-certificates-error`)).toBeInTheDocument();
  });

  function renderInView(
    meta: Partial<SurfaceMetaValue>,
    value: unknown = API_KEY,
    endpoint = 'https://agent.example'
  ) {
    return render(
      <SurfaceMetaProvider value={meta as SurfaceMetaValue}>
        <ResponseAuthSection endpoint={endpoint} value={value} onChange={jest.fn()} />
      </SurfaceMetaProvider>
    );
  }

  it('warns in the base view about the variants without the setting', () => {
    renderInView({ variantsWithoutResponseAuth: ['beta', 'canary'] });
    expect(screen.getByTestId(`${T}-variants-warning`)).toHaveTextContent(
      "Variants beta, canary don't check the Managed Agent's responses: each variant keeps its own setting."
    );
  });

  it('names a single variant in the singular', () => {
    renderInView({ variantsWithoutResponseAuth: ['beta'] });
    expect(screen.getByTestId(`${T}-variants-warning`)).toHaveTextContent(
      "Variant beta doesn't check the Managed Agent's responses"
    );
  });

  it('does not warn in a variant view, with no variant left out, or while Off', () => {
    const cases: Array<[Partial<SurfaceMetaValue>, unknown]> = [
      [{ activeVariantAlias: 'beta', variantsWithoutResponseAuth: ['canary'] }, API_KEY],
      [{ variantsWithoutResponseAuth: [] }, API_KEY],
      [{}, API_KEY],
      [{ variantsWithoutResponseAuth: ['beta'] }, null],
    ];
    for (const [meta, value] of cases) {
      const { unmount } = renderInView(meta, value);
      expect(screen.queryByTestId(`${T}-variants-warning`)).not.toBeInTheDocument();
      unmount();
    }
  });

  it('copies the base setting in its wire shape when asked, and only then', () => {
    const copy = jest.fn();
    renderInView({ variantsWithoutResponseAuth: ['beta'], onCopyResponseAuthToVariants: copy });
    expect(copy).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId(`${T}-copy-to-variants`));
    expect(copy).toHaveBeenCalledTimes(1);
    expect(copy).toHaveBeenCalledWith(API_KEY);
  });

  it('does not offer the copy while the base setting is incomplete or the surface is read-only', () => {
    const { unmount } = renderInView(
      { variantsWithoutResponseAuth: ['beta'], onCopyResponseAuthToVariants: jest.fn() },
      { api_key: { header_name: 'X-Agent-Key', secret_id: '' } }
    );
    expect(screen.getByTestId(`${T}-copy-to-variants`)).toBeDisabled();
    unmount();
    renderInView({ variantsWithoutResponseAuth: ['beta'] });
    expect(screen.getByTestId(`${T}-copy-to-variants`)).toBeDisabled();
  });

  it("shows the gateway's refusal and warnings for this view in plain words", async () => {
    const meta = {
      saveError:
        'target.response_auth.api_key.header_name must not be the reserved header Host (400)',
      saveWarnings: [
        'target.response_auth receives an API key, so its Target must be an https URL',
        "Transit Point 'crm' does not authenticate its callers",
      ],
    } as unknown as SurfaceMetaValue;
    render(
      <SurfaceMetaProvider value={meta}>
        <ResponseAuthSection endpoint="http://agent.example" value={API_KEY} onChange={jest.fn()} />
      </SurfaceMetaProvider>
    );
    expect(screen.getByTestId(`${T}-save-error`)).toHaveTextContent(
      'The gateway refused the last save: The response header must not be the reserved header Host'
    );
    await waitFor(() =>
      expect(screen.getAllByTestId(`${T}-save-warning`).map(w => w.textContent)).toEqual([
        'Response authentication receives an API key, so its Target must be an https URL',
      ])
    );
  });
});

describe('Response Authentication rules and messages', () => {
  it('reads the Target as the gateway does: trimmed, scheme in any case, with a host', () => {
    for (const endpoint of [
      'https://agent.example',
      'http://agent.example',
      'HTTPS://agent.example',
      'Http://agent.example',
      ' https://agent.example ',
    ]) {
      expect(isResponseAuthTarget(endpoint)).toBe(true);
    }
    for (const endpoint of [
      'proxy://tools',
      'fabric://gw/s',
      'a2a-proxy://worker',
      'http://',
      'not a url',
      '',
      undefined,
    ]) {
      expect(isResponseAuthTarget(endpoint)).toBe(false);
    }
    expect(isHttpsTarget('HTTPS://agent.example')).toBe(true);
    expect(isHttpsTarget('  https://agent.example\n')).toBe(true);
    expect(isHttpsTarget('HTTP://agent.example')).toBe(false);
    expect(isHttpsTarget('fabric://gw/s')).toBe(false);
  });

  it('checks the setting on an upper-case or padded https Target', () => {
    expect(responseAuthProblems('HTTPS://a.example', MTLS)).toEqual([]);
    expect(responseAuthProblems(' https://a.example ', MTLS)).toEqual([]);
    expect(responseAuthProblems('HTTP://a.example', MTLS)).toEqual([
      'mTLS needs an https:// Target',
    ]);
    expect(
      responseAuthProblems('HTTPS://a.example', { api_key: { header_name: 'X', secret_id: '' } })
    ).toEqual(['Select the secret holding the key']);
  });

  it('blocks an API key without a header or secret and mTLS without a certificate or on http', () => {
    expect(responseAuthProblems('https://a.example', API_KEY)).toEqual([]);
    expect(responseAuthProblems('https://a.example', MTLS)).toEqual([]);
    expect(
      responseAuthProblems('https://a.example', { api_key: { header_name: ' ', secret_id: '' } })
    ).toEqual(['Enter the response header name', 'Select the secret holding the key']);
    expect(
      responseAuthProblems('https://a.example', {
        mtls: { server_trust: { type: 'ca', ca_certificate_ids: [] } },
      })
    ).toEqual(['Select at least one CA certificate']);
    expect(responseAuthProblems('http://a.example', MTLS)).toEqual([
      'mTLS needs an https:// Target',
    ]);
    expect(responseAuthProblems('fabric://gw/s', { api_key: {} })).toEqual([]);
    expect(responseAuthProblems('https://a.example', null)).toEqual([]);
  });

  it('faults the Managed Agent node with the same rules', () => {
    expect(
      managedAgentDefinition.validate!({
        endpoint: 'https://a.example',
        response_auth: { api_key: { header_name: 'X-Agent-Key', secret_id: '' } },
      })
    ).toEqual([
      {
        field: 'response_auth',
        message: 'Response Authentication: Select the secret holding the key',
      },
    ]);
  });

  it('routes refusals and warnings to the base or the variant they name', () => {
    const variantError = "variants['beta'].target.response_auth.mtls needs an https Target (400)";
    expect(responseAuthSaveError(variantError)).toBeNull();
    expect(responseAuthSaveError(variantError, 'beta')).toBe('mTLS needs an https Target');
    expect(responseAuthSaveError(variantError, 'gamma')).toBeNull();
    expect(
      responseAuthSaveError(
        'target.response_auth.mtls.client_certificate_id gateway-cert must be stored with its private key'
      )
    ).toBe('The client certificate gateway-cert must be stored with its private key');
    expect(responseAuthSaveError("transit.points[0]: Transit Point 'crm' x")).toBeNull();
    expect(responseAuthSaveError(null)).toBeNull();
    expect(
      responseAuthWarnings(
        [
          'target.response_auth receives an API key, so its Target must be an https URL',
          "variants['beta'].target.response_auth receives an API key, so its Target must be an https URL",
        ],
        'beta'
      )
    ).toEqual(['Response authentication receives an API key, so its Target must be an https URL']);
  });
});

function makeCtx(nodes: CanvasNode[]): PayloadContext {
  return {
    protocol: 'a2a',
    surfaceMeta: { name: 'response-auth', tags: [], status: 'active' },
    allNodes: nodes,
    nodesOfType: (type: string) => nodes.filter(n => n.type === type),
    firstNodeOfType: (type: string) => nodes.find(n => n.type === type),
  };
}

function targetSavedAgain(target: Record<string, unknown>, canvas?: unknown) {
  const nodes = registry.nodesFromPayload({
    access_point: { route: '/a2a', protocol: 'a2a' },
    target,
    ...(canvas ? { canvas } : {}),
  });
  return { nodes, target: registry.buildPayload(makeCtx(nodes)).target };
}

describe('target.response_auth on save', () => {
  it.each([
    ['an API key', API_KEY],
    ['mTLS with pinned trust and a client certificate', MTLS],
    [
      'mTLS with CA trust',
      { mtls: { server_trust: { type: 'ca', ca_certificate_ids: ['bravo-ca'] } } },
    ],
  ])('keeps a stored %s the operator did not edit verbatim', (_case, responseAuth) => {
    const { target } = targetSavedAgain({
      endpoint: 'https://agent.example',
      response_auth: responseAuth,
    });
    expect(target.response_auth).toEqual(responseAuth);
  });

  it('sends null once switched off, and nothing for a surface that has none', () => {
    const { nodes, target } = targetSavedAgain({
      endpoint: 'https://agent.example',
      response_auth: API_KEY,
    });
    expect(target.response_auth).toEqual(API_KEY);
    const node = nodes.find(n => n.type === 'target')!;
    node.config = { ...node.config, response_auth: null };
    expect(registry.buildPayload(makeCtx(nodes)).target.response_auth).toBeNull();

    expect(targetSavedAgain({ endpoint: 'https://agent.example' }).target).not.toHaveProperty(
      'response_auth'
    );
  });

  it.each(['HTTPS://agent.example', '  https://agent.example  ', 'HTTP://agent.example'])(
    'keeps a stored setting on a Target set through the API as %p',
    endpoint => {
      expect(targetSavedAgain({ endpoint, response_auth: MTLS }).target.response_auth).toEqual(
        MTLS
      );
      expect(responseAuthToWire(endpoint, API_KEY)).toBe(API_KEY);
    }
  );

  it('writes what the panel set, in the wire shape', () => {
    expect(responseAuthToWire('https://a.example', MTLS)).toBe(MTLS);
    expect(responseAuthToWire('http://a.example', API_KEY)).toBe(API_KEY);
    expect(responseAuthToWire('https://a.example', null)).toBeNull();
    expect(responseAuthToWire('https://a.example', undefined)).toBeUndefined();
    expect(responseAuthToWire('fabric://peer/surface', API_KEY)).toBeNull();
    expect(responseAuthToWire('fabric://peer/surface', undefined)).toBeUndefined();
  });

  it.each(['fabric://peer/surface', 'proxy://tools', 'a2a-proxy://worker'])(
    'clears a stored one when the Target becomes %s, and sends nothing when there was none',
    endpoint => {
      const { nodes } = targetSavedAgain({
        endpoint: 'https://agent.example',
        response_auth: API_KEY,
      });
      const node = nodes.find(n => n.type === 'target')!;
      node.config = { ...node.config, endpoint };
      expect(registry.buildPayload(makeCtx(nodes)).target.response_auth).toBeNull();

      expect(targetSavedAgain({ endpoint }).target).not.toHaveProperty('response_auth');
    }
  );

  it('never brings back a setting the stored surface no longer has from the canvas blob', () => {
    const canvas = {
      version: 1,
      nodes: [
        {
          id: 'target',
          type: 'target',
          label: 'Managed Agent',
          config: { endpoint: 'https://agent.example', response_auth: API_KEY },
        },
      ],
    };
    const { target } = targetSavedAgain({ endpoint: 'https://agent.example' }, canvas);
    expect(target).not.toHaveProperty('response_auth');
  });

  it('round-trips a variant override, sends null to clear it, and leaves out one never set', () => {
    const base = {
      access_point: { route: '/a2a', protocol: 'a2a' },
      target: { endpoint: 'https://agent.example', response_auth: API_KEY },
    };
    const own = computeOverridesFromPayload({
      ...base,
      target: { ...base.target, response_auth: MTLS },
    });
    expect(own.target).toMatchObject({ response_auth: MTLS });
    expect(resolveVariant(base, own).target.response_auth).toEqual(MTLS);

    const off = computeOverridesFromPayload({
      ...base,
      target: { endpoint: base.target.endpoint, response_auth: null },
    });
    expect(off.complete).toBe(true);
    expect(off.target).toEqual({ endpoint: base.target.endpoint, response_auth: null });
    expect(resolveVariant(base, off).target.response_auth).toBeNull();

    const none = computeOverridesFromPayload({
      ...base,
      target: { endpoint: base.target.endpoint },
    });
    expect(none.target).not.toHaveProperty('response_auth');
    expect(resolveVariant(base, none).target).not.toHaveProperty('response_auth');
  });

  it('sends null for a variant whose override is cleared by moving its Target off http(s)', () => {
    const nodes = registry.nodesFromPayload({
      access_point: { route: '/a2a', protocol: 'a2a' },
      target: { endpoint: 'https://agent.example', response_auth: MTLS },
    });
    const node = nodes.find(n => n.type === 'target')!;
    node.config = { ...node.config, endpoint: 'proxy://tools' };
    const overrides = computeOverridesFromPayload(registry.buildPayload(makeCtx(nodes)));
    expect(overrides.target).toMatchObject({ response_auth: null });
  });
});

describe('Response authentication copied to variants', () => {
  const stored = {
    access_point: { route: '/a2a', protocol: 'a2a' },
    target: { endpoint: 'https://agent.example' },
    variants: [
      {
        id: 'v-beta',
        alias: 'beta',
        name: 'Beta',
        overrides: { complete: true, target: { endpoint: 'https://beta.example' } },
      },
      {
        id: 'v-canary',
        alias: 'canary',
        name: 'Canary',
        overrides: {
          complete: true,
          target: { endpoint: 'https://canary.example', response_auth: MTLS },
        },
      },
      {
        id: 'v-fabric',
        alias: 'fabric',
        name: 'Fabric',
        overrides: { complete: true, target: { endpoint: 'fabric://gw-2/surface-2' } },
      },
      {
        id: 'v-legacy',
        alias: 'legacy',
        name: 'Legacy',
        overrides: { target: { endpoint: 'http://legacy.example' } },
      },
    ],
  };
  const liveBase = {
    ...stored,
    target: { ...stored.target, response_auth: API_KEY },
    variants: undefined,
  };

  function hydrated() {
    const { result } = renderHook(() => useVariantSnapshots());
    act(() => {
      result.current.hydrateFromPayload(stored);
    });
    return result;
  }

  it('lists the variants with an http(s) Target and no setting, which a save sends as complete', () => {
    const result = hydrated();
    expect(
      variantsWithoutResponseAuth(result.current.variants, result.current.getSnapshot).map(
        v => v.alias
      )
    ).toEqual(['beta', 'legacy']);
  });

  it('never lists a variant without a snapshot, since the save freezes it from the base', () => {
    expect(variantsWithoutResponseAuth([{ id: 'new', alias: 'new' }], () => undefined)).toEqual([]);
  });

  it('sends the copied setting in each listed variant and keeps the others as they are', () => {
    const result = hydrated();
    const missing = variantsWithoutResponseAuth(
      result.current.variants,
      result.current.getSnapshot
    );
    act(() => {
      for (const v of missing) {
        result.current.setSnapshot(
          v.id,
          withResponseAuth(result.current.getSnapshot(v.id), API_KEY)
        );
      }
    });
    expect(
      variantsWithoutResponseAuth(result.current.variants, result.current.getSnapshot)
    ).toEqual([]);

    const wire = result.current.buildVariantsWireSlice(liveBase);
    const sent = Object.fromEntries(
      wire.variants.map(v => [v.alias, v.overrides?.target?.response_auth])
    );
    expect(sent).toEqual({
      beta: API_KEY,
      canary: MTLS,
      fabric: undefined,
      legacy: API_KEY,
    });
    expect(wire.basePayload.target.response_auth).toEqual(API_KEY);
  });

  it('keeps the rest of the variant snapshot when setting its Response authentication', () => {
    expect(
      withResponseAuth({ name: 'x', target: { endpoint: 'https://b.example', auth: 'a' } }, MTLS)
    ).toEqual({
      name: 'x',
      target: { endpoint: 'https://b.example', auth: 'a', response_auth: MTLS },
    });
  });
});
