import React from 'react';
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import { apiClient } from '../../../../../api';
import TrustRecorderEntryForm from '../TrustRecorderEntryForm';
import TrustRecorderFullscreenPanel from '../TrustRecorderFullscreenPanel';
import type { TrustRecorderEntry } from '../definition';
import { SurfaceMetaProvider, type SurfaceMetaValue } from '../../../SurfaceMetaContext';
import { DOCS_URL } from '../../../../../config/docs';
import type { Authority, Issuer, TrustRegistry } from '../../../../../types';

jest.mock('../../../../../api', () => ({
  apiClient: {
    listTrustRegistries: jest.fn(),
    listIssuers: jest.fn(),
    listDepartments: jest.fn(),
    listAuthorities: jest.fn(),
  },
}));

function baseEntry(overrides: Partial<TrustRecorderEntry> = {}): TrustRecorderEntry {
  return {
    trust_registry_id: 'tr-1',
    issuer_did: 'did:web:issuer.example',
    authority_did: '',
    include_owned_agent: true,
    custom_resources: [],
    ...overrides,
  };
}

function baseProps(overrides: Partial<Parameters<typeof TrustRecorderEntryForm>[0]> = {}) {
  const registries: TrustRegistry[] = [
    { id: 'tr-1', name: 'TR One', connection_status: 'connected' } as any,
  ];
  return {
    entry: baseEntry(),
    index: 0,
    registries,
    issuers: [] as Issuer[],
    authorities: [] as Authority[],
    loadError: null,
    issuersLoadError: null,
    authoritiesLoadError: null,
    updateEntry: jest.fn(),
    updateCustomResourceAt: jest.fn(),
    addCustomResource: jest.fn(),
    removeCustomResourceAt: jest.fn(),
    ...overrides,
  } as Parameters<typeof TrustRecorderEntryForm>[0];
}

function renderForm(props: Parameters<typeof TrustRecorderEntryForm>[0]) {
  return render(
    <MemoryRouter>
      <TrustRecorderEntryForm {...props} />
    </MemoryRouter>
  );
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe('TrustRecorderEntryForm — Authority dropdown', () => {
  it('renders authorities from the Authority register with their own description and Issuers with an "Issuer" prefix', () => {
    const authorities: Authority[] = [
      {
        id: 'auth-1',
        name: 'Acme Root',
        did: 'did:web:acme-root.example',
        description: 'Acme root of trust',
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ];
    const issuers: Issuer[] = [
      {
        id: 'issuer-1',
        name: 'Acme HR',
        did: 'did:web:hr.acme.example',
        authority_did: 'did:web:issuer-parent.example',
        description: 'HR issuer',
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ];

    renderForm(baseProps({ authorities, issuers }));

    const toggle = screen.getByTestId('trust-recorder-entry-0-authority');
    // Open the FormSelect listbox to reveal options.
    fireEvent.click(toggle);

    // Authority-register option: label + description come from the Authority row.
    const acmeRoot = screen.getByRole('option', { name: /Acme Root/ });
    expect(acmeRoot).toBeInTheDocument();
    expect(within(acmeRoot).getByText('Acme root of trust')).toBeInTheDocument();

    const acmeHr = screen.getByRole('option', { name: /Acme HR/ });
    expect(acmeHr).toBeInTheDocument();
    expect(within(acmeHr).getByText('Issuer · HR issuer')).toBeInTheDocument();

    // Authority-register entries render before issuer-derived entries in
    // the flat option list.
    const options = screen.getAllByRole('option');
    const authIdx = options.findIndex(o => o.textContent?.includes('Acme Root'));
    const issuerIdx = options.findIndex(o => o.textContent?.includes('Acme HR'));
    expect(authIdx).toBeGreaterThanOrEqual(0);
    expect(issuerIdx).toBeGreaterThan(authIdx);
  });

  it("selecting an Issuer stores the Issuer's own DID, not the authority it registered under", () => {
    const updateEntry = jest.fn();
    const issuers: Issuer[] = [
      {
        id: 'issuer-1',
        name: 'ABC Issuer',
        did: 'did:webvh:scid:gateway.example:issuers:issuer-1',
        authority_did: 'did:webvh:scid:gateway.example',
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ];

    renderForm(baseProps({ issuers, updateEntry }));
    fireEvent.click(screen.getByTestId('trust-recorder-entry-0-authority'));
    fireEvent.click(screen.getByRole('option', { name: /ABC Issuer/ }));

    expect(updateEntry).toHaveBeenCalledWith(0, {
      authority_did: 'did:webvh:scid:gateway.example:issuers:issuer-1',
    });
    expect(updateEntry).not.toHaveBeenCalledWith(0, {
      authority_did: 'did:webvh:scid:gateway.example',
    });
  });

  it('de-duplicates a DID that is both an Authority and an Issuer (Authority wins)', () => {
    const sharedDid = 'did:web:shared.example';
    const authorities: Authority[] = [
      {
        id: 'auth-1',
        name: 'From Authority Register',
        did: sharedDid,
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ];
    const issuers: Issuer[] = [
      {
        id: 'issuer-1',
        name: 'From Issuer',
        did: sharedDid,
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ];

    renderForm(baseProps({ authorities, issuers }));

    fireEvent.click(screen.getByTestId('trust-recorder-entry-0-authority'));

    expect(screen.getByRole('option', { name: /From Authority Register/ })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /From Issuer/ })).toBeNull();
  });

  it('renders a locked "Custom (from JSON API)" option when the stored authority_did matches nothing in either list', () => {
    renderForm(
      baseProps({
        entry: baseEntry({ authority_did: 'did:web:unknown.example' }),
      })
    );

    const toggle = screen.getByTestId('trust-recorder-entry-0-authority');
    // Toggle carries the selected label — the FormSelect renders it on the
    // closed button when a stored value maps to a listed option.
    expect(toggle).toHaveTextContent('Custom (from JSON API)');

    fireEvent.click(toggle);
    const customOption = screen.getByRole('option', { name: /Custom \(from JSON API\)/ });
    expect(customOption).toBeInTheDocument();
    // The custom slot is disabled — picking it is a no-op; the operator can
    // only overwrite by choosing a real Authority / Issuer.
    expect(customOption).toBeDisabled();
  });

  it('disables the Authority toggle and shows a plain-text empty-state hint when no Authorities or issuer-derived options exist', () => {
    renderForm(baseProps());

    const toggle = screen.getByTestId('trust-recorder-entry-0-authority');
    expect(toggle).toBeDisabled();
    // Placeholder from the FormSelect renders on the closed toggle.
    expect(toggle).toHaveTextContent(/Select an authority/i);

    // Empty-state hint replaces the old button-on-right pattern.
    const hint = screen.getByTestId('trust-recorder-entry-0-authority-empty-hint');
    expect(hint).toBeInTheDocument();
    expect(within(hint).getByText(/No Authorities configured yet/i)).toBeInTheDocument();
    expect(within(hint).getByTestId('trust-recorder-entry-0-add-authority-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });

  it('shows a populated-state "Add Authority" shortcut when at least one Authority is present', () => {
    renderForm(
      baseProps({
        authorities: [
          {
            id: 'auth-1',
            name: 'Acme',
            did: 'did:web:acme.example',
            created_at: '2026-07-01T10:00:00Z',
            updated_at: '2026-07-01T10:00:00Z',
          },
        ],
      })
    );

    const toggle = screen.getByTestId('trust-recorder-entry-0-authority');
    expect(toggle).not.toBeDisabled();
    // Nudge is always visible; only the leading copy toggles.
    const hint = screen.getByTestId('trust-recorder-entry-0-authority-empty-hint');
    expect(within(hint).getByText(/Don't see the one you need\?/i)).toBeInTheDocument();
    expect(within(hint).getByTestId('trust-recorder-entry-0-add-authority-link')).toHaveAttribute(
      'target',
      '_blank'
    );

    fireEvent.click(toggle);
    expect(screen.getByRole('option', { name: /Acme/ })).toBeInTheDocument();
  });

  it('surfaces both issuers and authorities load errors independently', () => {
    renderForm(
      baseProps({
        issuersLoadError: 'issuer load failed',
        authoritiesLoadError: 'auth load failed',
      })
    );

    // `issuersLoadError` renders under both the Issuer and the Authority
    // dropdowns, so the message appears twice by design; the picker owns only
    // one of those slots.
    expect(screen.getAllByText('issuer load failed').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('auth load failed')).toBeInTheDocument();
  });
});

describe('TrustRecorderEntryForm — empty-pool hints for Trust Registry and Issuer', () => {
  it('disables the Trust Registry toggle and shows a plain-text hint when no registries are configured', () => {
    renderForm(baseProps({ registries: [] }));

    const toggle = screen.getByTestId('trust-recorder-entry-0-registry');
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveTextContent(/Select a trust registry/i);

    const hint = screen.getByTestId('trust-recorder-entry-0-registry-empty-hint');
    expect(within(hint).getByText(/No Trust Registries configured yet/i)).toBeInTheDocument();
    expect(within(hint).getByTestId('trust-recorder-entry-0-add-registry-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });

  it('disables the Issuer toggle and shows a plain-text hint when no issuers are configured', () => {
    renderForm(baseProps({ issuers: [] }));

    const toggle = screen.getByTestId('trust-recorder-entry-0-issuer');
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveTextContent(/Select an issuer/i);

    const hint = screen.getByTestId('trust-recorder-entry-0-issuer-empty-hint');
    expect(within(hint).getByText(/No Issuers configured yet/i)).toBeInTheDocument();
    expect(within(hint).getByTestId('trust-recorder-entry-0-add-issuer-link')).toHaveAttribute(
      'target',
      '_blank'
    );
  });

  it('does not render the empty-state hint when a network load error is present (the load error carries the signal instead)', () => {
    renderForm(
      baseProps({
        registries: [],
        loadError: 'network is down',
      })
    );

    expect(screen.queryByTestId('trust-recorder-entry-0-registry-empty-hint')).toBeNull();
    expect(screen.getByText('network is down')).toBeInTheDocument();
  });
});

describe('TrustRecorderFullscreenPanel — data loading', () => {
  it('passes loaded issuers into the entry form without crashing', async () => {
    (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([
      { id: 'tr-1', name: 'TR One', connection_status: 'connected' },
    ]);
    (apiClient.listIssuers as jest.Mock).mockResolvedValue([
      {
        id: 'issuer-1',
        name: 'Acme HR',
        did: 'did:web:hr.acme.example',
        authority_did: 'did:web:issuer-parent.example',
        created_at: '2026-07-01T10:00:00Z',
        updated_at: '2026-07-01T10:00:00Z',
      },
    ]);
    (apiClient.listAuthorities as jest.Mock).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <TrustRecorderFullscreenPanel
          config={{}}
          updateField={jest.fn()}
          updateFields={jest.fn()}
        />
      </MemoryRouter>
    );

    await waitFor(() => expect(apiClient.listIssuers).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByTestId('trust-recorder-entry-0-issuer')).not.toBeDisabled()
    );

    fireEvent.click(screen.getByTestId('trust-recorder-entry-0-issuer'));
    expect(screen.getByRole('option', { name: /Acme HR/ })).toBeInTheDocument();
  });
});

describe('TrustRecorderEntryForm — Use surface Issuer toggle', () => {
  it('starts in Explicit DID mode when authority_did is empty', () => {
    renderForm(baseProps());
    const explicit = screen.getByTestId(
      'trust-recorder-entry-0-authority-mode-explicit-radio'
    ) as HTMLInputElement;
    const surface = screen.getByTestId(
      'trust-recorder-entry-0-authority-mode-surface-issuer-radio'
    ) as HTMLInputElement;
    expect(explicit.checked).toBe(true);
    expect(surface.checked).toBe(false);
    expect(screen.getByTestId('trust-recorder-entry-0-authority')).toBeInTheDocument();
    expect(
      screen.queryByTestId('trust-recorder-entry-0-authority-surface-issuer-value')
    ).not.toBeInTheDocument();
  });

  it('starts in Use surface Issuer mode when authority_did stores the template', () => {
    renderForm(baseProps({ entry: baseEntry({ authority_did: '{{ surface.issuer_did }}' }) }));
    const surface = screen.getByTestId(
      'trust-recorder-entry-0-authority-mode-surface-issuer-radio'
    ) as HTMLInputElement;
    expect(surface.checked).toBe(true);
    // The FormSelect picker must be hidden in this mode.
    expect(screen.queryByTestId('trust-recorder-entry-0-authority')).not.toBeInTheDocument();
    // The template value must be visible in the locked textbox.
    expect(screen.getByTestId('trust-recorder-entry-0-authority-surface-issuer-value')).toHaveValue(
      '{{ surface.issuer_did }}'
    );
  });

  it('writes the template into authority_did when the operator switches to Use surface Issuer', () => {
    const updateEntry = jest.fn();
    renderForm(
      baseProps({ entry: baseEntry({ authority_did: 'did:web:literal.example' }), updateEntry })
    );
    fireEvent.click(
      screen.getByTestId('trust-recorder-entry-0-authority-mode-surface-issuer-radio')
    );
    expect(updateEntry).toHaveBeenCalledWith(0, {
      authority_did: '{{ surface.issuer_did }}',
    });
  });

  it('clears authority_did back to empty when switching from Use surface Issuer to Explicit DID', () => {
    const updateEntry = jest.fn();
    renderForm(
      baseProps({
        entry: baseEntry({ authority_did: '{{ surface.issuer_did }}' }),
        updateEntry,
      })
    );
    fireEvent.click(screen.getByTestId('trust-recorder-entry-0-authority-mode-explicit-radio'));
    expect(updateEntry).toHaveBeenCalledWith(0, { authority_did: '' });
  });
});

describe('TrustRecorderEntryForm — custom resource row', () => {
  const entryWithResource = () =>
    baseEntry({
      custom_resources: [
        {
          action: 'is',
          resource: 'paymentAgent',
          entity_target: 'agent',
          record_type: 'recognition',
        },
      ],
    });

  it('labels every column so action and resource align with the selects', () => {
    renderForm(baseProps({ entry: entryWithResource() }));

    expect(screen.getByLabelText('Action')).toHaveValue('is');
    expect(screen.getByLabelText('Resource')).toHaveValue('paymentAgent');
    expect(screen.getByLabelText('Entity Target')).toHaveValue('agent');
    expect(screen.getByLabelText('Record Type')).toHaveValue('recognition');
  });

  it('lets the text inputs shrink and keeps the selects at a fixed width', () => {
    renderForm(baseProps({ entry: entryWithResource() }));

    const column = (field: string) =>
      screen.getByTestId(`trust-recorder-entry-0-custom-resource-0-${field}-column`);

    expect(column('action')).toHaveStyle({ flex: '1 1 0', minWidth: '0' });
    expect(column('resource')).toHaveStyle({ flex: '1 1 0', minWidth: '0' });
    expect(column('target')).toHaveStyle({ flex: '0 0 140px' });
    expect(column('record-type')).toHaveStyle({ flex: '0 0 150px' });
  });
});

describe('TrustRecorderEntryForm — surface Issuer warning', () => {
  const WARNING = 'trust-recorder-entry-0-no-surface-issuer-warning';
  const surfaceEntry = () => baseEntry({ authority_did: '{{ surface.issuer_did }}' });

  function renderInSurface(props: Parameters<typeof TrustRecorderEntryForm>[0], issuerId: string) {
    const meta = { issuerId } as unknown as SurfaceMetaValue;
    return render(
      <MemoryRouter>
        <SurfaceMetaProvider value={meta}>
          <TrustRecorderEntryForm {...props} />
        </SurfaceMetaProvider>
      </MemoryRouter>
    );
  }

  it('warns under Use surface Issuer when the surface has no Issuer', () => {
    renderInSurface(baseProps({ entry: surfaceEntry() }), '');

    const warning = screen.getByTestId(WARNING);
    expect(warning).toHaveTextContent('No Issuer is selected for this surface');
    expect(warning).toHaveTextContent('This entry uses the surface Issuer as its Authority');
    expect(warning).toHaveTextContent('writes no records');
  });

  it('treats a template padded with whitespace as Use surface Issuer, as the backend does', () => {
    renderInSurface(
      baseProps({ entry: baseEntry({ authority_did: '  {{ surface.issuer_did }}\n' }) }),
      ''
    );

    expect(
      screen.getByTestId('trust-recorder-entry-0-authority-mode-surface-issuer-radio')
    ).toBeChecked();
    expect(screen.getByTestId(WARNING)).toBeInTheDocument();
  });

  it('does not warn when the surface has an Issuer', () => {
    renderInSurface(baseProps({ entry: surfaceEntry() }), 'issuer-1');
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

  it('does not warn in Explicit DID mode even when the surface has no Issuer', () => {
    renderInSurface(
      baseProps({ entry: baseEntry({ authority_did: 'did:web:authority.example' }) }),
      ''
    );
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

  it('does not warn outside a surface editor', () => {
    renderForm(baseProps({ entry: surfaceEntry() }));
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();
  });

  it('shows the warning as soon as the operator switches to Use surface Issuer', () => {
    const updateEntry = jest.fn();
    const { rerender } = renderInSurface(baseProps({ entry: baseEntry(), updateEntry }), '');
    expect(screen.queryByTestId(WARNING)).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByTestId('trust-recorder-entry-0-authority-mode-surface-issuer-radio')
    );
    expect(updateEntry).toHaveBeenCalledWith(0, { authority_did: '{{ surface.issuer_did }}' });

    rerender(
      <MemoryRouter>
        <SurfaceMetaProvider value={{ issuerId: '' } as unknown as SurfaceMetaValue}>
          <TrustRecorderEntryForm {...baseProps({ entry: surfaceEntry(), updateEntry })} />
        </SurfaceMetaProvider>
      </MemoryRouter>
    );
    expect(screen.getByTestId(WARNING)).toBeInTheDocument();
  });
});

describe('TrustRecorderEntryForm — Issuer wording', () => {
  it('describes the entry Issuer as the Entity of Issuer DID records, not as a signer', () => {
    renderForm(baseProps());
    const form = screen.getByTestId('trust-recorder-entry-0-form');
    expect(form).toHaveTextContent('Recorded as the Entity of custom records');
    expect(form).toHaveTextContent('It does not sign records or set the Authority.');
    expect(form).not.toHaveTextContent('signs the records');
  });

  it('words the missing-Issuer validation without claiming the Issuer signs', () => {
    renderForm(baseProps({ entry: baseEntry({ issuer_did: '' }), saveAttempted: true } as any));
    expect(screen.getByText('Select an Issuer for this entry.')).toBeInTheDocument();
  });
});

describe('TrustRecorderFullscreenPanel — Issuer, Authority and Entity explainer', () => {
  function renderPanel() {
    (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([]);
    (apiClient.listIssuers as jest.Mock).mockResolvedValue([]);
    (apiClient.listAuthorities as jest.Mock).mockResolvedValue([]);
    return render(
      <MemoryRouter>
        <TrustRecorderFullscreenPanel
          config={{}}
          updateField={jest.fn()}
          updateFields={jest.fn()}
        />
      </MemoryRouter>
    );
  }

  it('is collapsed by default and opens on demand', async () => {
    renderPanel();
    await waitFor(() => expect(apiClient.listIssuers).toHaveBeenCalled());

    const toggle = screen.getByTestId('trust-recorder-fullscreen-context-toggle');
    expect(toggle).toHaveTextContent('How do Issuer, Authority and Entity relate?');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByTestId('trust-recorder-fullscreen-context-body')).toBeNull();

    fireEvent.click(toggle);
    const body = screen.getByTestId('trust-recorder-fullscreen-context-body');
    for (const term of ['Authority', 'Entity', 'Issuer (this entry)', 'Surface Issuer']) {
      expect(within(body).getByText(term)).toBeInTheDocument();
    }
    expect(body).toHaveTextContent('no records are written');
  });

  it('links to the Trust Recorder guide in a new tab', async () => {
    renderPanel();
    await waitFor(() => expect(apiClient.listIssuers).toHaveBeenCalled());
    fireEvent.click(screen.getByTestId('trust-recorder-fullscreen-context-toggle'));

    const link = screen.getByTestId('trust-recorder-fullscreen-context-doclink');
    expect(link).toHaveAttribute('href', DOCS_URL.trustElements);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(link).toHaveTextContent('Read the Trust Recorder guide');
  });
});
