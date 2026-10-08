import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import {
  CredentialPrincipalLabel,
  IdentityNameCell,
  NamedIdentity,
  parseAgentName,
} from '../IdentityNameCell';

const LONG_DID = 'did:webvh:zQmScid0123456789abcdef:gateway.example.com:surface:0123456789abcdef';

const renderCell = (identity: Partial<NamedIdentity>, liveSurfaceName?: string) =>
  render(
    <IdentityNameCell identity={{ did: LONG_DID, ...identity }} liveSurfaceName={liveSurfaceName} />
  );

describe('IdentityNameCell', () => {
  beforeEach(() => {
    Object.assign(navigator, { clipboard: { writeText: jest.fn(() => Promise.resolve()) } });
  });

  it('shows the name with a shortened monospace DID and copies the full DID', async () => {
    renderCell({ display_name: 'OXYGEN', display_name_source: 'surface_name' });

    expect(screen.getByTestId('identities-name')).toHaveTextContent('OXYGEN');
    const code = screen.getByTitle(LONG_DID);
    expect(code.tagName).toBe('CODE');
    expect(code.textContent).not.toBe(LONG_DID);
    expect(code.textContent).toContain('...');

    fireEvent.click(screen.getByTestId('identities-copy-did-button'));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(LONG_DID));
  });

  it('prefers the live surface name for surface-named identities', () => {
    renderCell({ display_name: 'OXYGEN', display_name_source: 'surface_name' }, 'OXYGEN-2');

    expect(screen.getByTestId('identities-name')).toHaveTextContent('OXYGEN-2');
  });

  it('ignores the live surface name for caller names', () => {
    renderCell({ display_name: 'Billing Bot', display_name_source: 'agent_card' }, 'OXYGEN');

    expect(screen.getByTestId('identities-name')).toHaveTextContent('Billing Bot');
    expect(screen.getByTestId('identities-name')).not.toHaveTextContent('OXYGEN');
  });

  it('marks a managed agent name from its target Agent Card as unverified', () => {
    renderCell({ display_name: 'DateTime Agent', display_name_source: 'target_agent_card' }, 'DEF');

    expect(screen.getByTestId('identities-name')).toHaveTextContent('DateTime Agent');
    expect(screen.getByTestId('identities-name')).not.toHaveTextContent('DEF');
    expect(screen.getByTestId('identities-name-unverified')).toHaveAttribute(
      'title',
      expect.stringContaining("target's Agent Card")
    );
    expect(screen.queryByTestId('identities-name-verified')).not.toBeInTheDocument();
  });

  it('shows a managed agent surface name without any badge', () => {
    renderCell({ display_name: 'DEF', display_name_source: 'surface_name' }, 'DEF');

    expect(screen.getByTestId('identities-name')).toHaveTextContent('DEF');
    expect(screen.queryByTestId('identities-name-unverified')).not.toBeInTheDocument();
  });

  it('makes the DID the primary line when no name is known', () => {
    renderCell({});

    expect(screen.queryByTestId('identities-name')).not.toBeInTheDocument();
    expect(screen.queryByText('No name')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identities-name-pending')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identities-name-conflict')).not.toBeInTheDocument();
    expect(screen.getByTitle(LONG_DID).style.fontSize).toBe('');
    expect(screen.getByTestId('identities-copy-did-button')).toBeInTheDocument();
  });

  it('keeps the DID secondary when a name is shown', () => {
    renderCell({ display_name: 'OXYGEN', display_name_source: 'surface_name' });

    expect(screen.getByTitle(LONG_DID).style.fontSize).toBe('0.75rem');
  });

  it('shows resolving above the DID while the caller name lookup is pending', () => {
    renderCell({ display_name_pending: true });

    expect(screen.getByTestId('identities-name-pending')).toHaveTextContent('resolving…');
    expect(screen.queryByTestId('identities-name')).not.toBeInTheDocument();
    expect(screen.getByTitle(LONG_DID).style.fontSize).toBe('0.75rem');
  });

  it('prefers a resolved name over the pending flag', () => {
    renderCell({
      display_name: 'Billing Bot',
      display_name_source: 'agent_card',
      display_name_pending: true,
    });

    expect(screen.getByTestId('identities-name')).toHaveTextContent('Billing Bot');
    expect(screen.queryByTestId('identities-name-pending')).not.toBeInTheDocument();
  });

  it('shows the DID as primary with the name conflict marker beside it', () => {
    renderCell({ name_conflict: true });

    expect(screen.getByTestId('identities-name-conflict')).toHaveTextContent('name conflict');
    expect(screen.queryByTestId('identities-name')).not.toBeInTheDocument();
    expect(screen.getByTitle(LONG_DID).style.fontSize).toBe('');
  });

  it('shows a verified agent name as local · host with the domain prominent', () => {
    renderCell({
      display_name: 'acme.com/@billing',
      display_name_source: 'agent_name',
      display_name_verified: true,
    });

    expect(screen.getByTestId('identities-name')).toHaveTextContent('billing · acme.com');
    expect(screen.getByText('acme.com').tagName).toBe('STRONG');
    expect(screen.getByRole('img', { name: 'Verified agent name' })).toBeInTheDocument();
    expect(screen.queryByTestId('identities-name-unverified')).not.toBeInTheDocument();
  });

  it('omits the verified marker when the agent name is not verified', () => {
    renderCell({ display_name: 'acme.com/@billing', display_name_source: 'agent_name' });

    expect(screen.queryByTestId('identities-name-verified')).not.toBeInTheDocument();
  });

  it('marks Agent Card names as unverified', () => {
    renderCell({ display_name: 'Billing Bot', display_name_source: 'agent_card' });

    expect(screen.getByTestId('identities-name-unverified')).toHaveTextContent('unverified');
    expect(screen.queryByTestId('identities-name-verified')).not.toBeInTheDocument();
  });

  it('renders only the DID line when names are hidden', () => {
    render(
      <IdentityNameCell
        identity={{ did: LONG_DID, display_name_pending: true, name_conflict: true }}
        showName={false}
      />
    );

    expect(screen.queryByTestId('identities-name')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identities-name-pending')).not.toBeInTheDocument();
    expect(screen.queryByTestId('identities-name-conflict')).not.toBeInTheDocument();
    expect(screen.getByTitle(LONG_DID)).toBeInTheDocument();
  });
});

describe('parseAgentName', () => {
  it('splits host and local part', () => {
    expect(parseAgentName('acme.com/@billing')).toEqual({ host: 'acme.com', local: 'billing' });
  });

  it('rejects strings that are not agent names', () => {
    expect(parseAgentName('Billing Bot')).toBeNull();
    expect(parseAgentName('/@billing')).toBeNull();
    expect(parseAgentName('acme.com/@')).toBeNull();
  });
});

describe('CredentialPrincipalLabel', () => {
  it('shows the principal name with its kind', () => {
    render(
      <CredentialPrincipalLabel
        principal={{ kind: 'certificate', id: 'cert-1', name: 'NITROGEN' }}
      />
    );

    const label = screen.getByTestId('identities-credential-principal');
    expect(label).toHaveTextContent('Certificate: NITROGEN');
    expect(label).toHaveAttribute('title', 'Certificate cert-1');
  });

  it('falls back to the id when the principal has no name', () => {
    render(<CredentialPrincipalLabel principal={{ kind: 'api_key', id: 'key-7' }} />);

    expect(screen.getByTestId('identities-credential-principal')).toHaveTextContent(
      'API key: key-7'
    );
  });

  it('renders nothing without a principal', () => {
    const { container } = render(<CredentialPrincipalLabel />);

    expect(container).toBeEmptyDOMElement();
  });
});
