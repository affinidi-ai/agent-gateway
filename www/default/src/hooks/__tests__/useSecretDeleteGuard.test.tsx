import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { useSecretDeleteGuard } from '../useSecretDeleteGuard';

const mockFetch = jest.fn();
const mockHasPermission = jest.fn();
jest.mock('../../api', () => ({
  apiClient: { fetch: (...args: unknown[]) => mockFetch(...args) },
}));
jest.mock('../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: mockHasPermission }),
}));

const remove = jest.fn();

const Harness: React.FC = () => {
  const headingRef = React.useRef<HTMLHeadingElement>(null);
  const { guardDelete, warningNode } = useSecretDeleteGuard(headingRef);
  return (
    <div>
      <h2 ref={headingRef} tabIndex={-1}>
        Secrets
      </h2>
      <button onClick={() => guardDelete({ secret_id: 'shared', name: 'Shared secret' }, remove)}>
        delete
      </button>
      {warningNode}
    </div>
  );
};

const json = (body: unknown, ok = true) => Promise.resolve({ ok, json: async () => body });

const providers = (...refs: Array<[string, Record<string, unknown>]>) =>
  mockFetch.mockImplementation((url: string) => {
    if (url === '/api/v1/credential-providers') {
      return json(refs.map(([name], i) => ({ id: `p${i}`, name })));
    }
    const index = Number(url.split('/p')[1]);
    return json(refs[index][1]);
  });

beforeEach(() => {
  jest.clearAllMocks();
  remove.mockResolvedValue(undefined);
  mockHasPermission.mockReturnValue(true);
});

describe('useSecretDeleteGuard', () => {
  it('names the referencing providers and deletes only after confirmation', async () => {
    providers(
      ['Hop 2 client credentials', { client_secret_secret_ref: 'shared' }],
      ['Signing provider', { jwt_bearer: { signing_key_secret_ref: 'shared' } }],
      ['Unrelated', { api_key_secret_ref: 'other' }]
    );
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    const warning = await screen.findByTestId('secret-delete-warning');
    expect(warning).toHaveAttribute('role', 'alertdialog');
    expect(warning).toHaveTextContent('Delete secret "Shared secret"?');
    expect(warning).toHaveTextContent('will lose their credential');
    expect(
      screen.getAllByTestId('secret-delete-warning-provider').map(li => li.textContent)
    ).toEqual(['Hop 2 client credentials', 'Signing provider']);
    expect(remove).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('secret-delete-warning-confirm-button'));
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument()
    );
  });

  it('uses the singular for one provider', async () => {
    providers(['Only provider', { api_key_secret_ref: 'shared' }]);
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    expect(await screen.findByTestId('secret-delete-warning')).toHaveTextContent(
      'This credential provider references it and will lose its credential'
    );
  });

  it('keeps the secret when the operator cancels', async () => {
    providers(['Only provider', { api_key_secret_ref: 'shared' }]);
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));
    fireEvent.click(await screen.findByTestId('secret-delete-warning-cancel-button'));

    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
    expect(remove).not.toHaveBeenCalled();
  });

  it('deletes at once, with no warning, when no provider references the secret', async () => {
    providers(['Unrelated', { api_key_secret_ref: 'other' }]);
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
  });

  it('deletes at once when there are no providers at all', async () => {
    providers();
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
  });

  it('warns that it could not check when the providers cannot be read, and still lets the delete go ahead', async () => {
    mockFetch.mockImplementation(() => json({}, false));
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    expect(await screen.findByTestId('secret-delete-warning-unknown')).toHaveTextContent(
      'Could not check which credential providers reference it'
    );
    expect(screen.queryByTestId('secret-delete-warning-provider')).not.toBeInTheDocument();
    expect(remove).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('secret-delete-warning-confirm-button'));
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
  });

  it('deletes without looking at providers when the role cannot view them', async () => {
    mockHasPermission.mockImplementation(
      (permission: string) => permission !== 'credential_providers.view'
    );
    render(<Harness />);
    fireEvent.click(screen.getByText('delete'));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    expect(mockFetch).not.toHaveBeenCalled();
    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
  });

  it('takes focus when it opens and returns it to the Delete button on Cancel', async () => {
    providers(['Only provider', { api_key_secret_ref: 'shared' }]);
    render(<Harness />);
    const trigger = screen.getByText('delete');
    trigger.focus();
    fireEvent.click(trigger);

    const warning = await screen.findByTestId('secret-delete-warning');
    await waitFor(() => expect(warning).toHaveFocus());
    fireEvent.click(screen.getByTestId('secret-delete-warning-cancel-button'));
    expect(trigger).toHaveFocus();
  });

  it('closes on Escape without deleting and returns focus to the Delete button', async () => {
    providers(['Only provider', { api_key_secret_ref: 'shared' }]);
    render(<Harness />);
    const trigger = screen.getByText('delete');
    trigger.focus();
    fireEvent.click(trigger);

    fireEvent.keyDown(await screen.findByTestId('secret-delete-warning'), { key: 'Escape' });
    expect(screen.queryByTestId('secret-delete-warning')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(remove).not.toHaveBeenCalled();
  });

  it('moves focus to the list heading after a confirmed delete', async () => {
    providers(['Only provider', { api_key_secret_ref: 'shared' }]);
    render(<Harness />);
    const trigger = screen.getByText('delete');
    trigger.focus();
    fireEvent.click(trigger);

    fireEvent.click(await screen.findByTestId('secret-delete-warning-confirm-button'));
    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Secrets' })).toHaveFocus());
  });
});
