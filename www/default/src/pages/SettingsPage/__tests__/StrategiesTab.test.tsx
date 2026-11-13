import { strategyDeleteError } from '../StrategiesTab';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => false, loading: false }),
}));

describe('strategyDeleteError', () => {
  const message =
    'The strategy is used by credential providers; remove their references to it first';
  const where =
    ". Change a provider's consent confirmation in its editor; its consent_identity_strategy_id is changed through the API";

  it('names the credential providers a refused delete lists and counts the hidden ones', () => {
    const body = JSON.stringify({
      message,
      references: [
        { kind: 'credential_provider', id: 'github', name: 'GitHub' },
        { kind: 'credential_provider', id: 'linear', name: '' },
      ],
      hidden_references: 1,
    });
    expect(strategyDeleteError(409, body, '')).toBe(
      `${message} (providers GitHub, linear and 1 you can't view)${where} (409)`
    );
  });

  it('counts the providers a caller cannot view when it may view none', () => {
    const body = JSON.stringify({ message, references: [], hidden_references: 2 });
    expect(strategyDeleteError(409, body, '')).toBe(
      `${message} (providers 2 you can't view)${where} (409)`
    );
  });

  it('shows another failure without providers or where to change them', () => {
    expect(strategyDeleteError(500, '', '')).toBe('Request failed (500)');
  });
});
