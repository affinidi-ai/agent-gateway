import { strategyDeleteError } from '../StrategiesTab';

jest.mock('../../../api', () => ({
  apiClient: { get: jest.fn(), put: jest.fn(), post: jest.fn(), fetch: jest.fn() },
}));
jest.mock('../../../context/PermissionsContext', () => ({
  usePermissions: () => ({ hasPermission: () => false, loading: false }),
}));

describe('strategyDeleteError', () => {
  it('names the credential providers a refused delete lists', () => {
    const body = JSON.stringify({
      message: 'The strategy is used by credential providers; remove their references to it first',
      references: [
        { kind: 'credential_provider', id: 'github', name: 'GitHub' },
        { kind: 'credential_provider', id: 'linear', name: 'Linear' },
      ],
      hidden_references: 1,
    });
    expect(strategyDeleteError(409, body, '')).toBe(
      'The strategy is used by credential providers; remove their references to it first (providers github, linear) (409)'
    );
    expect(strategyDeleteError(500, '', '')).toBe('Request failed (500)');
  });
});
