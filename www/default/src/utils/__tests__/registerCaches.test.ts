import { apiClient } from '../../api';
import { clearAuthoritiesCache, getAuthorities } from '../authoritiesCache';
import { clearIssuersCache, getIssuers } from '../issuersCache';

jest.mock('../../api', () => ({
  apiClient: {
    listAuthorities: jest.fn(),
    listIssuers: jest.fn(),
  },
}));

const listAuthorities = apiClient.listAuthorities as jest.Mock;
const listIssuers = apiClient.listIssuers as jest.Mock;

describe('register caches', () => {
  beforeEach(() => {
    clearAuthoritiesCache();
    clearIssuersCache();
    jest.clearAllMocks();
  });

  it('memoizes authorities until a caller requests a refresh', async () => {
    listAuthorities.mockResolvedValueOnce([{ id: 'a-old', name: 'Old', did: 'did:web:old' }]);

    await expect(getAuthorities()).resolves.toEqual([
      { id: 'a-old', name: 'Old', did: 'did:web:old' },
    ]);
    await expect(getAuthorities()).resolves.toEqual([
      { id: 'a-old', name: 'Old', did: 'did:web:old' },
    ]);
    expect(listAuthorities).toHaveBeenCalledTimes(1);

    listAuthorities.mockResolvedValueOnce([{ id: 'a-new', name: 'New', did: 'did:web:new' }]);

    await expect(getAuthorities({ refresh: true })).resolves.toEqual([
      { id: 'a-new', name: 'New', did: 'did:web:new' },
    ]);
    expect(listAuthorities).toHaveBeenCalledTimes(2);
  });

  it('memoizes issuers until a caller requests a refresh', async () => {
    listIssuers.mockResolvedValueOnce([{ id: 'd-old', name: 'Old', did: 'did:web:old' }]);

    await expect(getIssuers()).resolves.toEqual([{ id: 'd-old', name: 'Old', did: 'did:web:old' }]);
    await expect(getIssuers()).resolves.toEqual([{ id: 'd-old', name: 'Old', did: 'did:web:old' }]);
    expect(listIssuers).toHaveBeenCalledTimes(1);

    listIssuers.mockResolvedValueOnce([{ id: 'd-new', name: 'New', did: 'did:web:new' }]);

    await expect(getIssuers({ refresh: true })).resolves.toEqual([
      { id: 'd-new', name: 'New', did: 'did:web:new' },
    ]);
    expect(listIssuers).toHaveBeenCalledTimes(2);
  });
});
