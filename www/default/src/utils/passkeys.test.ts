import { apiClient } from '../api';
import { registerPasskey } from './passkeys';

jest.mock('../api', () => ({
  apiClient: { fetch: jest.fn() },
  sessionManager: {},
}));

class FakeAttestationResponse {
  attestationObject = new Uint8Array([1, 2, 3]).buffer;
  clientDataJSON = new Uint8Array([4, 5, 6]).buffer;
}

const START_URL = '/api/auth/register/start';
const FINISH_URL = '/api/auth/register/finish';

beforeEach(() => {
  jest.resetAllMocks();
  Object.assign(globalThis, { AuthenticatorAttestationResponse: FakeAttestationResponse });
  Object.assign(window, { PublicKeyCredential: function PublicKeyCredential() {} });
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: {
      create: jest.fn().mockResolvedValue({
        id: 'credential-1',
        rawId: new Uint8Array([7, 8, 9]).buffer,
        type: 'public-key',
        response: new FakeAttestationResponse(),
      }),
    },
  });
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve(
      url === START_URL
        ? new Response(
            JSON.stringify({
              challenge_id: 'challenge-1',
              creation_options: {
                publicKey: {
                  challenge: 'AQID',
                  user: { id: 'BAUG', name: 'alice', displayName: 'alice' },
                },
              },
            })
          )
        : new Response(null, { status: 200 })
    )
  );
});

afterEach(() => {
  Reflect.deleteProperty(globalThis, 'AuthenticatorAttestationResponse');
  Reflect.deleteProperty(window, 'PublicKeyCredential');
  Reflect.deleteProperty(navigator, 'credentials');
});

function requestBody(url: string): Record<string, unknown> {
  const call = (apiClient.fetch as jest.Mock).mock.calls.find(([calledUrl]) => calledUrl === url);
  expect(call).toBeDefined();
  return JSON.parse(call[1].body);
}

test('sends the setup token on registration start and finish', async () => {
  await expect(registerPasskey('alice', [], 'first-admin-token')).resolves.toEqual({
    success: true,
  });

  expect(requestBody(START_URL)).toEqual({ username: 'alice', setup_token: 'first-admin-token' });
  expect(requestBody(FINISH_URL)).toMatchObject({
    challenge_id: 'challenge-1',
    accepted_terms: [],
    setup_token: 'first-admin-token',
  });
});

test('sends no setup token when none is given', async () => {
  await expect(registerPasskey('alice')).resolves.toEqual({ success: true });

  expect(requestBody(START_URL)).toEqual({ username: 'alice' });
  expect(requestBody(FINISH_URL)).toMatchObject({ challenge_id: 'challenge-1' });
  expect(requestBody(FINISH_URL)).not.toHaveProperty('setup_token');
});
