import { buildMethod, methodConfigFromPayload, methodIncompleteReason } from '../methods';

const JWT = { method_type: 'jwt_bearer' as const, jwt_strategy_id: 'idp' };

describe('JWT Bearer audience claim', () => {
  it('needs a listed client before a client-bound method can be saved', () => {
    expect(
      methodIncompleteReason({ ...JWT, jwt_audience_claim: 'client_id', audiences: [' '] })
    ).toBe('List the client_id values this method accepts');
    expect(methodIncompleteReason({ ...JWT, jwt_audience_claim: 'azp', audiences: [] })).toBe(
      'List the azp values this method accepts'
    );
    expect(
      methodIncompleteReason({ ...JWT, jwt_audience_claim: 'client_id', audiences: ['app-1'] })
    ).toBeNull();
  });

  it('leaves an aud method without audiences to the gateway, which keeps a stored one', () => {
    expect(methodIncompleteReason({ ...JWT, audiences: [] })).toBeNull();
  });

  it('sends audience_claim only when it is not aud and reads it back', () => {
    const clientBound = buildMethod(
      { ...JWT, audiences: ['app-1'], jwt_audience_claim: 'client_id' },
      'surface'
    );
    expect(clientBound).toMatchObject({ audiences: ['app-1'], audience_claim: 'client_id' });
    expect(methodConfigFromPayload(clientBound).jwt_audience_claim).toBe('client_id');

    const audBound = buildMethod({ ...JWT, audiences: ['api'], jwt_audience_claim: 'aud' }, 's');
    expect(audBound).not.toHaveProperty('audience_claim');
    expect(methodConfigFromPayload(audBound).jwt_audience_claim).toBe('aud');
  });
});
