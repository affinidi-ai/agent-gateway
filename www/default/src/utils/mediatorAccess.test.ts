import { ApiError } from '../api';
import {
  ADD_GATEWAY_DID_LABELS,
  CONNECTION_POINT_DID_LABELS,
  labelledDids,
  mediatorAccessRefusal,
} from './mediatorAccess';

describe('mediatorAccess', () => {
  it('labels each DID by its role, in the order the gateway sent them', () => {
    const dids = labelledDids(
      {
        mediator_did: 'did:web:mediator.example',
        mediator_name: 'Mediator X',
        dids: [
          {
            role: 'connection_point',
            did: 'did:peer:2.cp',
            mediator_did: 'did:web:mediator.example',
          },
          { role: 'permanent', did: 'did:peer:2.perm', mediator_did: 'did:web:mediator.example' },
        ],
      },
      CONNECTION_POINT_DID_LABELS
    );

    expect(dids).toEqual([
      {
        role: 'connection_point',
        did: 'did:peer:2.cp',
        label: 'Connection Point DID',
        mediatorDid: 'did:web:mediator.example',
        mediatorName: 'Mediator X',
      },
      {
        role: 'permanent',
        did: 'did:peer:2.perm',
        label: 'Permanent DID for the paired gateway',
        mediatorDid: 'did:web:mediator.example',
        mediatorName: 'Mediator X',
      },
    ]);
  });

  it("keeps each DID's own mediator, as federation puts a permanent DID on another", () => {
    const dids = labelledDids(
      {
        mediator_did: 'did:web:inviter.example',
        mediator_name: 'Inviter Mediator',
        dids: [
          { role: 'temporary', did: 'did:peer:2.tmp', mediator_did: 'did:web:inviter.example' },
          {
            role: 'permanent',
            did: 'did:peer:2.perm',
            mediator_did: 'did:web:own.example',
            mediator_name: 'Own Mediator',
          },
        ],
      },
      CONNECTION_POINT_DID_LABELS
    );

    expect(dids.map(item => [item.mediatorDid, item.mediatorName])).toEqual([
      ['did:web:inviter.example', 'Inviter Mediator'],
      ['did:web:own.example', 'Own Mediator'],
    ]);
  });

  it('reads the refused DID from a 409 mediator_access_refused', () => {
    const body = JSON.stringify({
      code: 'mediator_access_refused',
      role: 'temporary',
      did: 'did:peer:2.tmp',
    });
    const refusal = mediatorAccessRefusal(
      new ApiError('refused', 409, 'mediator_access_refused', body),
      ADD_GATEWAY_DID_LABELS
    );

    expect(refusal).toEqual({ did: 'did:peer:2.tmp', label: 'Temporary DID for the handshake' });
  });

  it('is null for any other error', () => {
    expect(mediatorAccessRefusal(new ApiError('boom', 500), ADD_GATEWAY_DID_LABELS)).toBeNull();
    expect(mediatorAccessRefusal(new Error('boom'), ADD_GATEWAY_DID_LABELS)).toBeNull();
  });
});
