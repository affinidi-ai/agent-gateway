import { PolicyInputListens } from '../policyInputListens';

const socket = (readyState: number) =>
  ({ readyState, send: jest.fn() }) as unknown as WebSocket & { send: jest.Mock };

const sent = (ws: { send: jest.Mock }) => ws.send.mock.calls.map(([text]) => JSON.parse(text));

describe('PolicyInputListens', () => {
  it('sends a listen and a stop on an open socket', () => {
    const listens = new PolicyInputListens();
    const ws = socket(WebSocket.OPEN);

    listens.set(ws, 's1', true);
    listens.set(ws, 's1', false);

    expect(sent(ws)).toEqual([
      { type: 'capture_policy_input', surface_id: 's1' },
      { type: 'stop_capturing_policy_input', surface_id: 's1' },
    ]);
  });

  it('listens again to each open surface after a reconnect', () => {
    const listens = new PolicyInputListens();
    listens.set(socket(WebSocket.OPEN), 's1', true);
    listens.set(socket(WebSocket.OPEN), 's2', true);
    const reconnected = socket(WebSocket.OPEN);

    listens.resend(reconnected);

    expect(sent(reconnected)).toEqual([
      { type: 'capture_policy_input', surface_id: 's1' },
      { type: 'capture_policy_input', surface_id: 's2' },
    ]);
  });

  it('does not listen again to a surface it stopped', () => {
    const listens = new PolicyInputListens();
    listens.set(socket(WebSocket.OPEN), 's1', true);
    listens.set(socket(WebSocket.OPEN), 's1', false);
    const reconnected = socket(WebSocket.OPEN);

    listens.resend(reconnected);

    expect(reconnected.send).not.toHaveBeenCalled();
  });

  it('keeps a listen made while the socket is not open and sends it once one opens', () => {
    const listens = new PolicyInputListens();
    const connecting = socket(WebSocket.CONNECTING);

    listens.set(connecting, 's1', true);
    listens.set(null, 's2', true);
    expect(connecting.send).not.toHaveBeenCalled();

    const opened = socket(WebSocket.OPEN);
    listens.resend(opened);
    expect(sent(opened)).toEqual([
      { type: 'capture_policy_input', surface_id: 's1' },
      { type: 'capture_policy_input', surface_id: 's2' },
    ]);
  });

  it('forgets a listen the gateway ended without sending a stop', () => {
    const listens = new PolicyInputListens();
    const ws = socket(WebSocket.OPEN);
    listens.set(ws, 's1', true);
    ws.send.mockClear();

    listens.set(ws, 's1', false, false);
    const reconnected = socket(WebSocket.OPEN);
    listens.resend(reconnected);

    expect(ws.send).not.toHaveBeenCalled();
    expect(reconnected.send).not.toHaveBeenCalled();
  });
});
