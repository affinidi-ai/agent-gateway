/**
 * The surfaces this page listens to the policy input of on the dashboard WebSocket.
 * The set outlives one socket, so a reconnect can listen again; it ends with the page.
 */
export class PolicyInputListens {
  private readonly surfaces = new Set<string>();

  /**
   * Start or stop listening to `surfaceId`, sending the request on `socket` when it is
   * open. With `notify` false a stop only forgets the listen, for one the gateway ended.
   */
  set(socket: WebSocket | null, surfaceId: string, listening: boolean, notify = true): void {
    if (listening) {
      this.surfaces.add(surfaceId);
    } else {
      this.surfaces.delete(surfaceId);
    }
    if (notify && socket && socket.readyState === WebSocket.OPEN) {
      socket.send(
        JSON.stringify({
          type: listening ? 'capture_policy_input' : 'stop_capturing_policy_input',
          surface_id: surfaceId,
        })
      );
    }
  }

  /** Listen again to every surface on a newly opened `socket`. */
  resend(socket: WebSocket): void {
    this.surfaces.forEach(surfaceId => {
      socket.send(JSON.stringify({ type: 'capture_policy_input', surface_id: surfaceId }));
    });
  }
}
