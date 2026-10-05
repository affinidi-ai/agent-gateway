// Cross-component handoff: IdentityPanel marks a node id when the user
// presses "Onboard Agent", IdentityPayloadFullscreenPanel reads (and
// clears) the flag on mount to switch into the onboarding sub-view
// instead of the default schema editor.
const pending = new Set<string>();

export function requestOnboard(nodeId: string): void {
  pending.add(nodeId);
}

export function consumeOnboard(nodeId: string): boolean {
  const had = pending.has(nodeId);
  pending.delete(nodeId);
  return had;
}
