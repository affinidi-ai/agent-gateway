/**
 * WebSocket subscription section constants.
 *
 * Each page subscribes only to the delta sections it needs, so the server
 * can skip serialising sections the client will throw away anyway.
 *
 * Pass an empty array (`WS_ALL`) to receive every section (the default).
 */

/** All available delta sections. */
export const WS_SECTIONS = [
  'metrics',
  'logs',
  'channels',
  'identities',
  'tasks',
  'unread_count',
] as const;

export type WsSection = (typeof WS_SECTIONS)[number];

/** Receive every section (empty array = no filter on server). */
export const WS_ALL: string[] = [];

/** Everything except logs – used by most dashboard/detail pages. */
export const WS_DASHBOARD: string[] = WS_SECTIONS.filter(s => s !== 'logs');

/** Everything including logs – used by pages that show logs (e.g. channel detail). */
export const WS_DASHBOARD_WITH_LOGS: string[] = [...WS_SECTIONS];

/** Logs only – used by LogsPage. */
export const WS_LOGS: string[] = ['logs'];

/** Receive nothing – used in useEffect cleanup to pause delta delivery between page transitions. */
export const WS_NONE: string[] = ['_none'];
