/**
 * Label and badge icon of each record type, shared by the query list and the
 * editor's record type toggle. Kept in a module with no imports so it is never
 * read mid-cycle (`definition` → panels → query form → query list → `definition`).
 */
export const RECORD_TYPE = {
  recognition: { label: 'Recognition', icon: 'fa-id-badge' },
  authorization: { label: 'Authorization', icon: 'fa-user-shield' },
} as const;
