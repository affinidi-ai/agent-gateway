/** Base filter option with value, label, and optional count badge */
export interface FilterOption {
  value: string;
  label: string;
  count?: number;
  lowFrequency?: boolean; // If true or count === 0, option goes to overflow menu
}

/** Filter item used in overflow menus, with optional icon support */
export interface FilterItem extends FilterOption {
  icon?: string; // FontAwesome class, e.g. "fa-arrow-up"
}
