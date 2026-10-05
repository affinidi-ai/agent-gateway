import * as Cap from '../capabilities';
import type { NodeDefinition, PayloadSlice } from '../types';
import TargetVariantPanel from './TargetVariantPanel';
import { DOCS_URL } from '../../../../config/docs';

/**
 * One row of the variants list as edited in the panel and stored in
 * the singleton's config. `id` is a UUID assigned at row creation.
 *
 * The variant payload is
 * identity-only — overrides for AP / Target / Transit live on the
 * `surface.variants[].overrides` shape and are produced by the
 * upcoming per-element `VariantEditingContext`. The override fields
 * that previously appeared on this row (endpoint, policy ids, MPP,
 * agent card, extensions) were the legacy `target.variants` shape and
 * have been removed: variants now switch the entire surface, not
 * individual Target fields.
 */
export interface VariantEntry {
  id: string;
  name: string;
  alias: string;
  enabled?: boolean;
  is_default?: boolean;
  description?: string;
}

/**
 * Variants — surface-wide always-on element. Every surface implicitly
 * carries a variants config (an empty list means "no aliases"). The
 * editor opens via the top-left "Variants" widget in the surface
 * builder; the element is therefore hidden from the palette and never
 * rendered as a draggable canvas node.
 *
 * Storage: a single conceptual node of type `target-variant` whose
 * config carries the full `variants[]` and `default_variant_id` for the
 * surface. On save, the registry writes them to `target.variants` and
 * `target.default_variant_id`. On hydrate, the node is auto-created
 * regardless of how many (or zero) variants exist.
 */
export const targetVariantDefinition: NodeDefinition = {
  type: 'target-variant',
  label: 'Variants',
  description: 'Alias-based variants for the Target ($alias in URL path)',
  icon: '\uf126', // fa-code-branch
  paletteIcon: 'fa-code-branch',
  color: '#5a5c69',
  shape: 'rect',
  defaultRadius: 22,
  resizable: false,
  draggable: false,
  // Singleton, surface-wide config carrier. The user manages the
  // variants catalog inline via the panel's per-variant trash
  // buttons; the node itself must never be removable, since the
  // implicit `base` is the surface itself and "deleting base"
  // makes no sense.
  deletable: false,
  // Always-on: never drawn on the canvas; the dedicated top-left widget
  // is the only entry point to the editor.
  containedInSurface: false,
  edgeConstrained: false,
  xWeight: 0.6,
  stage: 'target',
  cardinality: 'singleton',
  // paletteCategory/paletteOrder are required by the type but unused —
  // `hiddenFromPalette` filters this element out of the palette UI.
  paletteCategory: 'transitPoints',
  paletteOrder: 99,
  dropMode: 'canvas',
  surfaceWide: true,
  hiddenFromPalette: true,
  provides: [Cap.CONFIGURABLE],
  requires: {},
  help: {
    title: 'Variants',
    docLink: DOCS_URL.variantsElement,
    bodyHtml: `
      <p><strong>Variants</strong> are full snapshots of this surface,
      addressed by a <code>$alias</code> path segment. Each variant
      can carry its own configuration of every element on the canvas
      (Access Point, Target, transit points, policies, payment, identity,
      networking, etc.), not just per-field overrides.</p>
      <p>To edit a variant's configuration, switch to it in the variants
      bar and edit elements on the canvas as you would the base. Switching
      back to another variant restores its state.</p>
      <p>One variant is marked default and answers requests with no
      <code>$alias</code> token.</p>
    `,
  },
  incompleteReason: c => {
    const list = Array.isArray(c?.variants) ? (c.variants as VariantEntry[]) : [];
    if (list.length === 0) return null;
    const bad = list.find(v => !v.alias);
    if (bad) return 'Each variant needs an alias';
    return null;
  },
  ConfigPanel: TargetVariantPanel,
  defaultConfig: () => ({ variants: [] as VariantEntry[] }),
  summary: c => {
    const list = Array.isArray(c?.variants) ? (c.variants as VariantEntry[]) : [];
    if (list.length === 0) return 'no variants';
    return `${list.length} variant${list.length === 1 ? '' : 's'}`;
  },
  getListViewInfo: c => {
    const list = Array.isArray(c?.variants) ? (c.variants as VariantEntry[]) : [];
    const defaultVariant =
      typeof c?.default_variant_id === 'string' && c.default_variant_id
        ? list.find(v => v.id === c.default_variant_id)
        : null;
    const defaultLabel = defaultVariant
      ? `${defaultVariant.name || defaultVariant.alias} ($${defaultVariant.alias})`
      : 'base';
    return {
      name: 'Variants',
      extras: [`${list.length} variant${list.length === 1 ? '' : 's'}`, `default: ${defaultLabel}`],
    };
  },
  buildPayload: ctx => {
    const node = ctx.firstNodeOfType('target-variant');
    if (!node) return undefined;
    const cfg = node.config ?? {};
    const list: VariantEntry[] = Array.isArray(cfg.variants) ? cfg.variants : [];
    if (list.length === 0) return undefined;
    // Alias is the addressable URL token and is auto-seeded when a
    // variant is created, so it is the only hard requirement for the
    // wire. Name defaults to the alias when blank so a freshly-added
    // variant survives a save the user performs before typing a name.
    const valid = list.filter(v => v && v.alias);
    if (valid.length === 0) return undefined;
    const slices: PayloadSlice[] = [];
    // North-star shape: top-level `variants[]` + `default_variant_id`
    // on the surface (per `agent_surface_variants.rs::SurfaceVariant`).
    // Each variant carries identity only here; per-element overrides
    // are produced by the (forthcoming) `VariantEditingContext` and
    // merged in by the surface-builder save flow.
    const northStar = valid.map(v => ({
      id: v.id,
      alias: v.alias,
      name: v.name || v.alias,
      enabled: v.enabled !== false,
      ...(v.description ? { description: v.description } : {}),
      overrides: {},
    }));
    slices.push({ path: 'variants', value: northStar });
    // Only emit `default_variant_id` when the user has explicitly
    // picked one (either persisted on the node config or marked via
    // `is_default`). Omitting the slice leaves it as `null` on the
    // wire, which the backend now treats as "base is the implicit
    // default" — alias-less URLs resolve to the bare base surface
    // with no overrides applied. Falling back to `valid[0].id` here
    // would silently apply that variant's overrides to base traffic.
    const explicitDefault =
      typeof cfg.default_variant_id === 'string' && valid.some(v => v.id === cfg.default_variant_id)
        ? cfg.default_variant_id
        : valid.find(v => v.is_default)?.id;
    if (explicitDefault) {
      slices.push({ path: 'default_variant_id', value: explicitDefault });
    }
    return slices;
  },
};
