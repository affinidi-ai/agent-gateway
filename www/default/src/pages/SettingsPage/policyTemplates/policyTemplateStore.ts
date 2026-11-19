import {
  CATEGORY_LABELS,
  type PolicyTemplate,
  type PolicyTemplateCategory,
  type PolicyTemplateExample,
  type PolicyType,
} from './types';

export interface NewPolicyTemplate {
  name: string;
  summary: string;
  category: PolicyTemplateCategory;
  policy_type: PolicyType;
  rego: string;
  reads: string[];
  examples: PolicyTemplateExample[];
}

/**
 * Where the editor reads and saves policy templates. A backend-backed store implements the same
 * three calls; `subscribe` tells readers to list again after a save.
 */
export interface PolicyTemplateStore {
  list(policyType: PolicyType): Promise<PolicyTemplate[]>;
  save(input: NewPolicyTemplate): Promise<PolicyTemplate>;
  subscribe(listener: () => void): () => void;
}

const DEFAULT_STORAGE_KEY = 'policy-templates:organization';

function isStoredExample(value: unknown): value is PolicyTemplateExample {
  if (typeof value !== 'object' || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.name === 'string' &&
    typeof e.input === 'object' &&
    e.input !== null &&
    !Array.isArray(e.input) &&
    (e.expected === 'allow' || e.expected === 'deny')
  );
}

function isStoredTemplate(value: unknown): value is PolicyTemplate {
  if (typeof value !== 'object' || value === null) return false;
  const t = value as Record<string, unknown>;
  return (
    typeof t.id === 'string' &&
    t.id.startsWith('org:') &&
    typeof t.name === 'string' &&
    typeof t.summary === 'string' &&
    typeof t.description === 'string' &&
    typeof t.rego === 'string' &&
    typeof t.category === 'string' &&
    Object.prototype.hasOwnProperty.call(CATEGORY_LABELS, t.category) &&
    (t.policy_type === 'gateway' || t.policy_type === 'agent_surface') &&
    Array.isArray(t.parameters) &&
    t.parameters.length === 0 &&
    Array.isArray(t.reads) &&
    t.reads.every(r => typeof r === 'string') &&
    Array.isArray(t.examples) &&
    t.examples.every(isStoredExample) &&
    t.builtin === false
  );
}

/** A stored template rebuilt from its checked fields only, so nothing else reaches the editor. */
function fromStored(t: PolicyTemplate): PolicyTemplate {
  return {
    id: t.id,
    name: t.name,
    summary: t.summary,
    description: t.description,
    category: t.category,
    policy_type: t.policy_type,
    rego: t.rego,
    parameters: [],
    reads: [...t.reads],
    examples: t.examples.map(ex => ({ name: ex.name, input: ex.input, expected: ex.expected })),
    builtin: false,
  };
}

/**
 * A store of `builtin` templates plus organisation templates kept in the tab's `sessionStorage`
 * under `storageKey`, or in memory when storage is unavailable.
 */
export function createSessionPolicyTemplateStore(
  builtin: readonly PolicyTemplate[],
  storageKey = DEFAULT_STORAGE_KEY
): PolicyTemplateStore {
  let unstored: PolicyTemplate[] = [];
  // Set once a write fails, so reads come from memory instead of the stale stored list.
  let writeFailed = false;
  const listeners = new Set<() => void>();

  const read = (): PolicyTemplate[] => {
    if (writeFailed) return unstored;
    let raw: string | null;
    try {
      raw = window.sessionStorage.getItem(storageKey);
    } catch {
      return unstored;
    }
    if (raw === null) return [];
    try {
      const parsed: unknown = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter(isStoredTemplate).map(fromStored) : [];
    } catch {
      return [];
    }
  };

  const write = (templates: PolicyTemplate[]) => {
    unstored = templates;
    try {
      window.sessionStorage.setItem(storageKey, JSON.stringify(templates));
      writeFailed = false;
    } catch {
      // Storage is unavailable or full; the templates last until the page reloads.
      writeFailed = true;
    }
  };

  return {
    async list(policyType) {
      return [...builtin, ...read()].filter(t => t.policy_type === policyType);
    },
    async save(input) {
      const name = input.name.trim();
      if (!name) throw new Error('Enter a template name.');
      const existing = read();
      const taken = existing.some(
        t => t.policy_type === input.policy_type && t.name.toLowerCase() === name.toLowerCase()
      );
      if (taken) throw new Error(`A template named "${name}" already exists.`);
      const template: PolicyTemplate = {
        id: `org:${Date.now().toString(36)}-${existing.length + 1}`,
        name,
        summary: input.summary.trim(),
        description: input.summary.trim(),
        category: input.category,
        policy_type: input.policy_type,
        rego: input.rego,
        parameters: [],
        reads: input.reads,
        examples: input.examples,
        builtin: false,
      };
      write([...existing, template]);
      listeners.forEach(l => l());
      return template;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
