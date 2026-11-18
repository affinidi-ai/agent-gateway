import { DOCS_URL } from '../../../config/docs';
import catalogue from './builtinPolicyTemplates.json';
import { EXPECTED_PACKAGE } from './policyDefaults';
import type {
  PolicyTemplate,
  PolicyTemplateCategory,
  PolicyTemplateExample,
  PolicyTemplateParameter,
  PolicyType,
} from './types';

/**
 * Catalogue entries hold the rules without a `package` line, so one entry serves every
 * policy type it lists. The JSON is also the input of the Regorus compile check.
 */
interface CatalogueEntry {
  id: string;
  name: string;
  summary: string;
  description: string;
  category: string;
  policy_types: string[];
  standalone?: boolean;
  input?: 'mcp_tool';
  docs: { page: keyof typeof DOCS_URL; anchor: string; label: string };
  rules: string;
  parameters: unknown[];
  reads: string[];
  examples: unknown[];
}

function expand(entry: CatalogueEntry, policyType: PolicyType): PolicyTemplate {
  return {
    id: `${entry.id}:${policyType}`,
    name: entry.name,
    summary: entry.summary,
    description: entry.description,
    category: entry.category as PolicyTemplateCategory,
    policy_type: policyType,
    rego: `package ${EXPECTED_PACKAGE[policyType]}\n\n${entry.rules}\n`,
    parameters: entry.parameters as PolicyTemplateParameter[],
    reads: entry.reads,
    examples: entry.examples as PolicyTemplateExample[],
    builtin: true,
    standalone: entry.standalone ?? false,
    ...(entry.input ? { policy_input: entry.input } : {}),
    docs_href: `${DOCS_URL[entry.docs.page]}#${entry.docs.anchor}`,
    docs_label: entry.docs.label,
  };
}

export const BUILTIN_POLICY_TEMPLATES: readonly PolicyTemplate[] = (
  catalogue as unknown as CatalogueEntry[]
).flatMap(entry =>
  entry.policy_types
    .filter((t): t is PolicyType => t === 'gateway' || t === 'agent_surface')
    .map(t => expand(entry, t))
);
