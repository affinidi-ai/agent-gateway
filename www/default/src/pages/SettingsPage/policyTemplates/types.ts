export type PolicyType = 'gateway' | 'agent_surface';

export type PolicyDecision = 'allow' | 'deny';

export type PolicyTemplateCategory =
  | 'baseline'
  | 'authentication'
  | 'trust_checks'
  | 'routing_paths'
  | 'allow_deny_lists'
  | 'time';

export type PolicyTemplateParameter =
  | {
      key: string;
      label: string;
      kind: 'integer';
      default: number;
      min: number;
      max: number;
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'string';
      default: string;
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'string_list';
      default: string[];
      help?: string;
    };

export type ParameterValue = number | string | string[];

export type ParameterValues = Record<string, ParameterValue>;

export interface PolicyTemplateExample {
  name: string;
  input: Record<string, unknown>;
  expected: PolicyDecision;
}

export interface PolicyTemplate {
  id: string;
  name: string;
  summary: string;
  description: string;
  category: PolicyTemplateCategory;
  policy_type: PolicyType;
  /** Full Rego module. Settings appear as `{{key}}` placeholders. */
  rego: string;
  parameters: PolicyTemplateParameter[];
  /** Input paths the policy reads, shown as tags. */
  reads: string[];
  examples: PolicyTemplateExample[];
  builtin: boolean;
  /**
   * The template decides on its own: its rules allow requests outside what it restricts,
   * so inserting them into another policy, whose rules combine with OR, would widen access.
   */
  standalone?: boolean;
  docs_href?: string;
}

export const CATEGORY_LABELS: Record<PolicyTemplateCategory, string> = {
  baseline: 'Baseline',
  authentication: 'Authentication',
  trust_checks: 'Trust checks',
  routing_paths: 'Routing & paths',
  allow_deny_lists: 'Allow / deny lists',
  time: 'Time',
};
