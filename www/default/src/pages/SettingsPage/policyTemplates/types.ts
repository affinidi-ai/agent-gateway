import type { PolicyType } from '../../../types';

export type { PolicyType };

export type PolicyDecision = 'allow' | 'deny';

export type PolicyTemplateCategory =
  | 'baseline'
  | 'authentication'
  | 'trust_checks'
  | 'routing_paths'
  | 'allow_deny_lists'
  | 'time'
  | 'mcp_tool_policies';

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
      /** `time_zone` accepts IANA time zone names only. */
      format?: 'time_zone';
      /**
       * Set on a deployment-specific setting, which starts empty and must be filled before Use:
       * the field's placeholder, and the value previews, examples and template tests use.
       */
      sample?: string;
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'string_list';
      default: string[];
      /** As on a `string` setting. */
      sample?: string[];
      /** The only values accepted, matched without regard to case. */
      allowed?: string[];
      /** An empty list is accepted and written as the empty set, `set()`. */
      optional?: boolean;
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'choice';
      /** The `value` of the option picked by default. */
      default: string;
      /** Each option's `rego` is the text the placeholder becomes when it is picked. */
      options: { value: string; label: string; rego: string }[];
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'time_of_day';
      /** `HH:MM`, written into the Rego as minutes since midnight. */
      default: string;
      /** Key of another time of day this one must differ from. */
      differs_from?: string;
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
  /**
   * The template decides on its own: its rules allow requests outside what it restricts,
   * so inserting them into another policy, whose rules combine with OR, would widen access.
   */
  standalone?: boolean;
  /**
   * `mcp_tool`: the template is for a policy bound to MCP tools, whose input is the tool call
   * (`input.jwt`, `input.mcp.params.name`), not the request's caller context.
   */
  policy_input?: 'mcp_tool';
  docs_href?: string;
  /** The text of the docs link, naming the guide or reference section it opens. */
  docs_label?: string;
}

/** Raw text of each setting field, so a list can be typed with its commas. */
export type FieldText = Record<string, string>;

/** The template last used from Start from (`blank` for a custom policy) and its settings as typed. */
export interface UsedTemplate {
  id: string;
  fieldText: FieldText;
}

/** A template group as Add to policy wrote it: its name and the lines between its markers. */
export interface AddedRules {
  name: string;
  body: string;
}

/** A policy Type's names: `label` as the Type select shows it, `name` before "policies". */
export const POLICY_TYPE_NAMES: Record<PolicyType, { label: string; name: string }> = {
  gateway: { label: 'Gateway', name: 'Gateway' },
  agent_surface: { label: 'Agent Surfaces', name: 'Agent Surface' },
};

export const CATEGORY_LABELS: Record<PolicyTemplateCategory, string> = {
  baseline: 'Baseline',
  authentication: 'Authentication',
  trust_checks: 'Trust checks',
  routing_paths: 'Routing & paths',
  allow_deny_lists: 'Allow / deny lists',
  time: 'Time',
  mcp_tool_policies: 'MCP tool policies',
};
