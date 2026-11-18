export type PolicyType = 'gateway' | 'agent_surface';

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
      /** Key of another integer setting this one must be greater than. */
      after?: string;
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'string';
      default: string;
      /** `time_zone` accepts IANA time zone names only. */
      format?: 'time_zone';
      help?: string;
    }
  | {
      key: string;
      label: string;
      kind: 'string_list';
      default: string[];
      /** The only values accepted, matched without regard to case. */
      allowed?: string[];
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
  /**
   * `mcp_tool`: the template is for a policy bound to MCP tools on the MCP Proxy hop, whose
   * input is the tool call (`input.jwt`, `input.mcp.method`), not the request's caller context.
   */
  policy_input?: 'mcp_tool';
  docs_href?: string;
  /** The text of the docs link, naming the guide or reference section it opens. */
  docs_label?: string;
}

export const CATEGORY_LABELS: Record<PolicyTemplateCategory, string> = {
  baseline: 'Baseline',
  authentication: 'Authentication',
  trust_checks: 'Trust checks',
  routing_paths: 'Routing & paths',
  allow_deny_lists: 'Allow / deny lists',
  time: 'Time',
  mcp_tool_policies: 'MCP tool policies',
};
