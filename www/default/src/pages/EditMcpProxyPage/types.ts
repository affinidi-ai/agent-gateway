export interface McpProxyFormData {
  name: string;
  description: string;
  channel_prefix: string;
  base_url: string;
  openapi_spec: string;
  endpoint_path: string;
  status: 'active' | 'disabled';
  flatten_post_params: boolean;
  /** False: served only through surfaces that target it. */
  direct_access: boolean;
  /** The product that maintains this proxy through the API, if any. */
  managed_by?: string | null;
}

export interface ChannelPrefix {
  id: string;
  name: string;
  prefix: string;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  tools_count?: number;
}
