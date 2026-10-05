export interface MetricsConfig {
  opentelemetry: OpenTelemetryConfig;
  cloudwatch: CloudWatchConfig;
  retention: RetentionConfig;
  advanced: AdvancedConfig;
}

export interface OpenTelemetryConfig {
  enabled: boolean;
  endpoint: string;
  protocol?: OtlpProtocol;
  auth?: OtlpAuthConfig;
  service_name: string;
  environment: string;
  traces: TracesConfig;
  metrics: MetricsExportConfig;
  logs: LogsConfig;
}

export type OtlpProtocol = 'grpc' | 'http';

export interface OtlpAuthConfig {
  header_name: string;
  secret_id: string;
  header_format: string;
}

export interface TracesConfig {
  enabled: boolean;
  sample_rate: number;
  target_crates: string[];
  record_caller_identity?: boolean;
}

export interface MetricsExportConfig {
  enabled: boolean;
  export_interval_seconds: number;
}

export interface LogsConfig {
  enabled: boolean;
}

export interface CloudWatchConfig {
  enabled: boolean;
  region: string;
  namespace: string;
}

export interface RetentionConfig {
  local_logs_hours: number;
  collector_log_mb: number;
}

export interface AdvancedConfig {
  batch_size: number;
  batch_delay_ms: number;
  batch_queue_size: number;
  host_metrics: {
    enabled: boolean;
  };
}

export interface ConnectionTestResult {
  success: boolean;
  message: string;
  latency_ms?: number;
}
