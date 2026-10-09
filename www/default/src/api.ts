import {
  AccessTokenCreated,
  AccessTokenMeta,
  Authority,
  CliLoginRequest,
  CreateAccessTokenRequest,
  DashboardStats,
  Issuer,
  LogEntry,
  PredefinedTrustCheckQuery,
  Settings,
  Task,
  TruncateLogsResult,
  TruncateMetricsResult,
  TrustRegistry,
  UpdateAccessTokenRequest,
  UserSettingsOverrides,
} from './types';

// Agent Surface types
import type { SurfaceStatus } from './generated/SurfaceStatus';
import { formatApiError } from './utils/apiError';

const API_BASE = '/api/v1';

export const TERMS_ACCEPTANCE_REQUIRED_EVENT = 'terms-acceptance-required';
export const TERMS_OPERATIONAL_FAILURE_EVENT = 'terms-operational-failure';

async function signalTermsAcceptanceRequired(response: Response): Promise<void> {
  if ((response.status !== 403 && response.status !== 503) || typeof window === 'undefined') return;
  const body = (await response
    .clone()
    .json()
    .catch(() => null)) as { code?: string } | null;
  if (response.status === 403 && body?.code === 'TERMS_ACCEPTANCE_REQUIRED') {
    window.dispatchEvent(new Event(TERMS_ACCEPTANCE_REQUIRED_EVENT));
  } else if (response.status === 503 && body?.code === 'TERMS_OPERATIONAL_FAILURE') {
    window.dispatchEvent(new Event(TERMS_OPERATIONAL_FAILURE_EVENT));
  }
}

/** One appliance resource limit with its current live count (GET /v1/limits). */
export interface LimitItem {
  id: string;
  name: string;
  description: string;
  limit: number;
  current: number;
}

class SessionManager {
  private static readonly YES_VALUE = '1';
  private static readonly SESSION_EXPIRED_KEY = 'session_expired';

  didSessionExpire(): boolean {
    return sessionStorage.getItem(SessionManager.SESSION_EXPIRED_KEY) === SessionManager.YES_VALUE;
  }

  setSessionExpiredError(): void {
    sessionStorage.setItem(SessionManager.SESSION_EXPIRED_KEY, SessionManager.YES_VALUE);
  }

  clearSessionExpiredError(): void {
    sessionStorage.removeItem(SessionManager.SESSION_EXPIRED_KEY);
  }

  private setCookie(name: string, value: string, days: number = 365): void {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
  }

  getCookie(name: string): string | null {
    const nameEQ = name + '=';
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) === ' ') c = c.substring(1, c.length);
      if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
  }

  getSessionToken(): string | null {
    // Try sessionStorage first
    let token = sessionStorage.getItem('session_token');
    if (token) return token;

    token = this.getCookie('session_token');
    if (token) {
      // Restore to sessionStorage for future calls
      sessionStorage.setItem('session_token', token);
    }
    return token;
  }

  getAuthHeaders(): Record<string, string> {
    const sessionToken = this.getSessionToken();
    if (!sessionToken) {
      return {};
    }
    return { Authorization: `Bearer ${sessionToken}` };
  }

  login(username: string, sessionToken: string): void {
    this.setCookie('lastUsername', username);
    sessionStorage.setItem('session_token', sessionToken);
  }

  async logout(logoutAction: () => void = () => {}): Promise<void> {
    logoutAction();
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: this.getAuthHeaders(),
      });
    } catch (error) {
      console.error('Logout failed:', error);
    }

    sessionStorage.removeItem('session_token');
    document.cookie = 'session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  }

  expireSession(): void {
    this.setSessionExpiredError();
    this.logout().finally(() => window.location.reload());
  }
}

export const sessionManager = new SessionManager();

class APIClient {
  private async request<T>(
    endpoint: string,
    options?: RequestInit & { timeout?: number }
  ): Promise<T> {
    const url = `${API_BASE}${endpoint}`;

    // Setup timeout using AbortController
    const controller = new AbortController();
    const timeoutId = options?.timeout
      ? setTimeout(() => controller.abort(), options.timeout)
      : null;

    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...sessionManager.getAuthHeaders(),
          ...options?.headers,
        },
        ...options,
        signal: controller.signal,
      });

      await signalTermsAcceptanceRequired(response);

      if (response.status === 401) {
        sessionManager.expireSession();
        throw new Error('Session expired');
      }

      if (!response.ok) {
        console.error('[API] Request failed:', endpoint, response.status, response.statusText);
        let errorBody: string | null = null;
        try {
          errorBody = await response.text();
          if (errorBody) {
            console.error('[API] Error body:', errorBody.substring(0, 500));
          }
        } catch (e) {
          console.error('[API] Could not read error response:', e);
        }
        throw new Error(formatApiError(response.status, errorBody, response.statusText));
      }

      // Don't try to parse JSON for 204 No Content responses
      if (response.status === 204) {
        return {} as T;
      }

      const data = await response.json();
      return data;
    } catch (error: any) {
      if (error.name === 'AbortError') {
        throw new Error('Request timeout - the webhook endpoint did not respond within 30 seconds');
      }
      throw error;
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  /**
   * Authenticated fetch — drop-in replacement for `fetch()` that adds the
   * Authorization header automatically.  Returns the raw `Response` so callers
   * can inspect status, stream the body, etc.
   */
  async fetch(input: string, init?: RequestInit): Promise<Response> {
    const response = await fetch(input, {
      ...init,
      headers: {
        ...sessionManager.getAuthHeaders(),
        ...init?.headers,
      },
    });
    await signalTermsAcceptanceRequired(response);
    return response;
  }

  // Generic HTTP methods
  async get<T = any>(endpoint: string, options?: { timeout?: number }): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, options);
    return { data };
  }

  async post<T = any>(
    endpoint: string,
    body?: any,
    options?: { timeout?: number }
  ): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
      ...options,
    });
    return { data };
  }

  async put<T = any>(
    endpoint: string,
    body?: any,
    options?: { timeout?: number }
  ): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
      ...options,
    });
    return { data };
  }

  async delete<T = any>(endpoint: string, options?: { timeout?: number }): Promise<{ data: T }> {
    const data = await this.request<T>(endpoint, {
      method: 'DELETE',
      ...options,
    });
    return { data };
  }

  // Dashboard Stats
  async getDashboardStats(
    bucketSeconds?: number,
    channelId?: string,
    gatewayId?: string,
    identityDid?: string,
    transitPoint?: string
  ): Promise<DashboardStats> {
    const params = new URLSearchParams();
    if (bucketSeconds) params.append('bucket_seconds', bucketSeconds.toString());
    if (channelId) params.append('surface_id', channelId);
    if (gatewayId) params.append('gateway_id', gatewayId);
    if (identityDid) params.append('identity_did', identityDid);
    if (transitPoint) params.append('transit_point', transitPoint);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    const result = await this.request<DashboardStats>(`/dashboard/stats${queryString}`);

    return result;
  }

  async getHierarchicalMetrics(): Promise<any> {
    return this.request('/dashboard/metrics/hierarchical');
  }

  async getSystemMetrics(timeRange?: string, since?: string): Promise<any> {
    const params = new URLSearchParams();
    if (since) params.set('since', since);
    else if (timeRange) params.set('time_range', timeRange);
    const qs = params.toString();
    return this.request(`/dashboard/system-metrics${qs ? `?${qs}` : ''}`);
  }

  // Identity Management
  async resolveIdentityDID(did: string): Promise<any> {
    return this.request(`/identity/resolve-did?did=${encodeURIComponent(did)}`);
  }

  async getGatewayDidDocument(): Promise<any> {
    return this.request('/identity/did-document');
  }

  async retryTrRegistration(identityHash: string): Promise<any> {
    return this.post(`/identities/${encodeURIComponent(identityHash)}/register-trust-registry`);
  }

  async retryIssuerTrRegistration(issuerId: string): Promise<any> {
    return this.post(`/issuers/${encodeURIComponent(issuerId)}/register-trust-registry`);
  }

  /**
   * @deprecated Use `retryIssuerTrRegistration` instead. Kept for compatibility
   * with dashboard code written before the `department` → `issuer` rename.
   */
  async retryDeptTrRegistration(issuerId: string): Promise<any> {
    return this.retryIssuerTrRegistration(issuerId);
  }

  // Settings Management
  async getSettings(): Promise<Settings> {
    const backendSettings = await this.request<any>('/settings');

    // Convert backend settings format to frontend format
    return {
      badge_threshold: backendSettings.badge_threshold_minutes || 5,
      metrics_retention: backendSettings.metrics_retention_minutes || 360, // Both in minutes now
      task_activity_window: backendSettings.task_activity_window_seconds || 60,
      connections_window: backendSettings.connections_window_minutes || 5,
      latency_window: backendSettings.latency_window_minutes || 5,
      onboarding_channel_ttl_seconds: backendSettings.onboarding_channel_ttl_seconds || 30,
      refresh_interval_seconds: backendSettings.refresh_interval_seconds || 5,
      log_timestamp_format: backendSettings.log_timestamp_format || 'local',
      bucket_seconds: backendSettings.bucket_seconds || 30,
      payments_min_display: backendSettings.payments_min_display || 10,
      feature_flags: backendSettings.feature_flags || {},
      prometheus_auth_enabled: backendSettings.prometheus_auth_enabled || false,
      prometheus_auth_username: backendSettings.prometheus_auth_username || '',
      audit_enabled: backendSettings.audit_enabled || false,
      audit_categories: backendSettings.audit_categories || {
        policies: false,
        trust_checks: false,
        identity: false,
      },
      expose_user_identity_downstream: backendSettings.expose_user_identity_downstream || false,
    };
  }

  async updateSettings(settings: Partial<Settings>): Promise<void> {
    // Map frontend field names to backend field names
    const backendSettings: any = {};

    if (settings.badge_threshold !== undefined) {
      backendSettings.badge_threshold_minutes = settings.badge_threshold;
    }

    if (settings.metrics_retention !== undefined) {
      backendSettings.metrics_retention_minutes = settings.metrics_retention;
    }

    if (settings.task_activity_window !== undefined) {
      backendSettings.task_activity_window_seconds = settings.task_activity_window;
    }

    if (settings.connections_window !== undefined) {
      backendSettings.connections_window_minutes = settings.connections_window;
    }

    if (settings.latency_window !== undefined) {
      backendSettings.latency_window_minutes = settings.latency_window;
    }

    if (settings.onboarding_channel_ttl_seconds !== undefined) {
      backendSettings.onboarding_channel_ttl_seconds = settings.onboarding_channel_ttl_seconds;
    }

    if (settings.refresh_interval_seconds !== undefined) {
      backendSettings.refresh_interval_seconds = settings.refresh_interval_seconds;
    }

    if (settings.log_timestamp_format !== undefined) {
      backendSettings.log_timestamp_format = settings.log_timestamp_format;
    }

    if (settings.bucket_seconds !== undefined) {
      backendSettings.bucket_seconds = settings.bucket_seconds;
    }

    if (settings.payments_min_display !== undefined) {
      backendSettings.payments_min_display = settings.payments_min_display;
    }

    if (settings.feature_flags !== undefined) {
      backendSettings.feature_flags = settings.feature_flags;
    }

    if (settings.prometheus_auth_enabled !== undefined) {
      backendSettings.prometheus_auth_enabled = settings.prometheus_auth_enabled;
    }

    if (settings.prometheus_auth_username !== undefined) {
      backendSettings.prometheus_auth_username = settings.prometheus_auth_username;
    }

    if ((settings as any).prometheus_auth_password !== undefined) {
      backendSettings.prometheus_auth_password = (settings as any).prometheus_auth_password;
    }

    if (settings.audit_enabled !== undefined) {
      backendSettings.audit_enabled = settings.audit_enabled;
    }

    if (settings.audit_categories !== undefined) {
      backendSettings.audit_categories = settings.audit_categories;
    }

    if (settings.expose_user_identity_downstream !== undefined) {
      backendSettings.expose_user_identity_downstream = settings.expose_user_identity_downstream;
    }

    await this.request('/settings', {
      method: 'POST',
      body: JSON.stringify(backendSettings),
    });
  }

  async resetSettings(): Promise<void> {
    await this.request('/settings', {
      method: 'DELETE',
    });
  }

  // Per-User Settings Management

  /**
   * Get effective settings for the current user (user overrides merged with system defaults).
   * Falls back to system settings if user settings endpoint is not available.
   */
  async getUserSettings(): Promise<Settings> {
    try {
      const backendSettings = await this.request<any>('/user-settings');
      return {
        badge_threshold: backendSettings.badge_threshold_minutes || 5,
        metrics_retention: backendSettings.metrics_retention_minutes || 360,
        task_activity_window: backendSettings.task_activity_window_seconds || 60,
        connections_window: backendSettings.connections_window_minutes || 5,
        latency_window: backendSettings.latency_window_minutes || 5,
        onboarding_channel_ttl_seconds: backendSettings.onboarding_channel_ttl_seconds || 30,
        refresh_interval_seconds: backendSettings.refresh_interval_seconds || 5,
        log_timestamp_format: backendSettings.log_timestamp_format || 'local',
        bucket_seconds: backendSettings.bucket_seconds || 30,
        payments_min_display: backendSettings.payments_min_display || 10,
        feature_flags: backendSettings.feature_flags || {},
        prometheus_auth_enabled: backendSettings.prometheus_auth_enabled || false,
        prometheus_auth_username: backendSettings.prometheus_auth_username || '',
        audit_enabled: backendSettings.audit_enabled || false,
        audit_categories: backendSettings.audit_categories || {
          policies: false,
          trust_checks: false,
          identity: false,
        },
        expose_user_identity_downstream: backendSettings.expose_user_identity_downstream || false,
      };
    } catch {
      // Fall back to system settings if user settings endpoint is unavailable
      return this.getSettings();
    }
  }

  /** Get only the user's personal overrides (without system defaults). */
  async getUserSettingsOverrides(): Promise<UserSettingsOverrides> {
    return this.request<UserSettingsOverrides>('/user-settings/overrides');
  }

  /** Update the current user's personal display preferences. */
  async updateUserSettings(settings: Partial<UserSettingsOverrides>): Promise<void> {
    await this.request('/user-settings', {
      method: 'POST',
      body: JSON.stringify(settings),
    });
  }

  /** Reset user settings to system defaults. */
  async resetUserSettings(): Promise<void> {
    await this.request('/user-settings', {
      method: 'DELETE',
    });
  }

  // Metrics Configuration Management
  async getMetricsConfig(): Promise<any> {
    return this.request('/metrics/config');
  }

  async updateMetricsConfig(config: any): Promise<{ success: boolean; message: string }> {
    return this.request('/metrics/config', {
      method: 'PUT',
      body: JSON.stringify(config),
    });
  }

  async testOtlpConnection(
    endpoint: string
  ): Promise<{ success: boolean; message: string; latency_ms?: number }> {
    return this.request('/metrics/test-connection', {
      method: 'POST',
      body: JSON.stringify({ endpoint }),
    });
  }

  // Appliance resource limits
  async getLimits(): Promise<LimitItem[]> {
    return this.request<LimitItem[]>('/limits');
  }

  // Agent Surfaces
  async listSurfaces(): Promise<AgentSurface[]> {
    const list = await this.request<AgentSurface[]>('/surfaces');
    return list.map(fromBackendSurface);
  }

  async getSurface(surfaceId: string): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>(`/surfaces/${encodeURIComponent(surfaceId)}`);
    return fromBackendSurface(s);
  }

  async createSurface(surface: Partial<AgentSurface>): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>('/surfaces', {
      method: 'POST',
      body: JSON.stringify(toBackendSurface(surface)),
    });
    return fromBackendSurface(s);
  }

  async updateSurface(surfaceId: string, surface: Partial<AgentSurface>): Promise<AgentSurface> {
    const s = await this.request<AgentSurface>(`/surfaces/${encodeURIComponent(surfaceId)}`, {
      method: 'PUT',
      body: JSON.stringify(toBackendSurface(surface)),
    });
    return fromBackendSurface(s);
  }

  async deleteSurface(surfaceId: string): Promise<void> {
    await this.request(`/surfaces/${encodeURIComponent(surfaceId)}`, {
      method: 'DELETE',
    });
  }

  // Surface Templates
  async listSurfaceTemplates(): Promise<SurfaceTemplate[]> {
    return this.request<SurfaceTemplate[]>('/surface-templates');
  }

  async getSurfaceTemplate(id: string): Promise<SurfaceTemplate> {
    return this.request<SurfaceTemplate>(`/surface-templates/${encodeURIComponent(id)}`);
  }

  async createSurfaceTemplate(tpl: Partial<SurfaceTemplate>): Promise<SurfaceTemplate> {
    return this.request<SurfaceTemplate>('/surface-templates', {
      method: 'POST',
      body: JSON.stringify(tpl),
    });
  }

  async updateSurfaceTemplate(id: string, tpl: Partial<SurfaceTemplate>): Promise<SurfaceTemplate> {
    return this.request<SurfaceTemplate>(`/surface-templates/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(tpl),
    });
  }

  async deleteSurfaceTemplate(id: string): Promise<void> {
    await this.request(`/surface-templates/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Upload an exported `*.surface-template.json` payload. The backend
   * re-assigns a fresh id if the incoming id collides with an
   * existing template, so this is safe to call repeatedly on the
   * same file (each call produces a clone).
   */
  async importSurfaceTemplate(payload: unknown): Promise<SurfaceTemplate> {
    return this.request<SurfaceTemplate>('/surface-templates/import', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Trigger a browser download of the template as a portable
   * `*.surface-template.json` file. Returns the resolved filename
   * (from the server's `Content-Disposition` header, falling back to
   * `<id>.surface-template.json`).
   */
  async exportSurfaceTemplate(id: string): Promise<string> {
    const response = await this.fetch(
      `${API_BASE}/surface-templates/${encodeURIComponent(id)}/export`
    );
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Export failed: ${response.status} ${response.statusText} ${body}`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get('content-disposition') ?? '';
    const match = /filename="?([^"]+)"?/i.exec(disposition);
    const filename = match?.[1] ?? `${id}.surface-template.json`;
    const url = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
    } finally {
      // Defer revocation so Safari has time to start the download.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    return filename;
  }

  // Trust Registries
  async listTrustRegistries(): Promise<TrustRegistry[]> {
    return this.request<TrustRegistry[]>('/trust-registries');
  }

  async reconnectTrustRegistry(id: string): Promise<void> {
    await this.request<void>(`/trust-registries/${id}/reconnect`, {
      method: 'POST',
    });
  }

  async listTrustRegistryRecords(id: string): Promise<{ round_trip_ms: number }> {
    return this.request<{ round_trip_ms: number }>(`/trust-registries/${id}/list-records`, {
      method: 'POST',
    });
  }

  // Issuers
  async listIssuers(): Promise<Issuer[]> {
    return this.request<Issuer[]>('/issuers');
  }

  /**
   * @deprecated Use `listIssuers` instead. Kept for compatibility with
   * dashboard code written before the `department` → `issuer` rename.
   */
  async listDepartments(): Promise<Issuer[]> {
    return this.listIssuers();
  }

  // Authorities — local trust-anchor register
  async listAuthorities(): Promise<Authority[]> {
    return this.request<Authority[]>('/authorities');
  }

  async getAuthority(id: string): Promise<Authority> {
    return this.request<Authority>(`/authorities/${encodeURIComponent(id)}`);
  }

  async createAuthority(payload: {
    name: string;
    did: string;
    description?: string;
    context?: Record<string, unknown> | null;
  }): Promise<Authority> {
    return this.request<Authority>('/authorities', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateAuthority(
    id: string,
    payload: {
      name: string;
      did: string;
      description?: string;
      context?: Record<string, unknown> | null;
    }
  ): Promise<Authority> {
    return this.request<Authority>(`/authorities/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async deleteAuthority(id: string): Promise<void> {
    await this.request<void>(`/authorities/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async listPredefinedTrustCheckQueries(): Promise<PredefinedTrustCheckQuery[]> {
    return this.request<PredefinedTrustCheckQuery[]>('/trust-check/predefined-queries');
  }

  // Onboarding Management
  async createTempOnboardChannel(protocol: string): Promise<{
    config_id: string;
    channel_name: string;
    endpoint_url: string;
    message: string;
    ttl_seconds: number;
  }> {
    return this.request('/onboard/create-temp-surface', {
      method: 'POST',
      body: JSON.stringify({ protocol }),
    });
  }

  async deleteTempOnboardChannel(configId: string): Promise<void> {
    await this.request(`/onboard/delete-temp-channel/${encodeURIComponent(configId)}`, {
      method: 'DELETE',
    });
  }

  // Metrics Management
  async truncateMetrics(): Promise<TruncateMetricsResult> {
    return this.request<TruncateMetricsResult>('/metrics/truncate', {
      method: 'POST',
    });
  }

  // Tasks (if available - placeholder for future implementation)
  async getTasks(): Promise<Task[]> {
    // This might need to be implemented in the backend
    return this.request<Task[]>('/tasks');
  }

  // Logs (if available - placeholder for future implementation)
  async getLogs(limit?: number): Promise<LogEntry[]> {
    const params = limit ? `?limit=${limit}` : '';
    return this.request<LogEntry[]>(`/logs${params}`);
  }

  // Truncate old / rotated log files
  async truncateOldLogs(): Promise<TruncateLogsResult> {
    return this.request<TruncateLogsResult>('/logs/truncate', {
      method: 'POST',
    });
  }

  // Download all logs as a ZIP archive (streaming for large files)
  async downloadLogs(): Promise<Blob> {
    const response = await fetch(`${API_BASE}/logs/download`, {
      method: 'GET',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
    });

    if (!response.ok) {
      let errorMessage = `Download failed: ${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.json();
        if (errorBody.error) errorMessage = errorBody.error;
      } catch {
        // ignore parse error
      }
      throw new Error(errorMessage);
    }

    return response.blob();
  }

  // Permissions
  async getPermissions(): Promise<Record<string, boolean>> {
    return this.request<Record<string, boolean>>('/permissions');
  }

  // API Keys Management
  async listAllApiKeys(): Promise<ApiKeyMeta[]> {
    return this.request<ApiKeyMeta[]>('/api-keys');
  }

  async listApiKeys(agentId: string): Promise<ApiKeyMeta[]> {
    return this.request<ApiKeyMeta[]>(`/api-keys/${encodeURIComponent(agentId)}`);
  }

  async createApiKey(
    agentId: string,
    clientId: string,
    labels?: Record<string, string>
  ): Promise<ApiKeyCreated> {
    return this.request<ApiKeyCreated>(`/api-keys/${encodeURIComponent(agentId)}`, {
      method: 'POST',
      body: JSON.stringify({ client_id: clientId, labels }),
    });
  }

  async getApiKey(agentId: string, keyId: string): Promise<ApiKeyRecord> {
    return this.request<ApiKeyRecord>(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}`
    );
  }

  async revokeApiKey(agentId: string, keyId: string, actor?: string): Promise<void> {
    await this.request(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}/revoke`,
      {
        method: 'POST',
        body: JSON.stringify({ actor: actor || 'dashboard' }),
      }
    );
  }

  async rotateApiKey(agentId: string, keyId: string, actor?: string): Promise<ApiKeyCreated> {
    return this.request<ApiKeyCreated>(
      `/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}/rotate`,
      {
        method: 'POST',
        body: JSON.stringify({ actor: actor || 'dashboard' }),
      }
    );
  }

  async deleteApiKey(agentId: string, keyId: string): Promise<void> {
    await this.request(`/api-keys/${encodeURIComponent(agentId)}/${encodeURIComponent(keyId)}`, {
      method: 'DELETE',
    });
  }

  async cliConsent(request: CliLoginRequest): Promise<Response> {
    return this.fetch('/api/auth/cli/consent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  }

  async listAccessTokens(): Promise<AccessTokenMeta[]> {
    const response = await this.request<{ access_tokens: AccessTokenMeta[] }>('/access-tokens');
    return response.access_tokens ?? [];
  }

  async getAccessToken(id: string): Promise<AccessTokenMeta> {
    return this.request<AccessTokenMeta>(`/access-tokens/${encodeURIComponent(id)}`);
  }

  async createAccessToken(payload: CreateAccessTokenRequest): Promise<AccessTokenCreated> {
    return this.request<AccessTokenCreated>('/access-tokens', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateAccessToken(id: string, payload: UpdateAccessTokenRequest): Promise<AccessTokenMeta> {
    return this.request<AccessTokenMeta>(`/access-tokens/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async revokeAccessToken(id: string): Promise<void> {
    await this.request(`/access-tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
  }

  // Outbound Credentials Management
  async listCredentials(agentId: string): Promise<OutboundCredentialMeta[]> {
    return this.request<OutboundCredentialMeta[]>(`/credentials/${encodeURIComponent(agentId)}`);
  }

  async createCredential(
    agentId: string,
    targetIdentifier: string,
    credentialType: CredentialType,
    credentialValue: string,
    headerName?: string,
    headerFormat?: string,
    labels?: Record<string, string>
  ): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(`/credentials/${encodeURIComponent(agentId)}`, {
      method: 'POST',
      body: JSON.stringify({
        target_identifier: targetIdentifier,
        credential_type: credentialType,
        credential_value: credentialValue,
        header_name: headerName,
        header_format: headerFormat,
        labels,
        actor: 'dashboard',
      }),
    });
  }

  async getCredential(agentId: string, credentialId: string): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`
    );
  }

  async updateCredential(
    agentId: string,
    credentialId: string,
    credentialValue: string,
    targetIdentifier?: string,
    labels?: Record<string, string>
  ): Promise<OutboundCredentialMeta> {
    return this.request<OutboundCredentialMeta>(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`,
      {
        method: 'PUT',
        body: JSON.stringify({
          credential_value: credentialValue,
          target_identifier: targetIdentifier,
          labels,
          actor: 'dashboard',
        }),
      }
    );
  }

  async deleteCredential(agentId: string, credentialId: string): Promise<void> {
    await this.request(
      `/credentials/${encodeURIComponent(agentId)}/${encodeURIComponent(credentialId)}`,
      {
        method: 'DELETE',
      }
    );
  }

  // DID:webvh Identity Management
  async listDidWebVhIdentities(): Promise<any> {
    const response = await this.get<any>('/identities');
    return response.data;
  }

  async getDidWebVhIdentity(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}`);
    return response.data;
  }

  async createDidWebVhIdentity(request: any): Promise<any> {
    const response = await this.post<any>('/identities', request);
    return response.data;
  }

  async updateDidWebVhIdentity(id: string, didDocument: any, updateKeys?: string[]): Promise<any> {
    const response = await this.post<any>(`/identities/${encodeURIComponent(id)}/update`, {
      did_document: didDocument,
      update_keys: updateKeys,
    });
    return response.data;
  }

  async deleteDidWebVhIdentity(id: string): Promise<void> {
    await this.delete(`/identities/${encodeURIComponent(id)}`);
  }

  async getIdentityTrustScore(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}/trust-score`);
    return response.data;
  }

  async getIdentityVersionHistory(id: string): Promise<any> {
    const response = await this.get<any>(`/identities/${encodeURIComponent(id)}/history`);
    return response.data;
  }

  async rotateIdentityKeys(id: string, params?: { pre_rotation_seconds?: number }): Promise<any> {
    const response = await this.post<any>(
      `/identities/${encodeURIComponent(id)}/rotate-keys`,
      params
    );
    return response.data;
  }

  async transferIdentityOwnership(id: string, request: any): Promise<any> {
    const response = await this.post<any>(
      `/identities/${encodeURIComponent(id)}/transfer`,
      request
    );
    return response.data;
  }

  async resolveDidWebVh(did: string, versionId?: string, versionTime?: string): Promise<any> {
    const params = new URLSearchParams({ did });
    if (versionId) params.append('versionId', versionId);
    if (versionTime) params.append('versionTime', versionTime);
    const response = await this.get<any>(`/resolve?${params.toString()}`);
    return response.data;
  }

  async verifyDidWebVh(did: string, dna?: any): Promise<any> {
    const response = await this.post<any>(
      `/verify/${encodeURIComponent(did)}`,
      dna ? { dna } : undefined
    );
    return response.data;
  }

  // Debug: Export storage with PII redaction, encrypted with Ed25519 public key
  async exportStorage(publicKeyPem: string): Promise<Blob> {
    const response = await fetch(`${API_BASE}/debug/export-storage`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...sessionManager.getAuthHeaders(),
      },
      body: JSON.stringify({ public_key_pem: publicKeyPem }),
    });

    if (!response.ok) {
      let errorMessage = `Export failed: ${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.text();
        if (errorBody) errorMessage += ` - ${errorBody}`;
      } catch (_) {}
      throw new Error(errorMessage);
    }

    return response.blob();
  }

  // Admin: Backup storage (full, with PIIs) — downloads backup.agbak
  async backupStorage(): Promise<Blob> {
    const response = await fetch(`${API_BASE}/admin/backup-storage`, {
      method: 'POST',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
    });

    if (!response.ok) {
      let errorMessage = `Backup failed: ${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.text();
        if (errorBody) errorMessage += ` - ${errorBody}`;
      } catch (_) {}
      throw new Error(errorMessage);
    }

    return response.blob();
  }

  // Admin: Restore storage from backup.agbak (or legacy backup.tgwbak) upload
  async restoreStorage(file: File): Promise<{ status: string; message: string }> {
    const formData = new FormData();
    formData.append('backup', file);

    const response = await fetch(`${API_BASE}/admin/restore-storage`, {
      method: 'POST',
      headers: {
        ...sessionManager.getAuthHeaders(),
      },
      body: formData,
    });

    if (!response.ok) {
      let errorMessage = `Restore failed: ${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.text();
        if (errorBody) errorMessage += ` - ${errorBody}`;
      } catch (_) {}
      throw new Error(errorMessage);
    }

    return response.json();
  }
}

// API Key types
export interface ApiKeyMeta {
  key_id: string;
  agent_id: string;
  client_id: string;
  prefix: string;
  status: 'active' | 'revoked';
  labels: Record<string, string>;
  created_at: string;
  created_by: string;
  revoked_at?: string;
  revoked_by?: string;
  last_used_at?: string;
  use_count: number;
  needs_rotation?: boolean;
}

export interface ApiKeyRecord {
  key_id: string;
  agent_id: string;
  client_id: string;
  status: 'active' | 'revoked';
  labels: Record<string, string>;
  created_at: string;
  revoked_at?: string;
  last_used_at?: string;
  issuer: { actor: string; method: string };
  rotated_from?: string;
  needs_rotation?: boolean;
}

export interface ApiKeyCreated {
  key_id: string;
  agent_id: string;
  client_id: string;
  secret: string;
  created_at: string;
  rotated_from?: string;
}

// Outbound Credential types
export type CredentialType = 'api_key' | 'bearer_token' | 'basic_auth' | 'custom';

export interface OutboundCredentialMeta {
  credential_id: string;
  agent_id: string;
  target_identifier: string;
  credential_type: CredentialType;
  header_name: string;
  header_format: string;
  labels: Record<string, string>;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export const apiClient = new APIClient();

/**
 * Surface template — a reusable bundle of pre-configured surface items
 * (palette elements, edges, policies) the user can inject onto a
 * surface. Mirrors the backend `SurfaceTemplate` in
 * `src/agent_surface_templates/types.rs`.
 */
export interface SurfaceTemplate {
  $schema?: string;
  /** Server-minted on create when omitted/empty. */
  id: string;
  name: string;
  /**
   * Template kind. `partial` (default) is a bundle of incremental items
   * dropped onto an existing canvas. `full` carries a complete channel
   * snapshot under `channel` and is applied by replacing the current
   * pipe wholesale (after user confirmation). The two kinds use
   * different apply pipelines on the frontend — partials go through
   * `planTemplate`/`applyPlan`, fulls go through `applyFullTemplate`.
   */
  kind?: 'partial' | 'full';
  /** Short one-liner shown in the template list row. */
  description?: string;
  /** Long-form explanation shown when the template row is expanded. */
  details?: string;
  /**
   * Body text for the welcome callout shown on the canvas the first
   * time the user lands on a surface created from this template.
   * The dashboard renders title + dismiss + "don't show again"
   * automatically; this field is just the contextual hint. When
   * empty the dashboard falls back to its generic default text.
   */
  starter_hint?: string;
  /** FontAwesome icon name without the `fa-` prefix. */
  icon?: string;
  tags?: string[];
  /** `"system"` for builtins, otherwise the author DID / user id. */
  author?: string;
  created_at?: string;
  updated_at?: string;
  /** Server-set. Builtins are read-only via the REST API. */
  builtin?: boolean;
  /**
   * Optional UX hint controlling display order in template lists and
   * the create-surface picker. Lower values sort first; ties fall
   * back to alphabetical by name. Templates without this field sort
   * last (the loader defaults it to `Number.MAX_SAFE_INTEGER`).
   */
  sort_priority?: number;
  /**
   * Item list for `kind: 'partial'` templates. Empty / omitted for
   * full templates.
   */
  items?: SurfaceTemplateItem[];
  /**
   * Verbatim surface snapshot for `kind: 'full'` templates. Same shape
   * the surface REST API accepts (an `AgentSurface`-equivalent
   * payload, including any variants under `canvas` / the access_point
   * node). May contain placeholder tokens like `$HOST` / `$ROUTE` /
   * `$NAME` / `$SLUG` / `$TARGET_ENDPOINT` that the apply step
   * substitutes against the current gateway / form context. Opaque
   * server-side — only the dashboard interprets it.
   */
  surface?: any;
}

export interface SurfaceTemplateItem {
  /**
   * Anchor scope. Known: `surface`, `target`, `access_point`,
   * `transit_point`, `gateway_policy`, `channel_policy`, `edge`.
   * Other strings are forward-compat placeholders.
   */
  scope: string;
  /** Element kind from the frontend registry (e.g. `agent_identity`). */
  kind: string;
  /** Optional address detail (e.g. `access_point->target` for edges). */
  address?: string;
  /** Partial config payload deep-merged onto the placed element. */
  config?: any;
}

export interface McpHttpConfig {
  allowed_origins?: string[];
  max_request_bytes?: number;
  max_header_bytes?: number;
  max_accept_ranges?: number;
  max_response_bytes?: number;
  max_chunk_bytes?: number;
  stream_idle_timeout_secs?: number;
  stream_max_lifetime_secs?: number;
  authorization?: {
    resource: string;
    scopes?: string[];
  };
}

export interface AgentSurface {
  surface_id: string;
  name: string;
  description: string;
  status: SurfaceStatus;
  agent_did?: string;
  issuer_id?: string;
  mcp_legacy_metadata_output?: 'compatibility' | 'canonical';
  mcp_http?: McpHttpConfig;
  tags: string[];
  access_point: {
    name?: string;
    listen_address: string;
    route: string;
    protocol: 'a2a' | 'ap2' | 'mcp';
    caller_context?: { mode: 'required' | 'optional' | 'anonymous' };
    identity_resolution?: any;
    inbound_policy?: { policy_definition_id: string };
    rate_limit?: { requests: number; window_secs: number };
    header_metadata_mapping?: {
      extension_uri?: string;
      headers?: Array<{ header: string; field: string }>;
      strip_mapped_headers?: boolean;
    };
    publish_to_did_document?: boolean;
    terminate_trace_id?: boolean;
    /** Per-surface A2A settings (A2A and AP2 Access Points). Absent means both versions, no request-shape validation. */
    a2a?: { accepted_versions: string[]; validate_messages: boolean };
  };
  target: {
    endpoint: string;
    a2a_proxy_id?: string;
    auth?: any;
    policy?: { policy_definition_id: string };
    response_policy?: { policy_definition_id: string };
    payment_policy?: any;
    mcp_tool_policies?: any[];
    /** MCP Tool Gating firewall (`{ gates: [...] }`). Passed through verbatim. */
    mcp_tool_gating?: { gates?: any[] };
    networking?: any;
    /**
     * Frontend-facing identity definition. The API client translates this
     * to/from the backend's `identity_injection` shape on every request —
     * the wire format and the UI model are intentionally decoupled so they
     * can evolve independently.
     */
    agent_identity?: {
      type?: 'from_payload' | 'from_api_key' | 'from_mtls' | 'static' | 'from_jwt_claim';
      api_key_id?: string;
      certificate_id?: string;
      static_did?: string;
      claim?: string;
      namespace_claims?: string[];
      meta_field?: string;
      extension_uri?: string;
      fields?: string[];
      json_schema?: any;
    };
  };
  transit?: {
    points: TransitPoint[];
    sign_requests?: boolean;
    transit_token_mode?: 'embedded' | 'reference';
    rate_limit?: { requests: number; window_secs: number };
  };
  /**
   * Opaque dashboard-owned blob persisting canvas layout (positions,
   * decorative NPC/human/caller nodes). The backend stores it verbatim;
   * the runtime never reads it.
   */
  canvas?: any;
  /**
   * Surface variants ("virtual channels"). Each carries an `overrides`
   * delta applied over the base surface at resolve time; addressed by
   * URL suffix `$alias`. Projected to/from the target-variant element.
   */
  variants?: SurfaceVariant[];
  /**
   * Id of the variant served for alias-less URLs. When absent/empty the
   * runtime resolves the base surface.
   */
  default_variant_id?: string;
  last_activity?: string | null;
}

/**
 * A single surface variant. `overrides` is a partial surface delta
 * (whitelisted access_point/target/transit fields plus the canvas blob)
 * merged over the base at resolve time; an empty override inherits base.
 */
export interface SurfaceVariant {
  id: string;
  alias: string;
  name: string;
  enabled?: boolean;
  overrides?: any;
}

export interface TransitPoint {
  /**
   * URL-safe identifier auto-derived from `name` on save (see
   * `slugifyAlias` / `deriveTransitPointAlias`). Stable across renames
   * of `name` once persisted; used as the routing/metrics key on the
   * backend and to correlate task rows in the dashboard.
   */
  alias?: string;
  name: string;
  target_endpoint: string;
  protocol: 'a2a' | 'ap2' | 'mcp' | 'http';
  mcp_http?: McpHttpConfig;
  target_auth?: any;
  policy?: { policy_definition_id: string };
  payment_policy?: any;
  networking?: any;
  identity_injection?: { inject_vp: boolean };
  transit_credentials?: any;
  /** Per-Transit-Point MCP Tool Gating firewall (`{ gates: [...] }`, MCP only). */
  mcp_tool_gating?: { gates?: any[] };
}

// ---------------------------------------------------------------------------
// Surface translation layer
// ---------------------------------------------------------------------------
// The frontend models the identity element as `target.agent_identity` with a
// `type` discriminator. The backend persists `target.identity_injection`
// (currently `{ inject_vp }` plus extra fields it ignores). These helpers are
// the single chokepoint that bridges the two shapes so the UI never leaks
// backend-specific names and the backend can evolve without churning the UI.

function toBackendSurface(surface: Partial<AgentSurface>): any {
  if (!surface || !surface.target) return surface;
  const target: any = { ...surface.target };
  const ai: any = (target as any).agent_identity;
  // Preserve any operator-set inject_vp toggle (Managed Agent panel); default
  // to true so legacy surfaces that never carried the flag keep stamping a VP.
  const existingII = (target as any).identity_injection;
  const injectVp =
    existingII && typeof existingII === 'object' && typeof existingII.inject_vp === 'boolean'
      ? (existingII.inject_vp as boolean)
      : true;
  if (ai && typeof ai === 'object') {
    delete target.agent_identity;
    target.identity_injection = {
      inject_vp: injectVp,
      ...ai,
    };
  } else if (existingII && typeof existingII === 'object') {
    target.identity_injection = { inject_vp: injectVp };
  }
  return { ...surface, target };
}

function fromBackendSurface(surface: AgentSurface): AgentSurface {
  if (!surface || !surface.target) return surface;
  const target: any = { ...surface.target };
  const ii: any = (target as any).identity_injection;
  if (ii && typeof ii === 'object') {
    const { inject_vp, ...rest } = ii;
    if (Object.keys(rest).length > 0) {
      target.agent_identity = rest;
    }
    // Keep the toggle on `target.identity_injection` so the Managed Agent
    // panel can round-trip it; legacy agent-identity fields move out to
    // `target.agent_identity` for the legacy Identity panel.
    target.identity_injection = { inject_vp: typeof inject_vp === 'boolean' ? inject_vp : true };
  }
  return { ...surface, target };
}
