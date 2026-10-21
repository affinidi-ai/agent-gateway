import { apiClient } from './api';
import { setVariablePattern } from './utils/templateVariables';

/** Integrations, their endpoints and event sets: `/v1/integrations`. */

export type DefinitionStatus = 'active' | 'disabled';

export type EndpointType = 'email' | 'slack' | 'webhook' | 'stream';

export interface CatalogEvent {
  id: string;
  name: string;
  description: string;
  family: string;
  family_label: string;
  /** Audit events only: the audit catalog group. */
  group?: string;
  group_label?: string;
  /** The template variables a delivery of this event fills. */
  variables: string[];
}

export interface CatalogVariable {
  name: string;
  label: string;
  description: string;
}

export interface EndpointTypeInfo {
  type: EndpointType;
  /** Configuration fields that are written but never read back. */
  secret_fields: string[];
}

export interface IntegrationCatalog {
  events: CatalogEvent[];
  variables: CatalogVariable[];
  endpoint_types: EndpointTypeInfo[];
  /** The placeholder syntax; its first group is the variable name. */
  variable_pattern: string;
}

export interface Endpoint {
  id: string;
  name: string;
  description: string;
  type: EndpointType;
  /** Without its secret fields, except `$SECRET:` references. */
  configuration: Record<string, unknown>;
  status: DefinitionStatus;
  /** The secret fields that hold a value. */
  secrets: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateEndpointRequest {
  name: string;
  description: string;
  type: EndpointType;
  configuration: Record<string, unknown>;
  status?: DefinitionStatus;
}

/** A secret field left out keeps its value; one sent as `null` clears it. */
export interface UpdateEndpointRequest {
  name: string;
  description: string;
  configuration: Record<string, unknown>;
  status: DefinitionStatus;
}

export interface EventSet {
  id: string;
  name: string;
  description: string;
  events: string[];
  created_at: string;
  updated_at: string;
}

export interface EventSetRequest {
  name: string;
  description: string;
  events: string[];
}

export interface Integration {
  id: string;
  name: string;
  description: string;
  endpoint_id: string;
  event_set_id: string;
  content: Record<string, unknown>;
  status: DefinitionStatus;
  audit_drop_after_secs?: number;
  audit_max_attempts?: number;
  created_at: string;
  updated_at: string;
}

export interface IntegrationRequest {
  name: string;
  description: string;
  endpoint_id: string;
  event_set_id: string;
  content: Record<string, unknown>;
  status?: DefinitionStatus;
  audit_drop_after_secs?: number | null;
  audit_max_attempts?: number | null;
}

export interface TestResult {
  delivered: boolean;
  event_type: string;
}

const BASE = '/integrations';
const TEST_TIMEOUT_MS = 30000;

const one = (path: string, id: string) => `${path}/${encodeURIComponent(id)}`;

let catalogRequest: Promise<IntegrationCatalog> | null = null;

/** The catalog, loaded once; templates are then read with its placeholder syntax. */
export function getCatalog(): Promise<IntegrationCatalog> {
  if (!catalogRequest) {
    catalogRequest = apiClient
      .get<IntegrationCatalog>(`${BASE}/catalog`)
      .then(({ data }) => {
        setVariablePattern(data.variable_pattern);
        return data;
      })
      .catch(error => {
        catalogRequest = null;
        throw error;
      });
  }
  return catalogRequest;
}

/** For tests. */
export function resetCatalogCache(): void {
  catalogRequest = null;
}

export const listIntegrations = async () => (await apiClient.get<Integration[]>(BASE)).data;
export const getIntegration = async (id: string) =>
  (await apiClient.get<Integration>(one(BASE, id))).data;
export const createIntegration = async (request: IntegrationRequest) =>
  (await apiClient.post<Integration>(BASE, request)).data;
export const updateIntegration = async (id: string, request: IntegrationRequest) =>
  (await apiClient.put<Integration>(one(BASE, id), request)).data;
export const deleteIntegration = async (id: string) => {
  await apiClient.delete(one(BASE, id));
};

const ENDPOINTS = `${BASE}/endpoints`;

export const listEndpoints = async () => (await apiClient.get<Endpoint[]>(ENDPOINTS)).data;
export const getEndpoint = async (id: string) =>
  (await apiClient.get<Endpoint>(one(ENDPOINTS, id))).data;
export const createEndpoint = async (request: CreateEndpointRequest) =>
  (await apiClient.post<Endpoint>(ENDPOINTS, request)).data;
export const updateEndpoint = async (id: string, request: UpdateEndpointRequest) =>
  (await apiClient.put<Endpoint>(one(ENDPOINTS, id), request)).data;
export const deleteEndpoint = async (id: string) => {
  await apiClient.delete(one(ENDPOINTS, id));
};

const EVENT_SETS = `${BASE}/event-sets`;

export const listEventSets = async () => (await apiClient.get<EventSet[]>(EVENT_SETS)).data;
export const getEventSet = async (id: string) =>
  (await apiClient.get<EventSet>(one(EVENT_SETS, id))).data;
export const createEventSet = async (request: EventSetRequest) =>
  (await apiClient.post<EventSet>(EVENT_SETS, request)).data;
export const updateEventSet = async (id: string, request: EventSetRequest) =>
  (await apiClient.put<EventSet>(one(EVENT_SETS, id), request)).data;
export const deleteEventSet = async (id: string) => {
  await apiClient.delete(one(EVENT_SETS, id));
};

/** Sends a saved integration's message once, for the first event of its event set. */
export const testIntegration = async (id: string) =>
  (
    await apiClient.post<TestResult>(`${one(BASE, id)}/test`, undefined, {
      timeout: TEST_TIMEOUT_MS,
    })
  ).data;

/** As {@link testIntegration}, for an integration not saved yet. */
export const testDraftIntegration = async (request: IntegrationRequest) =>
  (await apiClient.post<TestResult>(`${BASE}/test`, request, { timeout: TEST_TIMEOUT_MS })).data;

/** Sends the endpoint's default message once. */
export const testEndpoint = async (id: string) =>
  (
    await apiClient.post<TestResult>(`${one(ENDPOINTS, id)}/test`, undefined, {
      timeout: TEST_TIMEOUT_MS,
    })
  ).data;
