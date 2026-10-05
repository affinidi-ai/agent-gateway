import { apiClient } from './api';

export type TermsType = 'affinidi' | 'customer';

export interface TermsRequirement {
  terms_type: TermsType;
  document_id: string;
  version_id: string;
  version: string;
  title: string;
  url: string;
}

export interface TermsVersion extends TermsRequirement {
  requires_reconsent: boolean;
  published_at: string;
  published_by?: string;
}

export interface CustomerTermsDraft {
  version: string;
  title: string;
  url: string;
  requires_reconsent: boolean;
}

export interface CustomerTermsDocument {
  id: string;
  draft?: CustomerTermsDraft;
  current_version_id?: string;
  versions: TermsVersion[];
}

export type AffinidiProviderState = 'healthy' | 'degraded' | 'unavailable';

export interface AffinidiProviderStatus {
  state: AffinidiProviderState;
  last_successful_refresh?: string;
}

export interface TermsDefinitions {
  affinidi?: TermsVersion;
  affinidi_provider?: AffinidiProviderStatus;
  customer: CustomerTermsDocument;
}

export const termsRequirementKey = (term: TermsRequirement): string =>
  `${term.terms_type}:${term.document_id}:${term.version_id}`;

export interface TermsStatus {
  consent_required: boolean;
  required_terms: TermsRequirement[];
}

export class TermsApiError extends Error {
  constructor(
    public readonly code: string,
    public readonly status: number,
    public readonly requiredTerms: TermsRequirement[] = [],
    message?: string
  ) {
    super(message ?? code);
  }
}

async function read<T>(response: Response): Promise<T> {
  const text = await response.text();
  let body: { code?: string; required_terms?: TermsRequirement[]; message?: string } = {};
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new SyntaxError('Expected a JSON object');
    }
    body = parsed as typeof body;
  } catch {
    if (!response.ok) {
      throw new TermsApiError('TERMS_OPERATIONAL_FAILURE', response.status);
    }
    throw new Error(`Expected a JSON response but received: ${text.slice(0, 200)}`);
  }
  if (!response.ok) {
    throw new TermsApiError(
      body.code ?? 'TERMS_OPERATIONAL_FAILURE',
      response.status,
      body.required_terms ?? [],
      body.code === 'TERMS_INVALID' && typeof body.message === 'string' ? body.message : undefined
    );
  }
  return body as T;
}

export async function loadApplicableTerms(): Promise<TermsRequirement[]> {
  const response = await apiClient.fetch('/api/v1/terms/applicable');
  return (await read<{ terms: TermsRequirement[] }>(response)).terms;
}

export async function loadTermsStatus(): Promise<TermsStatus> {
  return read<TermsStatus>(await apiClient.fetch('/api/v1/terms/status'));
}

export async function loadTermsDefinitions(): Promise<TermsDefinitions> {
  return read<TermsDefinitions>(await apiClient.fetch('/api/v1/terms'));
}

export async function saveCustomerTermsDraft(
  draft: CustomerTermsDraft
): Promise<CustomerTermsDocument> {
  return read<CustomerTermsDocument>(
    await apiClient.fetch('/api/v1/terms/customer/draft', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(draft),
    })
  );
}

export async function publishCustomerTerms(): Promise<TermsVersion> {
  return read<TermsVersion>(
    await apiClient.fetch('/api/v1/terms/customer/publish', { method: 'POST' })
  );
}

export async function deactivateCustomerTerms(): Promise<void> {
  await read(await apiClient.fetch('/api/v1/terms/customer/deactivate', { method: 'POST' }));
}

export async function acceptTerms(requiredTerms: TermsRequirement[]): Promise<void> {
  await read(
    await apiClient.fetch('/api/v1/terms/acceptances', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accepted_terms: requiredTerms.map(term => ({
          terms_type: term.terms_type,
          version_id: term.version_id,
          accepted: true,
        })),
      }),
    })
  );
}
