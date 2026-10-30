/**
 * Authenticated gateway API client for specs that need real backend state.
 *
 * Specs drive the dashboard in the browser and use this client to seed
 * prerequisites, read back what the dashboard saved, and clean up, so each
 * spec leaves the gateway as it found it.
 */

import {APIRequestContext, request} from '@playwright/test';
import {authenticateTestUser} from './test-auth';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

export interface GatewayResponse<T = unknown> {
    status: number;
    body: T;
}

export class GatewayApi {
    private constructor(private readonly context: APIRequestContext) {}

    static async connect(): Promise<GatewayApi> {
        const bootstrap = await request.newContext();
        const auth = await authenticateTestUser(bootstrap, BASE_URL);
        await bootstrap.dispose();
        if (!auth.success || !auth.sessionToken) {
            throw new Error(`Gateway test login failed: ${auth.error}`);
        }
        const context = await request.newContext({
            baseURL: BASE_URL,
            extraHTTPHeaders: {Authorization: `Bearer ${auth.sessionToken}`},
        });
        return new GatewayApi(context);
    }

    async dispose(): Promise<void> {
        await this.context.dispose();
    }

    async get<T = unknown>(path: string): Promise<GatewayResponse<T>> {
        return this.read<T>(await this.context.get(path));
    }

    async post<T = unknown>(path: string, data: unknown): Promise<GatewayResponse<T>> {
        return this.read<T>(await this.context.post(path, {data}));
    }

    async put<T = unknown>(path: string, data: unknown): Promise<GatewayResponse<T>> {
        return this.read<T>(await this.context.put(path, {data}));
    }

    async patch<T = unknown>(path: string, data: unknown): Promise<GatewayResponse<T>> {
        return this.read<T>(
            await this.context.patch(path, {data, headers: {'Content-Type': 'application/merge-patch+json'}})
        );
    }

    async delete(path: string): Promise<number> {
        return (await this.context.delete(path)).status();
    }

    private async read<T>(response: Awaited<ReturnType<APIRequestContext['get']>>): Promise<GatewayResponse<T>> {
        const text = await response.text();
        let body: unknown = text;
        try {
            body = JSON.parse(text);
        } catch {
            // Non-JSON bodies are returned as text.
        }
        return {status: response.status(), body: body as T};
    }
}
