import {spawnSync} from 'child_process';
import {randomUUID} from 'crypto';
import {APIRequestContext, expect} from '@playwright/test';
import {env} from './env';

export interface AgentLogEntry {
    method: string;
    path: string;
    authenticated: boolean;
    client_id: string;
    status: number;
}

export async function agentLog(api: APIRequestContext): Promise<AgentLogEntry[]> {
    return (await (await api.get(`${env.agentUrl}/_demo/log`)).json()) as AgentLogEntry[];
}

export async function resetAgentLog(api: APIRequestContext): Promise<void> {
    await api.post(`${env.agentUrl}/_demo/reset`);
}

function hydraBLogs(): string {
    const result = spawnSync('docker', ['logs', env.hydraB.container], {encoding: 'utf8', maxBuffer: 64 * 1024 * 1024});
    return `${result.stdout}\n${result.stderr}`;
}

/**
 * Number of requests hydra-b has served at its token endpoint.
 *
 * Docker delivers container logs after a delay, so the count is read only after a request that
 * carries a unique marker shows up in the log: the log is ordered, so everything before the marker
 * has arrived too.
 */
export async function hydraBTokenRequests(api: APIRequestContext): Promise<number> {
    const marker = `barrier-${randomUUID()}`;
    await api.get(`${env.hydraB.admin}/admin/clients/${marker}`, {failOnStatusCode: false});
    await expect.poll(() => hydraBLogs().includes(marker), {message: 'hydra-b log shows the barrier request', timeout: 15_000}).toBe(true);
    return hydraBLogs()
        .split('\n')
        .filter(line => line.includes('completed handling request') && line.includes('path:/oauth2/token')).length;
}

const MESSAGE_SEND = {
    jsonrpc: '2.0',
    id: 7,
    method: 'message/send',
    params: {message: {role: 'user', messageId: 'oidc-e2e-1', parts: [{kind: 'text', text: 'hello'}]}},
};

export async function callAgent(
    api: APIRequestContext,
    token?: string
): Promise<{status: number; headers: Record<string, string>; text: string}> {
    const response = await api.post(env.entryPointUrl, {
        headers: {'Content-Type': 'application/json', ...(token ? {Authorization: `Bearer ${token}`} : {})},
        data: MESSAGE_SEND,
        failOnStatusCode: false,
    });
    return {status: response.status(), headers: response.headers(), text: await response.text()};
}
