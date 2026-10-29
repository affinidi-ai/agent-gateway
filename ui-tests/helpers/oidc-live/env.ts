import fs from 'fs';
import path from 'path';

function required(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`${name} is not set; run this suite with scripts/oidc-demo/run-ui-e2e.sh (make oidc-ui-e2e)`);
    }
    return value;
}

const accessPointOrigin = required('OIDC_E2E_ACCESS_POINT_ORIGIN');
const routePrefix = process.env.OIDC_E2E_SURFACE_ROUTE || '/mock-agent';
const customPath = 'agent';
const route = `${routePrefix}/${customPath}`;

export const env = {
    gatewayUrl: required('AG_BASE_URL'),
    hydraA: {issuer: required('OIDC_E2E_HYDRA_A_ISSUER'), admin: required('OIDC_E2E_HYDRA_A_ADMIN')},
    hydraB: {
        issuer: required('OIDC_E2E_HYDRA_B_ISSUER'),
        admin: required('OIDC_E2E_HYDRA_B_ADMIN'),
        container: required('OIDC_E2E_HYDRA_B_CONTAINER'),
    },
    agentUrl: required('OIDC_E2E_AGENT_URL'),
    accessPointOrigin,
    routePrefix,
    customPath,
    route,
    entryPointUrl: `${accessPointOrigin}${route}`,
    gatewayEnvDir: required('OIDC_E2E_GATEWAY_ENV_DIR'),
    stateFile: required('OIDC_E2E_WORLD_FILE'),
};

export function issuerWithoutSlash(issuer: string): string {
    return issuer.replace(/\/+$/, '');
}

export function ensureDir(file: string): void {
    fs.mkdirSync(path.dirname(file), {recursive: true});
}
