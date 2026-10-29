export const PREFIX = 'oidc-e2e';

export const names = {
    secrets: {
        hop2ClientId: `${PREFIX}-hop2-client-id`,
        hop2ClientSecret: `${PREFIX}-hop2-client-secret`,
        signingKey: `${PREFIX}-signing-key`,
        ccClientId: `${PREFIX}-cc-client-id`,
        ccClientSecret: `${PREFIX}-cc-client-secret`,
    },
    strategies: {
        hydraA: {id: `${PREFIX}-hydra-a`, name: `${PREFIX} hydra-a`},
        hydraB: {id: `${PREFIX}-hydra-b`, name: `${PREFIX} hydra-b`},
    },
    providers: {
        clientCredentials: `${PREFIX} client credentials`,
        jwtBearer: `${PREFIX} jwt bearer`,
    },
    surface: `${PREFIX}-surface`,
    clients: {
        good: 'demo-good',
        hop2: `${PREFIX}-hop2`,
    },
    assertion: {issuer: `${PREFIX}-gateway`, subject: `${PREFIX}-gateway-subject`, kid: `${PREFIX}-key-1`},
    scopes: {caller: 'a2a.invoke', hop2: 'agent.invoke'},
};
