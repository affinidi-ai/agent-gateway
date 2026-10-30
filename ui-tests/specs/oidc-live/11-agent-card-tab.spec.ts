/**
 * The Agent Cards tab
 *
 * An operator opens a saved A2A surface and compares the Managed Agent Card with the
 * Gateway-Served Agent Card, reads how the gateway's fetch of the agent's card went, refreshes it,
 * and diagnoses a card the gateway cannot fetch: the agent refusing the gateway's token, and a
 * surface with no Target Authentication in front of a login-only card. Nothing on the identity
 * side is mocked.
 *
 * The pages of this suite can show secret material, so each acceptance screenshot is of one area
 * only, taken after the test checked that the area shows no secret.
 */

import {APIRequestContext, Locator, Page, Response} from '@playwright/test';
import {expect, test} from '../../helpers/fixtures';
import {GatewayApi} from '../../helpers/gateway-api';
import {agentLog, resetAgentLog, setAgentRefusing} from '../../helpers/oidc-live/agent';
import {
    CARD_URL,
    CardJson,
    CardPreviewBody,
    SOURCE_CARD_URL,
    expectNoSecretIn,
    gatewayScheme,
    isCardRoute,
    readPreviewBody,
} from '../../helpers/oidc-live/agent-card';
import {openCallerAuth, openSurface, selectNode} from '../../helpers/oidc-live/builder';
import {env} from '../../helpers/oidc-live/env';
import {Entity, ensureSurface, listEntities} from '../../helpers/oidc-live/gateway-state';
import {newContext} from '../../helpers/oidc-live/hydra';
import {names, PREFIX} from '../../helpers/oidc-live/names';
import {loadWorld, World} from '../../helpers/oidc-live/world';
import {testUserStorageState, TestUserStorageState} from '../../helpers/test-auth';
import {attachCriterion, ticket} from '../../helpers/ticket';

const TICKET = 'FTL-30895';
const NO_AUTH_SURFACE = `${names.surface}-card-no-auth`;
const NO_AUTH_ROUTE = `${env.routePrefix}/card-no-auth`;
const CARD_OPERATOR = `${PREFIX}-card-operator`;
const METADATA_URL = `${env.hydraA.issuer}.well-known/oauth-authorization-server`;

const CHANGE_KINDS = [
    {status: 'added', label: 'Added', icon: 'fa-plus'},
    {status: 'changed', label: 'Modified', icon: 'fa-pen'},
    {status: 'removed', label: 'Removed', icon: 'fa-minus'},
    {status: 'same', label: 'Unchanged', icon: 'fa-equals'},
] as const;

let operatorState: Promise<TestUserStorageState> | undefined;

function surfaceIdOf(surface: Entity): string {
    return String(surface.surface_id ?? surface.id);
}

async function openTab(page: Page, world: World): Promise<CardPreviewBody> {
    const read = page.waitForResponse(response => isCardRoute(response, '', 'GET'));
    await page.getByTestId('surface-view-agent-card').click();
    const body = await readPreviewBody(await read, world);
    await expect(page.getByTestId('agent-card-tab')).toBeVisible();
    await expect(page.getByTestId('agent-card-loading')).toHaveCount(0);
    return body;
}

async function fetchedAt(page: Page): Promise<string> {
    const value = await page.getByTestId('agent-card-fetched-at').getAttribute('datetime');
    expect(value, 'the time element carries the fetch time').not.toBeNull();
    return String(value);
}

async function refresh(page: Page): Promise<Response> {
    const done = page.waitForResponse(response => isCardRoute(response, '/refresh', 'POST'));
    await page.getByTestId('agent-card-refresh-button').click();
    const response = await done;
    expect(response.status()).toBe(200);
    return response;
}

async function showRawJson(page: Page): Promise<void> {
    const toggle = page.getByTestId('agent-card-raw-toggle');
    if ((await toggle.getAttribute('aria-expanded')) !== 'true') await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
}

async function rawCard(area: Locator): Promise<CardJson> {
    return JSON.parse((await area.textContent()) ?? '') as CardJson;
}

function row(page: Page, key: string): Locator {
    return page.getByTestId(`agent-card-row-${key}`);
}

function managedCell(page: Page, key: string): Locator {
    return row(page, key).locator('td[data-label="Managed Agent Card"]');
}

function servedCell(page: Page, key: string): Locator {
    return row(page, key).locator('td[data-label="Gateway-Served Agent Card"]');
}

test.describe('Agent Cards tab', () => {
    test.describe.configure({mode: 'serial'});
    test.use({
        storageState: async ({}, use) => {
            operatorState ??= testUserStorageState(env.gatewayUrl, CARD_OPERATOR);
            await use(await operatorState);
        },
    });

    let http: APIRequestContext;
    let api: GatewayApi;
    let world: World;
    let surface: Entity;
    let noAuthSurface: Entity | undefined;

    async function removeNoAuthSurface(): Promise<void> {
        for (const listed of await listEntities(api, '/api/v1/surfaces')) {
            if (listed.name === NO_AUTH_SURFACE) await api.delete(`/api/v1/surfaces/${surfaceIdOf(listed)}`);
        }
    }

    test.beforeAll(async () => {
        http = await newContext();
        api = await GatewayApi.connect();
        world = loadWorld();
        await setAgentRefusing(http, false);
        surface = await ensureSurface(api, world);
        await removeNoAuthSurface();
    });

    test.afterAll(async () => {
        try {
            await setAgentRefusing(http, false);
            await resetAgentLog(http);
            await removeNoAuthSurface();
        } finally {
            await api.dispose();
            await http.dispose();
        }
    });

    test('the Agent Cards tab sits directly after Elements and before Monitoring and loads the cards the gateway fetched', async ({
        page,
    }) => {
        ticket(TICKET, 'FTL-30887');
        await openSurface(page, surfaceIdOf(surface));
        const view = page.getByTestId('surface-view-agent-card');
        await expect(view).toHaveText('Agent Cards');
        const order = await page
            .locator("[data-testid^='surface-view-']")
            .evaluateAll(views => views.map(v => v.getAttribute('data-testid')));
        const index = order.indexOf('surface-view-agent-card');
        expect(index).toBeGreaterThan(0);
        expect(order[index - 1]).toBe('surface-view-elements');
        expect(order[index + 1]).toBe('surface-view-monitoring');

        const read = page.waitForResponse(response => isCardRoute(response, '', 'GET'));
        await view.click();
        await expect(view).toHaveAttribute('aria-current', 'page');
        await expect(page.getByTestId('agent-card-heading')).toHaveText('Agent Cards');
        const body = await readPreviewBody(await read, world);

        expect(body.supported).toBe(true);
        expect(body.generated).toBe(false);
        expect(body.fetch).toMatchObject({status: 'ok', cause: null, http_status: null});
        expect(body.auth).toMatchObject({kind: 'credential_provider', result: 'sent', provider_name: names.providers.jwtBearer, failure: null});
        expect(body.auth.token_expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
        expect(body.served_url).toBe(CARD_URL);
        expect(body.source_url).toBe(SOURCE_CARD_URL);
        expect(body.source_url_query_hidden).toBe(false);
        expect(body.outcome).toEqual({
            variant: null,
            outcome: 'declare',
            reason: null,
            resource: env.entryPointUrl,
            authorization_servers: [env.hydraA.issuer],
            required_scopes: [names.scopes.caller],
            scopes_supported: [names.scopes.caller],
            metadata_url: `${env.accessPointOrigin}/.well-known/oauth-protected-resource${env.route}`,
        });
        expect(body.before_bytes).toBeGreaterThan(0);
        expect(body.after_bytes).toBeGreaterThan(0);
        expect(body.display_limit_bytes).toBe(262144);
        await expect(page.getByTestId('agent-card-loading')).toHaveCount(0);
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');

        const views = page.locator('.surface-form-sidebar-section').filter({has: view});
        await expectNoSecretIn(views, world);
        await attachCriterion(TICKET, 1, 'Agent Cards tab placement', views);
    });

    test('the Managed Agent Card and the Gateway-Served Agent Card sit side by side, each change marked by colour, icon and label', async ({
        page,
    }) => {
        ticket(TICKET);
        await openSurface(page, surfaceIdOf(surface));
        const body = await openTab(page, world);
        expect(body.fetch.status).toBe('ok');

        const managed = page.getByTestId('agent-card-before');
        const served = page.getByTestId('agent-card-after');
        await expect(managed.locator('.agent-card-column-title')).toHaveText('Managed Agent Card');
        await expect(managed.locator('.agent-card-column-hint')).toHaveText("The agent's own card");
        await expect(served.locator('.agent-card-column-title')).toHaveText('Gateway-Served Agent Card');
        await expect(served.locator('.agent-card-column-hint')).toHaveText('What callers see');
        await expect(page.getByTestId('agent-card-era-before')).toHaveText('A2A 0.3');
        await expect(page.getByTestId('agent-card-era-after')).toHaveText('A2A 0.3');
        const managedBox = await managed.boundingBox();
        const servedBox = await served.boundingBox();
        if (!managedBox || !servedBox) throw new Error('The card columns are not visible');
        expect(servedBox.x).toBeGreaterThanOrEqual(managedBox.x + managedBox.width - 1);
        expect(Math.abs(managedBox.y - servedBox.y)).toBeLessThan(2);

        await expect(row(page, 'signin')).toHaveAttribute('data-status', 'changed');
        const removedScheme = managedCell(page, 'signin').locator('li[data-status="removed"]', {hasText: 'agent_own_oauth'});
        await expect(removedScheme.locator('.agent-card-status-removed')).toHaveText('Removed');
        await expect(removedScheme.getByTestId('agent-card-status-icon')).toHaveClass(/fa-minus/);
        const addedScheme = servedCell(page, 'signin').locator('li[data-status="added"]', {hasText: 'agent_gateway'});
        await expect(addedScheme.locator('.agent-card-status-added')).toHaveText('Added');
        await expect(addedScheme.getByTestId('agent-card-status-icon')).toHaveClass(/fa-plus/);
        const requiredSignIn = servedCell(page, 'signin').locator('li[data-status="changed"]', {hasText: 'Required sign-in'});
        await expect(requiredSignIn.locator('.agent-card-status-changed')).toHaveText('Modified');
        await expect(requiredSignIn.getByTestId('agent-card-status-icon')).toHaveClass(/fa-pen/);

        await expect(row(page, 'scope')).toHaveAttribute('data-status', 'changed');
        await expect(managedCell(page, 'scope').locator('li[data-status="removed"]')).toContainText(names.scopes.hop2);
        await expect(servedCell(page, 'scope').locator('li[data-status="added"]')).toContainText(names.scopes.caller);

        await expect(row(page, 'signature')).toHaveAttribute('data-status', 'removed');
        await expect(managedCell(page, 'signature')).toContainText('1 signature');
        await expect(servedCell(page, 'signature')).toContainText('Not present');

        await expect(row(page, 'endpoint')).toHaveAttribute('data-status', 'changed');
        await expect(managedCell(page, 'endpoint')).toContainText(env.agentUrl);
        await expect(servedCell(page, 'endpoint').locator('li[data-status="changed"]')).toContainText(env.entryPointUrl);
        await expect(servedCell(page, 'endpoint').locator('li[data-status="changed"]')).toContainText('(primary)');

        await expect(row(page, 'other')).toHaveAttribute('data-status', 'same');
        await expect(row(page, 'other').locator('li')).toHaveCount(0);
        await expect(servedCell(page, 'other')).toContainText('unchanged');

        await expect(page.getByTestId('agent-card-summary')).toContainText('The gateway changed');
        expect(Number(await page.getByTestId('agent-card-change-count').innerText())).toBeGreaterThanOrEqual(4);
        const colours: string[] = [];
        for (const kind of CHANGE_KINDS) {
            const legend = page.getByTestId(`agent-card-legend-${kind.status}`);
            await expect(legend).toHaveText(kind.label);
            await expect(legend.getByTestId('agent-card-status-icon')).toHaveClass(new RegExp(kind.icon));
            colours.push(await legend.evaluate(tag => getComputedStyle(tag).color));
        }
        expect(new Set(colours).size, 'each kind of change has its own colour').toBe(CHANGE_KINDS.length);

        await showRawJson(page);
        const rawManaged = page.getByTestId('agent-card-raw-before');
        const rawServed = page.getByTestId('agent-card-raw-after');
        const managedCard = await rawCard(rawManaged);
        const servedCard = await rawCard(rawServed);
        expect(managedCard).toEqual(body.before);
        expect(servedCard).toEqual(body.after);
        expect(managedCard.url).toBe(env.agentUrl);
        expect(managedCard).toHaveProperty('signatures');
        expect(Object.keys(managedCard.securitySchemes as object)).toEqual(['agent_own_oauth']);
        expect(servedCard.url).toBe(env.entryPointUrl);
        expect(servedCard).not.toHaveProperty('signatures');
        expect(gatewayScheme(servedCard).oauth2MetadataUrl).toBe(METADATA_URL);
        await expect(page.getByTestId('agent-card-copy-before-button')).toBeVisible();
        await expect(page.getByTestId('agent-card-copy-after-button')).toBeVisible();

        const tab = page.getByTestId('agent-card-tab');
        await expectNoSecretIn(tab, world);
        await attachCriterion(TICKET, 2, 'Managed and served cards side by side', tab);
    });

    test('the Surface view keeps the Entry point URL, and the tab links to it and copies the served card discovery URL', async ({
        page,
    }) => {
        ticket(TICKET);
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], {origin: new URL(env.gatewayUrl).origin});
        await openSurface(page, surfaceIdOf(surface));
        const entryPoint = page.getByTestId('surface-entry-point-url');
        await expect(entryPoint).toContainText(env.entryPointUrl);

        const body = await openTab(page, world);
        expect(body.served_url).toBe(CARD_URL);
        const tab = page.getByTestId('agent-card-tab');
        await expect(tab.getByTestId('surface-entry-point-url')).toHaveCount(0);
        await expect(tab.getByTestId('access-point-entry-point-url')).toHaveCount(0);
        await expect(tab.getByTestId('agent-card-surface-link')).toContainText('Entry point URL');
        await expect(tab.getByTestId('agent-card-header')).toContainText('Served card discovery URL');
        await expect(tab.getByTestId('agent-card-served-url')).toHaveText(CARD_URL);
        const open = tab.getByTestId('agent-card-open-button');
        await expect(open).toHaveAttribute('href', CARD_URL);
        await expect(open).toHaveAttribute('target', '_blank');
        await expect(open).toHaveAttribute('rel', 'noopener noreferrer');

        const copy = tab.getByTestId('agent-card-url-copy-button');
        await copy.click();
        await expect(copy).toHaveText('Copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(CARD_URL);
        expect((await http.get(CARD_URL)).status(), 'the copied URL serves the card').toBe(200);

        await expectNoSecretIn(tab, world);
        await attachCriterion(TICKET, 3, 'Served card URL and link to the Surface', tab);

        await tab.getByTestId('agent-card-open-surface-button').click();
        await expect(page.getByTestId('surface-view-surface')).toHaveAttribute('aria-current', 'page');
        await expect(entryPoint).toContainText(env.entryPointUrl);
    });

    test('the authorization server, required scope and resource set in the Caller Context editor are what the served card declares', async ({
        page,
    }) => {
        ticket(TICKET, 'FTL-30894');
        await openSurface(page, surfaceIdOf(surface));
        await openCallerAuth(page);
        await expect(page.getByTestId('caller-auth-jwt-strategy')).toHaveValue(names.strategies.hydraA.id);
        await expect(page.getByTestId('caller-auth-scopes')).toContainText(names.scopes.caller);
        await expect(page.getByTestId('caller-auth-discovery-derived-authorization-server')).toHaveText(env.hydraA.issuer);
        await expect(page.getByTestId('caller-auth-discovery-derived-scopes')).toHaveText(names.scopes.caller);
        await expect(page.getByTestId('caller-auth-discovery-derived-audience')).toContainText(env.entryPointUrl);
        await expect(page.getByTestId('caller-auth-discovery-switch')).toBeChecked();
        await expect(page.getByTestId('caller-auth-discovery-resource-input')).toHaveValue(env.entryPointUrl);
        await expect(page.getByTestId('caller-auth-outcome-chip').first()).toContainText('Declares OAuth');
        await attachCriterion(
            TICKET,
            5,
            'Authorization server discovery, scopes and resource in the Caller Context editor',
            page.getByTestId('caller-auth-discovery')
        );
        await page.getByTestId('caller-auth-close-button').click();

        const panelOutcome = page.getByTestId('caller-auth-panel-outcome');
        await expect(panelOutcome.getByTestId('caller-auth-outcome-chip')).toContainText('Declares OAuth');
        await panelOutcome.getByTestId('caller-auth-outcome-card-link').click();
        const tab = page.getByTestId('agent-card-tab');
        await expect(tab).toBeVisible();
        await expect(page.getByTestId('surface-view-agent-card')).toHaveAttribute('aria-current', 'page');
        await expect(tab.getByTestId('agent-card-outcome')).toContainText('Declares OAuth');
        await expect(servedCell(page, 'scope').locator('li[data-status="added"]')).toContainText(names.scopes.caller);

        await showRawJson(page);
        const servedCard = await rawCard(page.getByTestId('agent-card-raw-after'));
        const scheme = gatewayScheme(servedCard);
        expect(scheme.type).toBe('oauth2');
        expect(scheme.oauth2MetadataUrl).toBe(METADATA_URL);
        expect(scheme.flows.clientCredentials.tokenUrl).toBe(`${env.hydraA.issuer}oauth2/token`);
        expect(Object.keys(scheme.flows.clientCredentials.scopes)).toEqual([names.scopes.caller]);
        expect(servedCard.security).toEqual([{agent_gateway: [names.scopes.caller]}]);
        expect(servedCard.url).toBe(env.entryPointUrl);

        await expectNoSecretIn(tab, world);
        await attachCriterion(TICKET, 5, 'Caller declaration reflected in the served card', tab);
    });

    test('the Managed Agent panel shows the card fetch status and links to the tab', async ({page}) => {
        ticket('FTL-30895');
        await openSurface(page, surfaceIdOf(surface));
        await selectNode(page, 'target');
        await expect(page.getByTestId('managed-agent-card-fetch-status')).toHaveText('Card fetch: OK');
        await page.getByTestId('managed-agent-card-fetch-link').click();
        await expect(page.getByTestId('agent-card-tab')).toBeVisible();
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
    });

    test('Refresh asks the agent again with the gateway token and moves the fetch time', async ({page}) => {
        ticket(TICKET, 'FTL-30887');
        await openSurface(page, surfaceIdOf(surface));
        await openTab(page, world);
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
        await expect(page.getByTestId('agent-card-auth')).toContainText(`${names.providers.jwtBearer}, token valid until`);
        await expect(page.getByTestId('agent-card-refresh-button')).toBeEnabled();
        const first = await fetchedAt(page);
        await expect
            .poll(() => Date.now() - Date.parse(first), {message: 'a whole second has passed since the first fetch', timeout: 5_000})
            .toBeGreaterThan(1_100);

        await resetAgentLog(http);
        const body = await readPreviewBody(await refresh(page), world);
        expect(body.cached).toBe(false);
        expect(body.fetch.status).toBe('ok');
        expect(body.fetched_at).not.toBe(first);
        expect(Date.parse(body.fetched_at as string)).toBeGreaterThan(Date.parse(first));

        await expect.poll(() => fetchedAt(page), {message: 'the dashboard shows the new fetch time'}).toBe(body.fetched_at);
        await expect(page.getByTestId('agent-card-refresh-status')).toHaveText('Card refreshed. The card fetch is OK.');
        const log = await agentLog(http);
        expect(
            log.filter(entry => entry.method === 'GET' && entry.authenticated && entry.client_id === names.clients.hop2 && entry.status === 200),
            'the agent saw one authenticated card fetch from the gateway'
        ).toHaveLength(1);
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
    });

    test('a failed managed card fetch shows its cause and HTTP status, keeps the served card visible, and Refresh recovers once the agent is fixed', async ({
        page,
    }) => {
        ticket(TICKET, 'FTL-30887');
        await openSurface(page, surfaceIdOf(surface));
        await openTab(page, world);
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
        const tab = page.getByTestId('agent-card-tab');

        try {
            await setAgentRefusing(http, true);
            const callerCard = await http.get(CARD_URL, {failOnStatusCode: false});
            expect(callerCard.status(), 'a caller gets no card while the agent refuses the gateway').not.toBe(200);

            const failed = await readPreviewBody(await refresh(page), world);
            expect(failed.fetch).toMatchObject({status: 'failed', cause: 'auth_failed', http_status: 401});
            expect(failed.auth).toMatchObject({kind: 'credential_provider', result: 'sent', provider_name: names.providers.jwtBearer});
            expect(failed.before).toBeNull();
            expect(failed.after, 'the preview keeps the card the gateway last served').not.toBeNull();
            expect(gatewayScheme(failed.after as CardJson).oauth2MetadataUrl).toBe(METADATA_URL);
            expect(failed.last_caller_fetch).toMatchObject({status: 'failed', cause: 'auth_failed', http_status: 401});

            await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('Failing');
            const cause = page.getByTestId('agent-card-fetch-cause');
            await expect(cause).toHaveAttribute('data-cause', 'auth_failed');
            await expect(cause).toHaveText('Sign-in failed — HTTP 401');
            await expect(page.getByTestId('agent-card-failed')).toBeVisible();
            await expect(page.getByTestId('agent-card-failed-cause')).toHaveText(
                "The agent rejected the gateway's credential (HTTP 401). Check the provider's scopes and audience."
            );
            await expect(page.getByTestId('agent-card-last-caller-fetch')).toContainText('Failing: Sign-in failed — HTTP 401');
            await expect(page.getByTestId('agent-card-refresh-button')).toBeEnabled();
            await expect(page.getByTestId('agent-card-refresh-status')).toHaveText('Card refreshed. The card fetch is failing.');
            await expect(page.getByTestId('agent-card-raw-before')).toHaveCount(0);
            const servedDuringFailure = page.getByTestId('agent-card-raw-after');
            await expect(servedDuringFailure).toBeVisible();
            expect(gatewayScheme(await rawCard(servedDuringFailure)).oauth2MetadataUrl).toBe(METADATA_URL);

            await expectNoSecretIn(tab, world);
            await attachCriterion(TICKET, 4, 'Failed card fetch with its cause and the served card', tab);
        } finally {
            await setAgentRefusing(http, false);
        }

        const recovered = await readPreviewBody(await refresh(page), world);
        expect(recovered.fetch).toMatchObject({status: 'ok', cause: null, http_status: null});
        expect(recovered.before).not.toBeNull();
        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('OK');
        await expect(page.getByTestId('agent-card-fetch-cause')).toHaveCount(0);
        await expect(page.getByTestId('agent-card-failed')).toHaveCount(0);
        await expect(page.getByTestId('agent-card-refresh-status')).toHaveText('Card refreshed. The card fetch is OK.');
        await expect(row(page, 'signin')).toHaveAttribute('data-status', 'changed');
        await expectNoSecretIn(tab, world);
        expect((await http.get(CARD_URL, {failOnStatusCode: false})).status()).toBe(200);
    });

    test('a surface on the same agent with no Target Authentication shows that the agent needs a token', async ({page}) => {
        ticket('FTL-30895');
        await resetAgentLog(http);
        const created = await api.post<Entity>('/api/v1/surfaces', {
            name: NO_AUTH_SURFACE,
            status: 'active',
            access_point: {listen_address: env.accessPointOrigin, route: NO_AUTH_ROUTE, protocol: 'a2a'},
            target: {endpoint: env.agentUrl},
        });
        expect(created.status, 'creating the surface without Target Authentication').toBe(201);
        noAuthSurface = created.body;

        await openSurface(page, surfaceIdOf(noAuthSurface));
        await selectNode(page, 'target');
        const fetchLine = page.getByTestId('managed-agent-card-fetch-status');
        await expect(fetchLine).toContainText('Card fetch: failing');
        await expect(fetchLine).toContainText('Needs a token — HTTP 401');

        const read = page.waitForResponse(response => isCardRoute(response, '', 'GET'));
        await page.getByTestId('managed-agent-card-fetch-link').click();
        const body = await readPreviewBody(await read, world);
        expect(body.fetch).toMatchObject({status: 'failed', cause: 'needs_token', http_status: 401});
        expect(body.auth).toEqual({kind: 'none', result: 'not_configured', provider_name: null, token_expires_at: null, failure: null});
        expect(body.before).toBeNull();
        expect(body.after).toBeNull();

        await expect(page.getByTestId('agent-card-fetch-status')).toHaveText('Failing');
        const cause = page.getByTestId('agent-card-fetch-cause');
        await expect(cause).toHaveAttribute('data-cause', 'needs_token');
        await expect(cause).toHaveText('Needs a token — HTTP 401');
        await expect(page.getByTestId('agent-card-auth')).toHaveText('No Target Authentication');
        await expect(page.getByTestId('agent-card-failed-cause')).toHaveText(
            'The agent asked for a token (HTTP 401) and the gateway sent none. Set Target Authentication on the Managed Agent.'
        );
        await expect(page.getByTestId('agent-card-raw-after')).toHaveCount(0);
        await expectNoSecretIn(page.getByTestId('agent-card-tab'), world);

        const log = await agentLog(http);
        expect(log.some(entry => entry.method === 'GET' && !entry.authenticated && entry.status === 401)).toBe(true);
    });

    test('no token, client secret or Authorization value reaches the tab, its raw JSON or the preview responses', async ({page}) => {
        ticket('FTL-30895', 'FTL-30888', 'FTL-30889');
        await openSurface(page, surfaceIdOf(surface));
        const body = await openTab(page, world);
        expect(body.auth.kind).toBe('credential_provider');
        expect(body.auth.result).toBe('sent');

        await showRawJson(page);
        await expect(page.getByTestId('agent-card-raw-before')).toBeVisible();
        await expect(page.getByTestId('agent-card-raw-after')).toBeVisible();
        const tab = page.getByTestId('agent-card-tab');
        await expectNoSecretIn(tab, world);
        await expect(tab).not.toContainText('Authorization');
        await expect(tab).not.toContainText(/Bearer\s+\S/);
        await attachCriterion(TICKET, 6, 'No secret in the Agent Cards tab', tab);
    });
});
