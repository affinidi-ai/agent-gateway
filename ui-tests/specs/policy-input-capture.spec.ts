/**
 * Policy input capture tests
 *
 * Asserts the Capture view's Policy Input card: listening is live over the
 * dashboard WebSocket, a captured evaluation shows its policy, decision and
 * input, stopping ends it, a surface with no policy says so, and with the
 * policy_input_capture feature flag off the card says capture is turned off.
 */

import type {APIRequestContext, Page, WebSocket} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {setSystemFeatureFlag, withFeatureFlag} from '../helpers/featureFlags';

const FLAG = 'policy_input_capture';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const SURFACE_ID = 'ui-test-policy-input-capture';

const SURFACE_FIXTURE = {
    surface_id: SURFACE_ID,
    name: 'Policy input capture fixture',
    description: 'Playwright fixture',
    status: 'active',
    tags: [],
    access_point: {
        listen_address: '0.0.0.0:0',
        route: '/ui-test-policy-input-capture',
        protocol: 'a2a',
        public: true,
        publish_to_did_document: false,
        terminate_trace_id: false,
    },
    target: {
        endpoint: 'http://localhost:9999',
        mcp_tool_policies_enabled: false,
        identity_injection: {inject_vp: false},
        mpp_auto_pay: false,
    },
};

async function openCaptureView(page: Page) {
    await page.route(new RegExp(`/api/v1/surfaces/${SURFACE_ID}(\\?.*)?$`), async (route) => {
        if (route.request().method() === 'GET') {
            await route.fulfill({json: SURFACE_FIXTURE});
        } else {
            await route.fallback();
        }
    });
    await page.goto(`${BASE_URL}/surfaces/${SURFACE_ID}`);
    await page.getByTestId('surface-view-monitoring').click();
    await page.getByTitle('Live payload and policy input capture for this surface').click();
    await expect(page.getByTestId('policy-input-capture-card')).toBeVisible();
}

/** Deliver a capture as the dashboard WebSocket hands it to the page. */
async function capture(page: Page, detail: Record<string, unknown>) {
    await page.evaluate(
        ([surfaceId, extra]) => {
            window.dispatchEvent(
                new CustomEvent('ws-message', {
                    detail: {
                        type: 'policy_input_captured',
                        config_id: surfaceId,
                        timestamp: new Date().toISOString(),
                        plane: 'surface',
                        engine: surfaceId,
                        slot: 'target',
                        policies: [{id: 'allow-partners', name: 'Allow partners', version: 2}],
                        decision: 'deny',
                        reason: 'only partners may call',
                        input: {a2a: {text: 'hello policy'}},
                        ...extra,
                    },
                }),
            );
        },
        [SURFACE_ID, detail] as const,
    );
}

/** Whether a dashboard WebSocket frame is the gateway's answer that it listens to the surface. */
function isListeningAnswer(payload: string | Buffer): boolean {
    try {
        const message = JSON.parse(typeof payload === 'string' ? payload : payload.toString());
        return (
            message?.type === 'policy_input_capture' &&
            message.surface_id === SURFACE_ID &&
            message.listening === true
        );
    } catch {
        return false;
    }
}

// The gateway refuses to listen while the flag is off, so this live listen needs the
// appliance's stored flag on; it is put back as it was afterwards.
test.describe('Policy input capture, listening', () => {
    let restoreFlags: (() => Promise<void>) | undefined;
    let flagContext: APIRequestContext | undefined;

    test.beforeAll(async ({playwright}) => {
        flagContext = await playwright.request.newContext();
        restoreFlags = await setSystemFeatureFlag(flagContext, BASE_URL, FLAG);
    });

    test.afterAll(async () => {
        await restoreFlags?.();
        await flagContext?.dispose();
    });

    test('listens live, shows a captured evaluation and stops', async ({page}) => {
        // The dashboard socket opens when the page loads, before the Capture view is shown.
        const dashboardSocket: Promise<WebSocket> = page.waitForEvent('websocket', (ws) =>
            new URL(ws.url()).pathname.endsWith('/api/ws'),
        );
        await openCaptureView(page);
        const socket = await dashboardSocket;
        const listen = page.getByTestId('policy-input-capture-listen');
        await expect(listen).toHaveText(/Listen to policy input/);

        const listeningAnswer = socket.waitForEvent('framereceived', {
            predicate: ({payload}) => isListeningAnswer(payload),
        });
        await listen.click();
        await listeningAnswer;
        await expect(page.getByTestId('policy-input-capture-listening')).toBeVisible();
        await expect(listen).toHaveText(/Stop listening/);
        await expect(page.getByTestId('policy-input-capture-error')).toHaveCount(0);

        await capture(page, {});
        const row = page.getByTestId('policy-input-capture-row');
        await expect(row).toHaveCount(1);
        await expect(page.getByTestId('policy-input-capture-policy')).toHaveText(/Allow partners v2/);
        await expect(page.getByTestId('policy-input-capture-reason')).toHaveText('only partners may call');

        await page.getByTestId('policy-input-capture-toggle').click();
        await expect(page.getByTestId('policy-input-capture-input')).toContainText('hello policy');

        await listen.click();
        await expect(page.getByTestId('policy-input-capture-listening')).toHaveCount(0);
        await expect(listen).toHaveText(/Listen to policy input/);
    });
});

test.describe('Policy input capture', () => {
    test('says a surface with no policy has nothing to capture', async ({page}) => {
        await withFeatureFlag(page, FLAG);
        await openCaptureView(page);

        await expect(page.getByTestId('policy-input-capture-no-policy')).toContainText(
            'This surface has no policy yet',
        );
        await expect(page.getByTestId('policy-input-capture-empty')).toContainText(
            'only requests served by the node this dashboard is connected to show',
        );
    });

    test('says capture is turned off and offers no Listen button while the flag is off', async ({page}) => {
        await withFeatureFlag(page, FLAG, false);
        await openCaptureView(page);

        await expect(page.getByTestId('policy-input-capture-off')).toContainText(
            'Policy input capture is turned off on this gateway',
        );
        await expect(page.getByTestId('policy-input-capture-off')).toContainText(
            'Settings › Admin › Feature Flags',
        );
        await expect(page.getByTestId('policy-input-capture-listen')).toHaveCount(0);
        await expect(page.getByTestId('policy-input-capture-empty')).toHaveCount(0);
    });
});
