import {Page} from '@playwright/test';

const LOOPBACK_HTTPS = /https:\/\/(127\.0\.0\.1:\d+)/g;

/**
 * Rewrites `https://127.0.0.1:<port>` to `http://127.0.0.1:<port>` in the body of the requests that
 * match `urlPattern` before they reach the gateway.
 *
 * Hydra and the mock agent listen on plain http, because the gateway trusts only the system
 * certificate store and the suite changes no system trust. The dashboard accepts only https for an
 * issuer and for a credential provider's Target. The bridge lets the dashboard do its work on an
 * https looking address while the real gateway talks to the real http service. Nothing else about
 * the request or the response is touched.
 */
export async function bridgeLoopbackScheme(page: Page, urlPattern: string | RegExp): Promise<void> {
    await page.route(urlPattern, async route => {
        const request = route.request();
        const body = request.postData();
        if (body === null || request.method() === 'GET') {
            await route.continue();
            return;
        }
        await route.continue({postData: body.replace(LOOPBACK_HTTPS, 'http://$1')});
    });
}

export function asHttpsLooking(url: string): string {
    return url.replace(/^http:\/\//, 'https://');
}
