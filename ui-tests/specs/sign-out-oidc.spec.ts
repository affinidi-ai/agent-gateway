import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const PROVIDER_SIGN_OUT = 'https://idp.example.test/logout?id_token_hint=hint&state=s';

async function answerSignOut(page: Page, answer: Record<string, unknown>): Promise<() => number> {
    let requests = 0;
    await page.route('**/api/auth/logout', route => {
        requests += 1;
        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(answer),
        });
    });
    return () => requests;
}

async function signOutFromTopbar(page: Page): Promise<void> {
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.getByTestId('page-dashboard')).toBeVisible();
    await page.getByTestId('topbar-user-menu-button').click();
    await page.getByRole('button', {name: 'Sign Out'}).click();
}

test('signing out of the dashboard sends the browser to the provider to sign out there too', async ({page}) => {
    const signOutRequests = await answerSignOut(page, {end_session_url: PROVIDER_SIGN_OUT});
    await page.route('https://idp.example.test/**', route =>
        route.fulfill({status: 200, contentType: 'text/html', body: '<p>Signed out at the provider</p>'}),
    );

    await signOutFromTopbar(page);

    await page.waitForURL(PROVIDER_SIGN_OUT);
    await expect(page.getByText('Signed out at the provider')).toBeVisible();
    expect(signOutRequests()).toBe(1);
});

test('signing out of the dashboard without a provider sign-out shows the sign-in page', async ({page}) => {
    const signOutRequests = await answerSignOut(page, {});

    await signOutFromTopbar(page);

    await expect(page.getByTestId('page-login')).toBeVisible();
    await expect(page.getByTestId('page-dashboard')).toHaveCount(0);
    expect(page.url().startsWith(BASE_URL)).toBe(true);
    expect(signOutRequests()).toBe(1);
});

test('the login page says the person has signed out when the provider sends them back', async ({page}) => {
    await page.route('**/api/auth/check', route =>
        route.fulfill({status: 401, contentType: 'application/json', body: '{}'}),
    );
    await page.route('**/api/v1/auth/mode', route =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({mode: 'oidc', label: 'Example Directory'}),
        }),
    );

    await page.goto(`${BASE_URL}/?signed_out=1&state=s`);

    await expect(page.getByTestId('login-signed-out-notice')).toHaveText('You have signed out.');
    await expect(page.getByTestId('login-sso-button')).toHaveText('Sign in with Example Directory');
    await expect(page).toHaveURL(`${BASE_URL}/`);
});
