import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test('in OIDC mode the login page names the provider and starts the sign-in at the gateway', async ({page}) => {
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
    let started: string | null = null;
    await page.route('**/api/oidc/login**', route => {
        started = route.request().url();
        return route.fulfill({status: 200, contentType: 'text/html', body: '<p>provider</p>'});
    });

    await page.goto(`${BASE_URL}/?next=${encodeURIComponent('/access-tokens/new')}`);

    const button = page.getByTestId('login-sso-button');
    await expect(button).toHaveText('Sign in with Example Directory');
    await expect(page.getByTestId('login-username')).toHaveCount(0);

    await button.click();

    await expect.poll(() => started).not.toBeNull();
    const url = new URL(started as unknown as string);
    expect(url.pathname).toBe('/api/oidc/login');
    expect(url.searchParams.get('next')).toBe('/access-tokens/new');
});
