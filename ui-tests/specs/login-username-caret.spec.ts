import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test('editing the middle of the login username keeps the caret where it was edited', async ({page}) => {
    await page.route('**/api/auth/check', route =>
        route.fulfill({status: 401, contentType: 'application/json', body: '{}'}),
    );
    await page.route('**/api/v1/auth/mode', route =>
        route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({mode: 'passkey'})}),
    );

    await page.goto(BASE_URL);

    const username = page.getByTestId('login-username');
    const caret = () => username.evaluate((el: HTMLInputElement) => el.selectionStart);

    await username.fill('alice@example.com');
    await username.press('Home');
    for (let i = 0; i < 'alice'.length; i++) {
        await username.press('ArrowRight');
    }

    await username.pressSequentially('XY');
    await expect(username).toHaveValue('aliceXY@example.com');
    expect(await caret()).toBe('aliceXY'.length);

    await username.press('Backspace');
    await expect(username).toHaveValue('aliceX@example.com');
    expect(await caret()).toBe('aliceX'.length);

    await username.press('Delete');
    await expect(username).toHaveValue('aliceXexample.com');
    expect(await caret()).toBe('aliceX'.length);
});
