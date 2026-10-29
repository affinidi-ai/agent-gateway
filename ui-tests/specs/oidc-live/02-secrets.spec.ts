/**
 * Secrets through the dashboard secret editor
 *
 * The hop 2 client id and secret, the assertion signing key and a client credentials pair are
 * created in the editor. After saving, no page and no API response shows a stored value again.
 */

import {GatewayApi} from '../../helpers/gateway-api';
import {expect, test} from '../../helpers/fixtures';
import {Entity, listEntities, secretLabels, secretValues} from '../../helpers/oidc-live/gateway-state';
import {names} from '../../helpers/oidc-live/names';
import {createSecretInDashboard, fillSecret} from '../../helpers/oidc-live/ui';
import {loadWorld, World} from '../../helpers/oidc-live/world';

function confidentialValues(values: Record<string, string>): string[] {
    return [names.secrets.hop2ClientSecret, names.secrets.ccClientSecret].map(id => values[id]).concat(
        (values[names.secrets.signingKey].split('\n')[1] ?? '')
    );
}

test.describe('Secrets', () => {
    test.describe.configure({mode: 'serial'});

    let api: GatewayApi;
    let world: World;

    test.beforeAll(async () => {
        api = await GatewayApi.connect();
        world = loadWorld();
        for (const secret of await listEntities(api, '/api/v1/secrets/')) {
            if (secret.secret_id?.startsWith('oidc-e2e')) await api.delete(`/api/v1/secrets/${secret.id}`);
        }
    });

    test.afterAll(async () => {
        await api.dispose();
    });

    test('creates the client secrets and the signing key in the editor', async ({page}) => {
        const values = secretValues(world);
        for (const secretId of Object.keys(values)) {
            await createSecretInDashboard(page, {
                name: secretLabels[secretId],
                id: secretId,
                type: secretId === names.secrets.signingKey ? 'Certificate' : 'General',
                value: values[secretId],
            });
        }
        const stored = await listEntities(api, '/api/v1/secrets/');
        for (const secretId of Object.keys(values)) {
            expect(stored.some(secret => secret.secret_id === secretId), `${secretId} is stored`).toBe(true);
        }
    });

    test('lists the secrets by name and never shows a value', async ({page}) => {
        await page.goto('/secrets');
        const values = secretValues(world);
        for (const secretId of Object.keys(values)) {
            await expect(page.getByText(secretLabels[secretId], {exact: true}).first()).toBeVisible();
        }
        const text = await page.locator('body').innerText();
        for (const value of confidentialValues(values)) {
            expect(text.includes(value), 'the list shows a stored value').toBe(false);
        }
    });

    test('opens a stored secret with the value hidden and disabled', async ({page}) => {
        const stored = (await listEntities(api, '/api/v1/secrets/')).find(
            secret => secret.secret_id === names.secrets.hop2ClientSecret
        ) as Entity;
        await page.goto(`/secrets/${stored.id}`);

        const input = page.getByTestId('secret-value-input');
        await expect(input).toBeDisabled();
        await expect(input).toHaveAttribute('placeholder', /Stored value is hidden/);
        await expect(input).toHaveValue('');
        await expect(page.getByTestId('secret-value-reveal-checkbox')).toHaveCount(0);
        await expect(page.getByTestId('secret-save-button')).toBeDisabled();
        expect((await page.content()).includes(world.hop2.secret), 'the editor shows the stored value').toBe(false);
    });

    test('the API never returns a stored value, and the editor hides it again after an update', async ({page}) => {
        const values = secretValues(world);
        const listed = JSON.stringify((await api.get('/api/v1/secrets/')).body);
        for (const value of confidentialValues(values)) {
            expect(listed.includes(value), 'the list API returns a stored value').toBe(false);
        }

        const stored = (await listEntities(api, '/api/v1/secrets/')).find(
            secret => secret.secret_id === names.secrets.ccClientSecret
        ) as Entity;
        const one = JSON.stringify((await api.get(`/api/v1/secrets/${stored.id}`)).body);
        expect(one.includes(world.good.secret), 'the secret API returns the stored value').toBe(false);

        await page.goto(`/secrets/${stored.id}`);
        await page.locator('label[for=updateValueCheckbox]').click();
        const input = page.getByTestId('secret-value-input');
        await expect(input).toBeEnabled();
        await fillSecret(input, world.good.secret);
        await page.getByTestId('secret-save-button').click();

        await expect(input).toBeDisabled();
        await expect(input).toHaveAttribute('placeholder', /Stored value is hidden/);
        await expect(input).toHaveValue('');
        expect((await page.content()).includes(world.good.secret), 'the editor shows the saved value').toBe(false);
    });
});
