import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

const applicableTerms = {
    terms: [
        {
            terms_type: 'affinidi',
            document_id: 'affinidi-terms',
            version_id: 'affinidi-v1',
            version: '1',
            title: 'Affinidi Terms',
            url: 'https://example.com/terms',
        },
    ],
};

test('registration remains blocked until every applicable term is accepted', async ({page}) => {
    await page.route('**/api/auth/check', route =>
        route.fulfill({status: 401, contentType: 'application/json', body: '{}'}),
    );
    await page.route('**/api/v1/auth/mode', route =>
        route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({mode: 'passkey'})}),
    );
    await page.route('**/api/v1/terms/applicable', route =>
        route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(applicableTerms)}),
    );

    await page.goto(BASE_URL);
    await page.getByTestId('login-mode-toggle').click();

    const submit = page.getByTestId('login-register-button');
    await expect(page.getByTestId('registration-terms-affinidi')).toBeVisible();
    await expect(page.getByTestId('registration-terms-affinidi-link')).toHaveAttribute(
        'href',
        'https://example.com/terms',
    );
    await page.getByTestId('login-username').fill('alice');
    await expect(submit).toBeDisabled();
    await page.getByTestId('registration-terms-affinidi').check();
    await expect(submit).toBeEnabled();
});
