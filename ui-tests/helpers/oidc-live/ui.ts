import {Locator, Page, expect} from '@playwright/test';

/**
 * Types a secret into a field without `locator.fill`, whose report step is titled with the
 * typed value. The value travels as an evaluate argument, which the report does not record.
 */
export async function fillSecret(field: Locator, value: string): Promise<void> {
    await field.evaluate((element, secret) => {
        const input = element as HTMLInputElement | HTMLTextAreaElement;
        const prototype = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(input, secret);
        input.dispatchEvent(new Event('input', {bubbles: true}));
    }, value);
    await expect(field).not.toHaveValue('');
}

export async function createSecretInDashboard(
    page: Page,
    secret: {name: string; id: string; type: string; value: string}
): Promise<void> {
    await page.goto('/secrets/new');
    await page.locator('#name').fill(secret.name);
    await page.locator('#secret_id').fill(secret.id);
    await page.locator('#secret_type').selectOption(secret.type);
    await fillSecret(page.getByTestId('secret-value-input'), secret.value);
    const saved = page.waitForResponse(
        response => response.url().endsWith('/api/v1/secrets/new') && response.request().method() === 'POST'
    );
    await page.getByTestId('secret-save-button').click();
    expect((await saved).status()).toBe(201);
    await expect(page).toHaveURL(/\/secrets$/);
}
