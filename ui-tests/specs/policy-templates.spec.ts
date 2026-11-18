/**
 * Policy template tests
 *
 * Asserts the create policy page's Start from gallery, the templates column's Add rules
 * panel and the Rules view, and on a saved policy the Template examples card and Save as
 * template.
 */

import type {Page} from '@playwright/test';
import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

/** Picks a Start from card, opening Show all first since the gallery starts with six cards. */
async function pickCard(page: Page, key: string) {
    await page.getByTestId('policy-template-gallery-show-all').click();
    await page.getByTestId(`policy-template-card-${key}`).click();
}

test.describe('Policy templates on the create policy page', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/policy-definitions/new?type=agent_surface`);
        await expect(page.getByTestId('policy-template-gallery')).toBeVisible();
    });

    test('starts from Deny by default on the Rules view', async ({page}) => {
        await expect(page.getByTestId('policy-template-card-deny-by-default')).toHaveAttribute('aria-pressed', 'true');
        await expect(page.getByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
        await captureFullPage(page, 'policy-templates-start');
    });

    test('shows a template in place and fills the form when it is used', async ({page}) => {
        await pickCard(page, 'allow-http-methods');
        const detail = page.getByTestId('policy-template-gallery-detail');
        await expect(detail).toContainText('Allow listed HTTP methods');
        await detail.getByTestId('policy-template-gallery-example-input-0').click();
        await expect(detail.getByTestId('policy-template-gallery-example-input-0-json')).toContainText('"method"');
        await captureFullPage(page, 'policy-templates-gallery-detail');

        await detail.getByTestId('policy-template-gallery-use-button').click();

        await expect(page.getByTestId('policy-template-gallery-summary')).toContainText(
            'Started from Allow listed HTTP methods'
        );
        await expect(page.getByPlaceholder('e.g. Require Authentication')).toHaveValue('Allow listed HTTP methods');
    });

    test('moves the focus to Change once a template is used', async ({page}) => {
        await pickCard(page, 'allow-http-methods');
        await page.getByTestId('policy-template-gallery-detail').getByTestId('policy-template-gallery-use-button').click();

        await expect(page.getByTestId('policy-template-gallery-summary')).toBeVisible();
        await expect(page.getByTestId('policy-template-gallery-change-button')).toBeFocused();
    });

    test('adds rules from a template and removes them again', async ({page}) => {
        const column = page.getByTestId('policy-templates-column');
        await column.getByTestId('policy-templates-row-allow-http-methods:agent_surface').click();
        await column.getByTestId('policy-templates-insert-rules-button').click();

        const group = page.getByTestId('policy-rules-group-0');
        await expect(group).toContainText('From template Allow listed HTTP methods');
        await expect(page.getByTestId('policy-rules-allow-default-warning')).toHaveCount(0);
        await captureFullPage(page, 'policy-templates-rules-added');

        await page.getByTestId('policy-rules-group-0-remove-button').click();
        await expect(page.getByTestId('policy-rules-empty')).toBeVisible();
    });

    test('keeps the editor width when a template is shown', async ({page}) => {
        const editor = page.getByTestId('policy-editor-section');
        const before = await editor.boundingBox();

        await pickCard(page, 'allow-http-methods');
        await page.getByTestId('policy-templates-column').getByTestId('policy-templates-row-allow-http-methods:agent_surface').click();

        const after = await editor.boundingBox();
        expect(before).not.toBeNull();
        expect(after).not.toBeNull();
        expect(after!.width).toBe(before!.width);
    });
});

async function deletePolicy(page: Page, policyId: string) {
    const token = await page.evaluate(() => sessionStorage.getItem('session_token'));
    await page.request.delete(`${BASE_URL}/api/v1/policy-definitions/${encodeURIComponent(policyId)}`, {
        headers: {Authorization: `Bearer ${token}`},
    });
}

test.describe('Policy templates on a saved policy', () => {
    test('checks added rules against the template examples and saves the policy as a template', async ({page}) => {
        const suffix = `${Date.now()}-${test.info().workerIndex}`;
        const policyName = `UI test policy ${suffix}`;
        const templateName = `UI test template ${suffix}`;

        await page.goto(`${BASE_URL}/policy-definitions/new?type=agent_surface`);
        await pickCard(page, 'allow-http-methods');
        await page.getByTestId('policy-template-gallery-detail').getByTestId('policy-template-gallery-use-button').click();
        await page.getByTestId('policy-definition-name-input').fill(policyName);
        const save = page.getByTestId('policy-definition-editor-save-button');
        await expect(save).toBeEnabled();
        await save.click();

        await page.waitForURL(/\/policy-definitions\/[0-9a-f-]{36}$/);
        const policyId = page.url().split('/').pop()!;
        try {
            const saveAs = page.getByTestId('policy-templates-save-as-button');
            await expect(saveAs).toBeEnabled();

            const column = page.getByTestId('policy-templates-column');
            await column.getByTestId('policy-templates-row-require-authentication:agent_surface').click();
            await column.getByTestId('policy-templates-insert-rules-button').click();

            const examples = page.getByTestId('policy-template-examples-card');
            await expect(examples).toBeVisible();
            await expect(examples).toContainText('Require authenticated caller');
            await expect(examples.getByTestId('policy-template-example-row-2')).toBeVisible();
            await captureFullPage(page, 'policy-templates-examples-card');

            await expect(saveAs).toBeDisabled();
            await expect(save).toBeEnabled();
            await save.click();
            await expect(saveAs).toBeEnabled();
            await saveAs.click();

            const savePanel = column.getByTestId('policy-templates-save-panel');
            await savePanel.getByTestId('policy-templates-save-name-input').fill(templateName);
            await savePanel.getByTestId('policy-templates-save-button').click();
            await expect(savePanel).toHaveCount(0);

            await column.getByTestId('policy-templates-tab-organization').click();
            await expect(column.getByTestId('policy-templates-organization-empty')).toHaveCount(0);
            const orgRow = column.locator('[data-testid^="policy-templates-row-org:"]');
            await expect(orgRow).toHaveCount(1);
            await expect(orgRow).toContainText(templateName);
            await captureFullPage(page, 'policy-templates-organization-tab');
        } finally {
            await deletePolicy(page, policyId);
        }
    });
});
