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

/** The picked card's detail, shown in the templates column. */
const galleryDetail = (page: Page) =>
    page.getByTestId('policy-templates-column').getByTestId('policy-template-gallery-detail');

/** Uses Deny by default, which shows the Details and Policy sections. */
async function useDenyByDefault(page: Page) {
    await page.getByTestId('policy-template-card-deny-by-default').click();
    await galleryDetail(page).getByTestId('policy-template-gallery-use-button').click();
}

test.describe('Policy templates on the create policy page', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/policy-definitions/new?type=agent_surface`);
        await expect(page.getByTestId('policy-template-gallery')).toBeVisible();
    });

    test('shows only Start from until a template is used', async ({page}) => {
        await expect(page.getByTestId('policy-template-card-deny-by-default')).toHaveAttribute('aria-pressed', 'false');
        await expect(page.getByTestId('policy-template-gallery-detail-empty')).toBeVisible();
        await expect(page.getByTestId('policy-editor-section')).toHaveCount(0);
        await captureFullPage(page, 'policy-templates-start');

        await useDenyByDefault(page);
        await expect(page.getByTestId('policy-view-rules')).toHaveAttribute('aria-pressed', 'true');
        await expect(page.getByTestId('policy-templates-column').getByTestId('policy-templates-panel')).toBeVisible();
    });

    test('shows a template in the templates column and fills the form when it is used', async ({page}) => {
        await pickCard(page, 'allow-http-methods');
        const detail = galleryDetail(page);
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
        await galleryDetail(page).getByTestId('policy-template-gallery-use-button').click();

        await expect(page.getByTestId('policy-template-gallery-summary')).toBeVisible();
        await expect(page.getByTestId('policy-template-gallery-change-button')).toBeFocused();
    });

    test('adds rules from a template and removes them again', async ({page}) => {
        await useDenyByDefault(page);
        const column = page.getByTestId('policy-templates-column');
        await column.getByTestId('policy-templates-row-allow-http-methods:agent_surface').click();
        await column.getByTestId('policy-templates-insert-rules-button').click();

        const group = page.getByTestId('policy-rules-group-0');
        await expect(group).toContainText('From template: Allow listed HTTP methods');
        await expect(page.getByTestId('policy-rules-allow-default-warning')).toHaveCount(0);
        await expect(page.getByTestId('policy-rules-summary')).toHaveText(
            'This policy allows a request when its allow rule matches. Otherwise: DENY'
        );
        await expect(page.getByTestId('policy-rules-summary-otherwise')).toHaveText('DENY');
        await expect(page.getByTestId('policy-rules-group-0-rule-0-kind')).toHaveText('Allows');
        await captureFullPage(page, 'policy-templates-rules-added');

        await page.getByTestId('policy-rules-group-0-remove-button').click();
        await expect(page.getByTestId('policy-rules-empty')).toBeVisible();
    });

    test('states what the policy decides and marks the rules allow reads', async ({page}) => {
        await page.setViewportSize({width: 1366, height: 768});
        await pickCard(page, 'business-hours-access-window');
        await galleryDetail(page).getByTestId('policy-template-gallery-use-button').click();

        await expect(page.getByTestId('policy-rules-summary')).toHaveText(
            'This policy allows a request when its allow rule matches. Otherwise: DENY'
        );
        await expect(page.getByTestId('policy-rules-group-0-rule-0-kind')).toHaveText('Allows');
        const helper = page.getByTestId('policy-rules-group-0-rule-1-kind');
        await expect(helper).toHaveText('Used by allow');
        await expect(helper).toHaveAttribute(
            'title',
            'allow reads this rule, directly or through other rules, so it changes what the policy decides'
        );
        await captureFullPage(page, 'policy-templates-rules-summary-laptop');

        await page.getByTestId('topbar-theme-button').click();
        await expect.poll(() => page.evaluate(() => document.body.classList.contains('dark-theme'))).toBe(true);
        await page.evaluate(() =>
            Promise.all(
                document
                    .getAnimations()
                    .filter(a => a instanceof CSSTransition)
                    .map(a => a.finished.catch(() => undefined))
            )
        );
        await captureFullPage(page, 'policy-templates-rules-summary-laptop-dark');
    });

    test('keeps the editor width when a template is shown', async ({page}) => {
        await useDenyByDefault(page);
        const editor = page.getByTestId('policy-editor-section');
        const before = await editor.boundingBox();

        await page.getByTestId('policy-template-gallery-change-button').click();
        await pickCard(page, 'allow-http-methods');
        await expect(galleryDetail(page)).toContainText('Allow listed HTTP methods');

        const after = await editor.boundingBox();
        expect(before).not.toBeNull();
        expect(after).not.toBeNull();
        expect(after!.width).toBe(before!.width);
    });

    test('creates a custom policy from the button under the templates', async ({page}) => {
        await page.getByTestId('policy-template-gallery-create-custom-button').click();
        await expect(page.getByTestId('policy-template-gallery-summary')).toContainText('Started from Custom policy');
        await expect(page.getByTestId('policy-editor-section')).toBeVisible();
    });

    test('marks a template for surfaces only with a note', async ({page}) => {
        await pickCard(page, 'require-trust-registry-recognition');
        await expect(
            page.getByTestId('policy-template-card-require-trust-registry-recognition')
                .getByTestId('policy-template-card-scope')
        ).toHaveText('Agent surface only');
    });
});

test.describe('Policy templates on a new Gateway policy', () => {
    test('lists only templates for gateways, with no filters', async ({page}) => {
        await page.goto(`${BASE_URL}/policy-definitions/new?type=gateway`);
        await expect(page.getByTestId('policy-template-card-deny-by-default')).toBeVisible();
        await expect(page.getByTestId('policy-template-card-require-trust-registry-recognition')).toHaveCount(0);
        await expect(page.getByTestId('policy-template-card-scope')).toHaveCount(0);
        await expect(page.getByTestId('policy-template-gallery-search-input')).toHaveCount(0);
        await captureFullPage(page, 'policy-templates-gateway-start');
    });
});

async function deletePolicy(page: Page, policyId: string) {
    const token = await page.evaluate(() => sessionStorage.getItem('session_token'));
    await page.request.delete(`${BASE_URL}/api/v1/policy-definitions/${encodeURIComponent(policyId)}`, {
        headers: {Authorization: `Bearer ${token}`},
    });
}

test.describe('Policy templates on a saved policy', () => {
    test('checks added rules against the template examples', async ({page}) => {
        const suffix = `${Date.now()}-${test.info().workerIndex}`;
        const policyName = `UI test policy ${suffix}`;

        await page.goto(`${BASE_URL}/policy-definitions/new?type=agent_surface`);
        await pickCard(page, 'allow-http-methods');
        await galleryDetail(page).getByTestId('policy-template-gallery-use-button').click();
        await page.getByTestId('policy-definition-name-input').fill(policyName);
        const save = page.getByTestId('policy-definition-editor-save-button');
        await expect(save).toBeEnabled();
        await save.click();

        await page.waitForURL(/\/policy-definitions\/[0-9a-f-]{36}$/);
        const policyId = page.url().split('/').pop()!;
        try {
            const column = page.getByTestId('policy-templates-column');
            await column.getByTestId('policy-templates-row-require-authentication:agent_surface').click();
            await column.getByTestId('policy-templates-insert-rules-button').click();

            const examples = page.getByTestId('policy-template-examples-card');
            await expect(examples).toBeVisible();
            await expect(examples).toContainText('Require authenticated caller');
            await expect(examples.getByTestId('policy-template-example-row-2')).toBeVisible();
            await captureFullPage(page, 'policy-templates-examples-card');
        } finally {
            await deletePolicy(page, policyId);
        }
    });
});
