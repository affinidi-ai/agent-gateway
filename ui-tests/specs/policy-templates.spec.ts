/**
 * Policy template tests
 *
 * Asserts the create policy page's Start from gallery, the templates column's Add rules
 * panel and the Rules view, without saving a policy.
 */

import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

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
        await page.getByTestId('policy-template-card-allow-http-methods').click();
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

        await page.getByTestId('policy-template-card-allow-http-methods').click();
        await page.getByTestId('policy-templates-column').getByTestId('policy-templates-row-allow-http-methods:agent_surface').click();

        const after = await editor.boundingBox();
        expect(before).not.toBeNull();
        expect(after).not.toBeNull();
        expect(after!.width).toBe(before!.width);
    });
});
