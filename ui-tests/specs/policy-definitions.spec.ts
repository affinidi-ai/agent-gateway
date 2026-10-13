/**
 * Policy definition editor tests
 *
 * Asserts the "Policy Instructions & Examples" panel on the Create Policy
 * Definition page expands and collapses from anywhere on its header.
 */

import {expect, test} from '../helpers/fixtures';
import {captureFullPage} from '../helpers/screenshots';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test.describe('Policy definition editor — instructions panel', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/policy-definitions/new`);
        await expect(page.getByTestId('policy-instructions-toggle')).toBeVisible();
    });

    test('is collapsed by default', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await expect(toggle).toHaveAttribute('aria-expanded', 'false');
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
        await captureFullPage(page, 'policy-instructions-collapsed');
    });

    test('expands when the title text is clicked', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await toggle.getByText('Policy Instructions & Examples').click();

        await expect(toggle).toHaveAttribute('aria-expanded', 'true');
        await expect(page.getByTestId('policy-instructions-body')).toBeVisible();
        await expect(page.getByTestId('policy-instructions-body').getByText('Policy Structure')).toBeVisible();
        await captureFullPage(page, 'policy-instructions-expanded-via-title');
    });

    test('collapses again when the empty header area is clicked', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await toggle.getByText('Policy Instructions & Examples').click();
        await expect(page.getByTestId('policy-instructions-body')).toBeVisible();

        const box = await toggle.boundingBox();
        expect(box).not.toBeNull();
        await page.mouse.click(box!.x + box!.width / 2, box!.y + box!.height / 2);

        await expect(toggle).toHaveAttribute('aria-expanded', 'false');
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
    });

    test('still toggles from the chevron hint', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await toggle.locator('.btn').click();
        await expect(page.getByTestId('policy-instructions-body')).toBeVisible();
        await toggle.locator('.btn').click();
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
    });

    test('toggles from the keyboard', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await toggle.focus();
        await page.keyboard.press('Enter');
        await expect(page.getByTestId('policy-instructions-body')).toBeVisible();
        await page.keyboard.press('Space');
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
    });

    test('does not disturb the policy editor below it', async ({page}) => {
        const toggle = page.getByTestId('policy-instructions-toggle');
        await toggle.click();
        const editor = page.getByPlaceholder('...add policy here...');
        await editor.fill('package gateway.policy\ndefault allow = true');
        await expect(editor).toHaveValue('package gateway.policy\ndefault allow = true');
    });
});
