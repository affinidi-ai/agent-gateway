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

        const title = await page.getByTestId('policy-instructions-title').boundingBox();
        const chevron = await page.getByTestId('policy-instructions-chevron').boundingBox();
        const header = await toggle.boundingBox();
        expect(title).not.toBeNull();
        expect(chevron).not.toBeNull();
        expect(header).not.toBeNull();

        const titleEnd = title!.x + title!.width;
        const emptyX = (titleEnd + chevron!.x) / 2;
        expect(chevron!.x - titleEnd, 'the header must have empty space between the title and the arrow').toBeGreaterThan(40);
        await page.mouse.click(emptyX, header!.y + header!.height / 2);

        await expect(toggle).toHaveAttribute('aria-expanded', 'false');
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
    });

    test('still toggles from the chevron hint', async ({page}) => {
        const chevron = page.getByTestId('policy-instructions-chevron');
        await chevron.click();
        await expect(page.getByTestId('policy-instructions-body')).toBeVisible();
        await chevron.click();
        await expect(page.getByTestId('policy-instructions-body')).toBeHidden();
    });

    test('keeps the title a heading that holds the toggle button', async ({page}) => {
        const heading = page.getByRole('heading', {name: 'Policy Instructions & Examples'});
        await expect(heading).toBeVisible();
        await expect(heading.getByRole('button')).toHaveAttribute('aria-expanded', 'false');
        await expect(heading.getByRole('button')).toHaveAttribute('aria-controls', 'policyDefInstructions');
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
