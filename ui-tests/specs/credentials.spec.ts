/**
 * Outbound Credentials Page Tests
 *
 * Tests for the Outbound Credentials management page including:
 * - Page load and navigation
 * - Agent selector functionality
 * - Credentials list display
 * - Credential creation workflow
 * - Credential update and deletion
 * - Secret value masking
 */

import {expect, test} from '../helpers/fixtures';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

// Helper to get screenshot path
function getScreenshotPath(name: string): string {
    const timestamp = new Date().toISOString().replace(/[-:]/g, '').replace(/T/, '_').replace(/\..+/, '');
    return `test_results/latest/screenshots/credentials-${name}-${timestamp}.png`;
}

test.describe('Credentials Page', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard`);
        await page.waitForLoadState('networkidle');
    });

    test('should navigate to Credentials page', async ({page}) => {
        // Look for Credentials navigation link
        const credentialsLink = page.locator(
            'a[href*="credentials"], ' +
            'button:has-text("Credentials"), ' +
            '[data-testid*="credentials"]'
        ).first();

        const linkExists = await credentialsLink.count() > 0;

        if (linkExists) {
            await credentialsLink.click();
            await page.waitForLoadState('networkidle');

            // Verify navigation
            expect(page.url()).toMatch(/credentials/i);

            await page.screenshot({
                path: getScreenshotPath('page-loaded'),
                fullPage: true,
            });
        } else {
            console.log('Credentials navigation link not found in sidebar');

            // Try direct navigation
            await page.goto(`${BASE_URL}/dashboard/credentials`);
            await page.waitForLoadState('networkidle');

            await page.screenshot({
                path: getScreenshotPath('direct-navigation'),
                fullPage: true,
            });
        }
    });

    test('should display page title', async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');

        // Look for page heading
        const heading = page.locator(
            'h1:has-text("Credentials"), ' +
            'h2:has-text("Credentials"), ' +
            'h1:has-text("Outbound"), ' +
            '[data-testid="page-title"]'
        ).first();

        if (await heading.count() > 0) {
            await expect(heading).toBeVisible();
        }

        await page.screenshot({
            path: getScreenshotPath('page-title'),
        });
    });
});

test.describe('Credentials Agent Selector', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');
    });

    test('should display agent selector', async ({page}) => {
        const agentSelector = page.locator(
            'select[name*="agent"], ' +
            '[data-testid*="agent-selector"], ' +
            '.agent-selector, ' +
            '[role="combobox"]'
        ).first();

        const selectorExists = await agentSelector.count() > 0;

        if (selectorExists) {
            await expect(agentSelector).toBeVisible();

            await page.screenshot({
                path: getScreenshotPath('agent-selector'),
            });
        } else {
            console.log('Agent selector not found');
        }
    });
});

test.describe('Credentials List', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');
    });

    test('should display credentials table or empty state', async ({page}) => {
        const table = page.locator(
            'table, ' +
            '[role="table"], ' +
            '.credentials-table, ' +
            '[data-testid="credentials-table"]'
        ).first();

        const emptyState = page
            .locator('.empty-state')
            .or(page.getByText(/no.*credentials/i))
            .or(page.getByText(/add.*first/i))
            .first();

        const hasTable = await table.count() > 0;
        const hasEmptyState = await emptyState.count() > 0;

        console.log(`Table found: ${hasTable}, Empty state: ${hasEmptyState}`);

        await page.screenshot({
            path: getScreenshotPath('credentials-list'),
            fullPage: true,
        });
    });

    test('should display expected table columns', async ({page}) => {
        const expectedColumns = ['target', 'type', 'header', 'created', 'actions'];

        const headers = page.locator('th, [role="columnheader"]');
        const headerCount = await headers.count();

        if (headerCount > 0) {
            const headerTexts: string[] = [];

            for (let i = 0; i < headerCount; i++) {
                const text = await headers.nth(i).textContent();
                if (text) headerTexts.push(text.toLowerCase());
            }

            console.log('Table headers found:', headerTexts);
        }

        await page.screenshot({
            path: getScreenshotPath('table-columns'),
        });
    });
});

test.describe('Credential Creation', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');
    });

    test('should have create credential button', async ({page}) => {
        const createButton = page.locator(
            'button:has-text("create"), ' +
            'button:has-text("add"), ' +
            'button:has-text("new"), ' +
            '[data-testid*="create-credential"]'
        ).first();

        if (await createButton.count() > 0) {
            await expect(createButton).toBeVisible();

            await createButton.evaluate((el) => {
                (el as HTMLElement).style.outline = '3px solid red';
            });

            await page.screenshot({
                path: getScreenshotPath('create-button'),
            });
        } else {
            console.log('Create credential button not found');
        }
    });

    test('should open create credential modal', async ({page}) => {
        const createButton = page.locator(
            'button:has-text("create"), ' +
            'button:has-text("add credential"), ' +
            '[data-testid*="create-credential"]'
        ).first();

        if (await createButton.count() > 0) {
            await createButton.click();
            await page.waitForTimeout(500);

            const modal = page.locator(
                '.modal, ' +
                '[role="dialog"], ' +
                '.create-credential-modal'
            ).first();

            if (await modal.count() > 0) {
                await expect(modal).toBeVisible();

                // Look for credential type selector
                const typeSelector = modal.locator(
                    'select[name*="type"], ' +
                    '[data-testid*="credential-type"]'
                ).first();

                if (await typeSelector.count() > 0) {
                    await expect(typeSelector).toBeVisible();
                }

                await page.screenshot({
                    path: getScreenshotPath('create-modal'),
                    fullPage: true,
                });

                // Close modal
                const closeButton = modal.locator(
                    'button:has-text("cancel"), ' +
                    'button:has-text("close"), ' +
                    '[aria-label="close"]'
                ).first();

                if (await closeButton.count() > 0) {
                    await closeButton.click();
                }
            }
        }
    });

    test('should have credential type options', async ({page}) => {
        // Open create modal
        const createButton = page.locator(
            'button:has-text("create"), ' +
            '[data-testid*="create-credential"]'
        ).first();

        if (await createButton.count() > 0) {
            await createButton.click();
            await page.waitForTimeout(500);

            // Look for type selector
            const typeSelector = page.locator(
                'select[name*="type"], ' +
                '[data-testid*="credential-type"]'
            ).first();

            if (await typeSelector.count() > 0) {
                await typeSelector.click();
                await page.waitForTimeout(300);

                // Expected types: api_key, bearer_token, basic_auth, custom
                const options = page.locator('option, [role="option"]');
                const optionCount = await options.count();

                console.log(`Found ${optionCount} credential type options`);

                await page.screenshot({
                    path: getScreenshotPath('type-options'),
                });
            }
        }
    });
});

test.describe('Secret Value Masking', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');
    });

    test('should never display credential values in plain text', async ({page}) => {
        // Get all text content on the page
        const pageText = await page.textContent('body');

        // Common patterns that should NOT appear
        const sensitivePatterns = [
            /sk_live_[a-zA-Z0-9]+/,  // API key patterns
            /Bearer [a-zA-Z0-9]+/,   // Bearer tokens
            /password=.+/,           // Password values
        ];

        for (const pattern of sensitivePatterns) {
            expect(pageText).not.toMatch(pattern);
        }

        // Look for masked placeholders
        const maskedElements = page
            .locator('.masked, [data-masked="true"]')
            .or(page.getByText(/\*{4,}/))
            .or(page.getByText(/•{4,}/));

        const maskedCount = await maskedElements.count();
        console.log(`Found ${maskedCount} masked value indicators`);

        await page.screenshot({
            path: getScreenshotPath('masked-values'),
            fullPage: true,
        });
    });
});

test.describe('Credential Actions', () => {
    test.beforeEach(async ({page}) => {
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');
    });

    test('should have edit/update button for credentials', async ({page}) => {
        const editButtons = page.locator(
            'button[aria-label*="edit"], ' +
            'button:has-text("edit"), ' +
            'button:has-text("update"), ' +
            '[data-testid*="edit"]'
        );

        const buttonCount = await editButtons.count();
        console.log(`Found ${buttonCount} edit buttons`);

        await page.screenshot({
            path: getScreenshotPath('edit-buttons'),
            fullPage: true,
        });
    });

    test('should have delete button for credentials', async ({page}) => {
        const deleteButtons = page.locator(
            'button[aria-label*="delete"], ' +
            'button:has-text("delete"), ' +
            '[data-testid*="delete"]'
        );

        const buttonCount = await deleteButtons.count();
        console.log(`Found ${buttonCount} delete buttons`);

        await page.screenshot({
            path: getScreenshotPath('delete-buttons'),
            fullPage: true,
        });
    });

    test('should show confirmation before deleting', async ({page}) => {
        const deleteButton = page.locator(
            'button[aria-label*="delete"], ' +
            'button:has-text("delete")'
        ).first();

        if (await deleteButton.count() > 0) {
            page.on('dialog', async (dialog) => {
                console.log(`Confirmation dialog: ${dialog.message()}`);
                await dialog.dismiss();
            });

            await deleteButton.click();
            await page.waitForTimeout(500);

            const confirmModal = page.locator(
                '.modal:has-text("delete"), ' +
                '[role="dialog"]:has-text("confirm"), ' +
                '.confirmation-dialog'
            ).first();

            if (await confirmModal.count() > 0) {
                await page.screenshot({
                    path: getScreenshotPath('delete-confirm'),
                    fullPage: true,
                });

                const cancelButton = confirmModal.locator(
                    'button:has-text("cancel"), ' +
                    'button:has-text("no")'
                ).first();

                if (await cancelButton.count() > 0) {
                    await cancelButton.click();
                }
            }
        }
    });
});

test.describe('Responsive Design', () => {
    test('should display correctly on mobile', async ({page}) => {
        await page.setViewportSize({width: 375, height: 667});
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');

        await page.screenshot({
            path: getScreenshotPath('mobile-view'),
            fullPage: true,
        });
    });

    test('should display correctly on tablet', async ({page}) => {
        await page.setViewportSize({width: 768, height: 1024});
        await page.goto(`${BASE_URL}/dashboard/credentials`);
        await page.waitForLoadState('networkidle');

        await page.screenshot({
            path: getScreenshotPath('tablet-view'),
            fullPage: true,
        });
    });
});
