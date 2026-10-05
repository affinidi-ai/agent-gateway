/**
 * Authentication Setup
 *
 * This test runs before all other tests to establish authentication.
 * It uses the internal test-support auth endpoint to bypass passkey auth and saves
 * the session state for use by other tests.
 */

import {expect, test as setup} from '@playwright/test';
import {applyAuthToContext, authenticateTestUser} from './helpers/test-auth';
import fs from 'fs';
import path from 'path';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const AUTH_FILE = path.join(__dirname, 'test_results', '.auth', 'user.json');

setup('authenticate', async ({page, context}) => {
    setup.setTimeout(60000);

    console.log('🔐 Setting up test authentication...');

    // Attempt to authenticate using the internal test-support auth endpoint
    const result = await authenticateTestUser(page.request, BASE_URL);

    if (!result.success) {
        console.warn(`⚠️  Test authentication unavailable: ${result.error}`);
        console.warn('   Some tests may fail if they require authentication.');

        // Create empty auth state file so tests can still run
        const emptyState = {
            cookies: [],
            origins: [],
        };

        // Ensure directory exists
        const authDir = path.dirname(AUTH_FILE);
        if (!fs.existsSync(authDir)) {
            fs.mkdirSync(authDir, {recursive: true});
        }

        fs.writeFileSync(AUTH_FILE, JSON.stringify(emptyState, null, 2));
        return;
    }

    console.log(`✅ Authenticated as: ${result.username}`);

    // Apply auth to the current context
    await applyAuthToContext(context, page, BASE_URL, result.sessionToken!);

    // Navigate to dashboard to verify auth works
    await page.goto(`${BASE_URL}/dashboard`);

    // Wait for dashboard to load (should not redirect to login)
    await expect(page).not.toHaveURL(/login/i, {timeout: 10000});

    // Verify we're on the dashboard
    await expect(page.locator('body')).toBeVisible();

    // Save storage state for use by other tests
    await context.storageState({path: AUTH_FILE});

    console.log('💾 Authentication state saved successfully');
});
