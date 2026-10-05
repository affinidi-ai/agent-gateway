/**
 * Global Setup for UI Tests
 *
 * This runs once before all tests. It:
 * 1. Verifies the gateway is running
 * 2. Checks if test mode is enabled
 * 3. Creates test_results directories
 * 4. Sets up any global fixtures
 */

import { chromium, FullConfig } from '@playwright/test';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import {applyAuthToContext, authenticateTestUser} from './helpers/test-auth';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const AUTH_FILE = path.join(__dirname, 'test_results', '.auth', 'user.json');
const TEST_TOKEN = process.env.AG_TEST_TOKEN || 'ui-test-token-32-plus-characters';
const REPO_ROOT = path.resolve(__dirname, '..');
const UI_SRC_DIR = path.join(REPO_ROOT, 'www', 'default', 'src');
const UI_BUILD_DIR = path.join(REPO_ROOT, 'www', 'default', 'build');
const SKIP_UI_BUILD = process.env.AG_SKIP_UI_BUILD === 'true';
const ENV_DIR = process.env.AG_ENV_DIR || 'tmp/local-ui-tests';

/**
 * Walk a directory and return the latest mtime found, in ms.
 * Returns 0 if the directory does not exist.
 */
function latestMtimeMs(dir: string): number {
    if (!fs.existsSync(dir)) {
        return 0;
    }
    let latest = 0;
    const stack: string[] = [dir];
    while (stack.length > 0) {
        const current = stack.pop()!;
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) {
                if (entry.name === 'node_modules' || entry.name === 'build' || entry.name === 'dist') {
                    continue;
                }
                stack.push(full);
            } else if (entry.isFile()) {
                const mtime = fs.statSync(full).mtimeMs;
                if (mtime > latest) {
                    latest = mtime;
                }
            }
        }
    }
    return latest;
}

/**
 * Ensure the React dashboard bundle on disk reflects the latest source.
 *
 * Triggered before any test runs so the gateway (which serves static files
 * directly from disk on each request) cannot accidentally hand out a stale
 * bundle that lacks the `data-testid` attributes our specs rely on.
 *
 * Skipped when `AG_SKIP_UI_BUILD=true` (useful in CI when the bundle is
 * built in a separate, cached stage).
 */
function ensureUiBuildIsFresh(): void {
    if (SKIP_UI_BUILD) {
        console.log('⏭️  AG_SKIP_UI_BUILD=true \u2014 skipping UI freshness check');
        return;
    }

    const srcMtime = latestMtimeMs(UI_SRC_DIR);
    const buildMtime = latestMtimeMs(UI_BUILD_DIR);
    const stale = buildMtime === 0 || srcMtime > buildMtime;

    if (!stale) {
        console.log('✅ UI bundle is up to date');
        return;
    }

    console.log('🛠️  UI bundle is stale or missing \u2014 running `make www-rebuild`...');
    execSync('make www-rebuild', { cwd: REPO_ROOT, stdio: 'inherit' });
    console.log('✅ UI bundle rebuilt');
}

async function globalSetup(_config: FullConfig): Promise<void> {
    console.log('\n🚀 Starting UI Test Suite Global Setup...\n');

    // 0. Make sure the bundle the gateway will serve matches the latest
    //    source. Done before any browser/network checks so a stale bundle
    //    cannot waste a full test run.
    ensureUiBuildIsFresh();

    // 1. Create the minimal directories the suite needs at the root.
    //    Per-run artifacts (html, screenshots, traces, snapshots, test-output)
    //    are created inside `test_results/result_*` by playwright.config.ts.
    const testResultsDir = path.join(__dirname, 'test_results');
    const authDir = path.join(testResultsDir, '.auth');
    for (const dir of [testResultsDir, authDir]) {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }

    // 2. Verify gateway is running
    console.log(`\n🔍 Checking gateway at ${BASE_URL}...`);

    const browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
        // Try to access the dashboard
        const response = await page.goto(`${BASE_URL}/dashboard`, {
            waitUntil: 'domcontentloaded',
            timeout: 30000,
        });

        if (!response) {
            throw new Error('No response from gateway');
        }

        if (response.status() >= 500) {
            throw new Error(`Gateway returned error status: ${response.status()}`);
        }

        console.log('✅ Gateway is running and accessible');

        // 2b. Verify the gateway is serving the freshly built bundle.
        //
        // We just rebuilt `www/default/build` in `ensureUiBuildIsFresh`.
        // The gateway reads static files directly from disk, so as long as
        // its configured `path` points at `www/default/build` it will pick
        // up the new bundle automatically. If it doesn't, the configured
        // path has drifted (e.g. an old `www/build` from a previous run);
        // re-run `_prepare.sh` to repair gateway.json and instruct the
        // operator to restart the gateway.
        try {
            const html = await (await page.request.get(`${BASE_URL}/`)).text();
            const match = html.match(/main\.[a-f0-9]+\.js/);
            const buildJsDir = path.join(UI_BUILD_DIR, 'static', 'js');
            if (match && fs.existsSync(buildJsDir)) {
                const onDisk = fs.readdirSync(buildJsDir).filter((f) => /^main\.[a-f0-9]+\.js$/.test(f));
                if (onDisk.length > 0 && !onDisk.includes(match[0])) {
                    console.log(
                        `⚠️  Gateway is serving ${match[0]} but on-disk build has ${onDisk.join(', ')}.`
                    );
                    console.log('🔧 Re-running scripts/_prepare.sh to repair the dashboard path...');
                    execSync(`./scripts/_prepare.sh debug ${ENV_DIR}`, { cwd: REPO_ROOT, stdio: 'inherit' });
                    throw new Error(
                        'Gateway dashboard path was repaired but the gateway must be restarted ' +
                        'for the change to take effect. Restart the gateway and re-run the tests.'
                    );
                }
            }
        } catch (err) {
            if (err instanceof Error && err.message.includes('must be restarted')) {
                throw err;
            }
            // Non-fatal: best-effort probe.
        }

        // 3. Check if test mode is enabled by attempting test login
        console.log('\n🔐 Checking test authentication mode...');

        const authResult = await authenticateTestUser(page.request, BASE_URL);

        if (!authResult.success || !authResult.sessionToken) {
            console.log(`⚠️  Test authentication unavailable: ${authResult.error}`);
            console.log('   Tests will attempt to use any existing session or may fail on authenticated pages.');
        } else {
            console.log('✅ Test mode is enabled and working');
            // Use the same cookie-backed auth-state format as auth.setup.ts so
            // dependent projects never race on incompatible storage shapes.
            await applyAuthToContext(context, page, BASE_URL, authResult.sessionToken);
            await context.storageState({path: AUTH_FILE});
            console.log('💾 Saved authentication state to test_results/.auth/user.json');
        }

    } catch (error) {
        console.error('\n❌ Global setup failed:');
        console.error(error);

        // Take a screenshot of the current state into the per-run dir.
        const failureDir = process.env.AG_RESULT_DIR
            ? path.resolve(__dirname, process.env.AG_RESULT_DIR)
            : testResultsDir;
        if (!fs.existsSync(failureDir)) {
            fs.mkdirSync(failureDir, { recursive: true });
        }
        const failurePath = path.join(failureDir, 'global-setup-failure.png');
        await page.screenshot({ path: failurePath, fullPage: true });
        console.log(`📸 Saved failure screenshot to ${path.relative(__dirname, failurePath)}`);

        throw error;
    } finally {
        await context.close();
        await browser.close();
    }

    // 4. Write test run metadata into the per-run result directory.
    const metadata = {
        startTime: new Date().toISOString(),
        baseUrl: BASE_URL,
        testMode: process.env.AG_TEST_MODE || 'false',
        nodeVersion: process.version,
        platform: process.platform,
    };

    if (process.env.AG_RESULT_DIR) {
        const resultDir = path.resolve(__dirname, process.env.AG_RESULT_DIR);
        if (!fs.existsSync(resultDir)) {
            fs.mkdirSync(resultDir, { recursive: true });
        }
        fs.writeFileSync(
            path.join(resultDir, 'run-metadata.json'),
            JSON.stringify(metadata, null, 2)
        );
    }

    console.log('\n✨ Global setup completed successfully!\n');
}

export default globalSetup;
