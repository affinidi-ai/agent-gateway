import { defineConfig, devices } from '@playwright/test';
import path from 'path';
import fs from 'fs';

/**
 * Playwright configuration for Agent Gateway UI tests.
 *
 * Test results are stored in timestamped directories for comparison:
 * - test_results/result_YYYYMMDD_HHMMSS/ - Per-run result directory
 *   - html/ - HTML test report
 *   - screenshots/ - Screenshots
 *   - traces/ - Playwright traces on failure
 *   - results.json - JSON results
 *   - junit.xml - JUnit XML report
 * - test_results/latest/ - Symlink to most recent run
 */

// Base URL for the gateway dashboard
const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

// Generate timestamp for this test run.
//
// Workers spawn fresh node processes that re-import this config; if each
// computed its own timestamp we'd get one result_* directory per worker.
// `AG_RESULT_DIR` lets the runner (scripts/l-run-ui-tests.sh) pin a single
// directory for the whole run; otherwise we derive one here for ad-hoc
// `npx playwright` invocations.
const timestamp = new Date().toISOString()
    .replace(/[-:]/g, '')
    .replace(/T/, '_')
    .replace(/\..+/, '');
const RESULT_DIR = process.env.AG_RESULT_DIR || `./test_results/result_${timestamp}`;
if (!process.env.AG_RESULT_DIR) {
    process.env.AG_RESULT_DIR = RESULT_DIR;
}

// Create result directory
if (!fs.existsSync(RESULT_DIR)) {
    fs.mkdirSync(RESULT_DIR, { recursive: true });
}

// Create subdirectories
const subdirs = ['html', 'screenshots', 'traces', 'test-output'];
subdirs.forEach(dir => {
    const fullPath = path.join(RESULT_DIR, dir);
    if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
    }
});

// Create/update 'latest' symlink (best-effort; tolerate races between workers)
const latestLink = './test_results/latest';
try {
    fs.rmSync(latestLink, { recursive: true, force: true });
    fs.symlinkSync(path.basename(RESULT_DIR), latestLink, 'dir');
} catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
        // Worker processes can race while creating the shared symlink.
        // If another worker already created it, the link is usable.
    } else {
        // Symlink may fail on Windows, ignore
        console.warn('Could not create latest symlink:', e);
    }
}

// Write run metadata
const metadata = {
    timestamp: new Date().toISOString(),
    resultDir: RESULT_DIR,
    baseUrl: BASE_URL,
    ci: !!process.env.CI,
};
fs.writeFileSync(
    path.join(RESULT_DIR, 'test-metadata.json'),
    JSON.stringify(metadata, null, 2)
);

// Auth state file (shared across runs for session reuse)
const AUTH_DIR = path.join(__dirname, 'test_results', '.auth');
if (!fs.existsSync(AUTH_DIR)) {
    fs.mkdirSync(AUTH_DIR, { recursive: true });
}
const AUTH_FILE = path.join(AUTH_DIR, 'user.json');

export default defineConfig({
    // Test directory
    testDir: './specs',

    // Output directory for test artifacts
    outputDir: path.join(RESULT_DIR, 'test-output'),

    // Maximum time one test can run
    timeout: 60_000,

    // Expect timeout for assertions
    expect: {
        timeout: 10_000,
    },

    // Run tests in parallel
    fullyParallel: true,

    // Fail the build on CI if you accidentally left test.only in the source code
    forbidOnly: !!process.env.CI,

    // Retry failed tests on CI
    retries: process.env.CI ? 2 : 0,

    // Limit parallel workers on CI
    workers: process.env.CI ? 2 : undefined,

    // Global setup and teardown
    globalSetup: require.resolve('./global-setup'),
    globalTeardown: require.resolve('./global-teardown'),

    // Reporter configuration - multiple reporters for comprehensive output
    reporter: [
        // Always output to console
        ['list'],
        // HTML report in timestamped result directory
        ['html', {
            outputFolder: path.join(RESULT_DIR, 'html'),
            open: 'never'
        }],
        // JSON report for CI integration
        ['json', {
            outputFile: path.join(RESULT_DIR, 'results.json')
        }],
        // JUnit XML for CI systems
        ['junit', {
            outputFile: path.join(RESULT_DIR, 'junit.xml')
        }],
    ],

    // Shared settings for all projects
    use: {
        // Base URL for navigation
        baseURL: BASE_URL,

        // Capture screenshot on failure
        screenshot: {
            mode: 'only-on-failure',
            fullPage: true,
        },

        // Record trace on failure for debugging
        trace: 'retain-on-failure',

        // Record video on failure
        video: 'retain-on-failure',

        // Browser context options
        viewport: { width: 1280, height: 720 },

        // Ignore HTTPS errors (for self-signed certs in dev)
        ignoreHTTPSErrors: true,

        // Action timeout
        actionTimeout: 10_000,

        // Navigation timeout
        navigationTimeout: 30_000,
    },

    // Test projects for different browsers
    projects: [
        // Primary browser - Chromium headless
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
                // Store authentication state per project
                storageState: AUTH_FILE,
            },
            dependencies: ['setup'],
        },

        // Optional: Firefox
        // {
        //   name: 'firefox',
        //   use: {
        //     ...devices['Desktop Firefox'],
        //     storageState: AUTH_FILE,
        //   },
        //   dependencies: ['setup'],
        // },

        // Optional: WebKit (Safari)
        // {
        //   name: 'webkit',
        //   use: {
        //     ...devices['Desktop Safari'],
        //     storageState: AUTH_FILE,
        //   },
        //   dependencies: ['setup'],
        // },

        // Setup project - performs authentication before other tests.
        // Override testDir so setup files at the project root are discovered
        // (the global testDir is ./specs).
        {
            name: 'setup',
            testDir: '.',
            testMatch: /.*\.setup\.ts/,
            use: {
                // Don't use saved storage state for setup
                storageState: undefined,
            },
        },
    ],

    // Folder for screenshots, videos, and traces on failure
    snapshotDir: path.join(RESULT_DIR, 'snapshots'),

    // Web server configuration - starts gateway if not running
    // Uncomment if you want Playwright to start the gateway automatically
    // webServer: {
    //   command: 'cd .. && bash ../scripts/l-run.sh',
    //   url: BASE_URL,
    //   reuseExistingServer: !process.env.CI,
    //   timeout: 120_000,
    // },
});
