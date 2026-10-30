import {defineConfig, devices} from '@playwright/test';
import path from 'path';

/**
 * Live OIDC/OAuth suite: the real dashboard, two live Ory Hydra instances and the mock A2A agent.
 *
 * Run it with `make oidc-ui-e2e`, which starts those services and a gateway first. Traces,
 * videos and screenshots stay off because a page in this suite can show secret material.
 */

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';
const RESULT_DIR = process.env.AG_RESULT_DIR || path.join(__dirname, 'test_results', 'oidc-live');
const AUTH_FILE = path.join(__dirname, 'test_results', '.auth', 'user.json');

export default defineConfig({
    testDir: './specs/oidc-live',
    outputDir: path.join(RESULT_DIR, 'test-output'),
    timeout: 90_000,
    expect: {timeout: 15_000},
    fullyParallel: false,
    workers: 1,
    forbidOnly: !!process.env.CI,
    retries: 0,
    reporter: [
        ['list'],
        ['html', {outputFolder: path.join(RESULT_DIR, 'html'), open: 'never'}],
        ['json', {outputFile: path.join(RESULT_DIR, 'results.json')}],
    ],
    use: {
        baseURL: BASE_URL,
        screenshot: 'off',
        trace: 'off',
        video: 'off',
        viewport: {width: 1600, height: 1000},
        ignoreHTTPSErrors: true,
        actionTimeout: 15_000,
        navigationTimeout: 30_000,
    },
    projects: [
        {
            name: 'auth',
            testDir: '.',
            testMatch: /auth\.setup\.ts/,
            use: {storageState: undefined},
        },
        {
            name: 'world-setup',
            testMatch: /world\.setup\.ts/,
            dependencies: ['auth'],
            teardown: 'world-teardown',
        },
        {
            name: 'world-teardown',
            testMatch: /world\.teardown\.ts/,
        },
        {
            name: 'oidc-live',
            testIgnore: /\.(setup|teardown)\.ts/,
            use: {...devices['Desktop Chrome'], viewport: {width: 1600, height: 1000}, storageState: AUTH_FILE},
            dependencies: ['world-setup'],
        },
    ],
});
