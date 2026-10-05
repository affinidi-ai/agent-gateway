# UI Automated Tests

Automated UI tests for the Agent Gateway dashboard using Playwright.

## Prerequisites

- Node.js 18+
- npm or yarn
- Gateway running locally (default: http://localhost:8080)

## Quick Start

```bash
# From repository root - run all UI tests
make ui-test

# View the HTML report
make ui-test-report
```

## Setup

```bash
# Install dependencies
npm install

# Install Playwright browsers
npx playwright install chromium
```

## Running Tests

### Prerequisites

Before running tests, ensure:

1. **Gateway is running** with test mode enabled. `make ui-test` does this for you: it
   wipes and prepares `tmp/local-ui-tests`, starts the gateway on port 8711, runs the
   suite, and stops the gateway. The env dir, including its `gateway.log`, is kept after
   the run for debugging. Set `AG_ENV_DIR=<dir>` to use an existing env and its own ports
   instead; that dir is never wiped. To run the gateway yourself, from the repository root:
   ```bash
   ./scripts/_prepare.sh debug tmp/local-ui-tests --auto-accept
   cargo build --bin agent-gateway
   cd tmp/local-ui-tests
   AG_TEST_MODE=true \
   AG_TEST_TOKEN=your-32-plus-character-secret-token \
   AG_TEST_ALLOW_ROLE_OVERRIDE=true \
   AG_BACKUP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
   ../../target/debug/agent-gateway --config config/config.toml
   ```

2. **Set test environment variables** (optional):
   ```bash
   export AG_BASE_URL=http://localhost:8711    # Gateway URL (default http://localhost:8080)
   export AG_TEST_TOKEN=your-32-plus-character-secret-token # Must match gateway config
   export AG_TEST_ALLOW_ROLE_OVERRIDE=true     # Allows UI tests to request administrator sessions
   export AG_TEST_USERNAME=test-user           # Optional: custom username
   ```

### Run All Tests

```bash
npm run test:ui
# Or from repo root:
make ui-test
```

### Run in Headed Mode (Visible Browser)

```bash
npm run test:ui:headed
# Or from repo root:
make ui-test-headed
```

### Debug Mode (Step Through Tests)

```bash
npm run test:ui:debug
```

### View HTML Report

```bash
npm run test:ui:report
# Or from repo root:
make ui-test-report
```

### Generate Test Code

```bash
npm run test:ui:codegen
```

## Test Results

Test results are stored in **timestamped directories** for comparison and historical analysis:

```
test_results/
├── result_20260128_143052/   # Timestamped result directory
│   ├── html/                 # Interactive HTML report
│   ├── screenshots/          # Test screenshots
│   ├── traces/               # Playwright traces (on failure)
│   ├── test-output/          # Raw test output
│   ├── results.json          # Machine-readable JSON results
│   ├── junit.xml             # JUnit XML for CI integration
│   └── test-metadata.json    # Run metadata and summary
├── result_20260128_120000/   # Previous run (preserved for comparison)
├── latest/                   # Symlink to most recent run
└── .auth/                    # Shared authentication state
```

### Comparing Test Results

To compare results across runs:

```bash
# Compare pass/fail rates
diff test_results/result_20260128_120000/results.json \
     test_results/result_20260128_143052/results.json

# Compare screenshots visually
open test_results/result_*/screenshots/
```

## Test Structure

```
ui-tests/
├── specs/                    # Test specifications
│   ├── dashboard.spec.ts     # Dashboard page tests
│   ├── navigation.spec.ts    # Navigation tests
│   ├── channels.spec.ts      # Channel management tests
│   ├── api-keys.spec.ts      # API Keys page tests
│   ├── credentials.spec.ts   # Outbound Credentials tests
│   └── accessibility.spec.ts # WCAG accessibility tests
├── helpers/                  # Test utilities
│   ├── test-auth.ts          # Authentication helpers
│   ├── screenshots.ts        # Screenshot utilities
│   ├── wait.ts               # Custom wait functions
│   └── index.ts              # Helper exports
├── test_results/             # Test output (gitignored)
│   ├── screenshots/          # Test screenshots
│   ├── traces/               # Playwright traces
│   ├── html/                 # HTML report
│   ├── results.json          # JSON results
│   └── junit.xml             # JUnit XML report
├── auth.setup.ts             # Authentication setup
├── global-setup.ts           # Test suite setup
├── global-teardown.ts        # Test suite teardown
├── playwright.config.ts      # Playwright configuration
├── package.json              # Dependencies
└── tsconfig.json             # TypeScript config
```

## Test Authentication

Tests use a bypass mechanism to avoid WebAuthn passkey authentication:

1. Gateway must be started with `AG_TEST_MODE=true`
2. Tests call `/api/internal/test-support/auth/login` with `X-Test-Token` header
3. Gateway provisions or reuses an approved synthetic test user, then creates a real session for that user
4. Gateway sets the session cookie through the shared auth finalizer, while the Playwright helper keeps `sessionStorage` aligned with the current frontend contract

### Security Note

⚠️ **Never enable test mode in production!**

Test mode should only be used for:

- Local development
- CI/CD pipelines
- Automated testing environments

## Test Results

After running tests, results are available in `test_results/`:

| File/Directory       | Description                        |
|----------------------|------------------------------------|
| `screenshots/`       | Full-page and element screenshots  |
| `traces/`            | Playwright traces for failed tests |
| `html/`              | Interactive HTML report            |
| `results.json`       | JSON test results                  |
| `junit.xml`          | JUnit XML for CI integration       |
| `test-metadata.json` | Run metadata and summary           |

### Viewing the HTML Report

```bash
npx playwright show-report test_results/html
```

## Writing New Tests

### Selector convention

**Specs MUST select elements via `page.getByTestId(...)`.** Text, CSS-class, and
`:has-text()` selectors are not allowed in new specs — they are brittle and silently
pass when the UI changes shape.

The dashboard exposes stable `data-testid` attributes per the convention described in
this document (see the reserved patterns below).
Reserved patterns:

| Purpose | Pattern | Example |
|---|---|---|
| Page root | `page-<area>` | `page-channels` |
| Primary CTA | `<area>-<verb>-button` | `channels-add-button` |
| List item / row | `<area>-card-<id>` / `<area>-row-<id>` | `channel-card-prod-a2a` |
| Empty state | `<area>-empty-state` | `channels-empty-state` |
| Form field | `<form>-<field>` | `add-channel-name` |
| Modal root | `<area>-modal` | `apikey-secret-modal` |
| Sidebar nav item | `nav-<route-key>` | `nav-channels` |
| Wizard root + steps | `wizard-<name>`, `wizard-step-<name>` | `wizard-add-channel`, `wizard-step-configure` |
| Wizard navigation | `wizard-next`, `wizard-back`, `wizard-submit` | (shared across all wizards) |

If you need a testid that does not yet exist on the dashboard, add it to the React
component first (see the `data-testid` rules in [`www/default/AGENTS.md`](../www/default/AGENTS.md)),
then write the spec against it. Do not work around
a missing testid with text/class selectors.

### Assertion rules

- Use hard `expect(...)` assertions. Soft patterns like `expect(count).toBeGreaterThanOrEqual(0)`
  or `if (await el.count() > 0) { ... }` are not real assertions — a green run must mean
  the feature works.
- Wait on testid visibility, not arbitrary timeouts. `await expect(page.getByTestId('page-channels')).toBeVisible()`
  is preferred over `waitForTimeout`.

### Basic test structure

```typescript
import { test, expect } from '@playwright/test';

const BASE_URL = process.env.AG_BASE_URL || 'http://localhost:8080';

test.describe('Channels', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/channels-next`);
    await expect(page.getByTestId('page-channels')).toBeVisible();
  });

  test('exposes the add-channel CTA', async ({ page }) => {
    const addButton = page.getByTestId('channels-add-button');
    await expect(addButton).toBeVisible();

    await addButton.click();
    await expect(page.getByTestId('wizard-add-channel')).toBeVisible();
  });
});
```

### Using Helpers

```typescript
import { test, expect } from '@playwright/test';
import {
  loginAsTestUser,
  captureFullPage,
  waitForNetworkIdle
} from './helpers';

test('authenticated test', async ({ page }) => {
  await loginAsTestUser(page);
  await waitForNetworkIdle(page);
  await captureFullPage(page, 'after-login');
});
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run UI Tests
  run: |
    cd agent-gateway/ui-tests
    npm ci
    npx playwright install chromium
    npm run test:ui
  env:
    AG_TEST_MODE: 'true'
    AG_TEST_TOKEN: ${{ secrets.AG_TEST_TOKEN }}

- name: Upload Test Results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: ui-test-results
    path: agent-gateway/ui-tests/test_results/
```

## Troubleshooting

### Tests fail with "Gateway not running"

Run `make ui-test`, which starts and stops the gateway itself, or start the gateway as
described under [Prerequisites](#prerequisites-1) before running the tests.

### Tests fail with "Test mode not enabled"

Start the gateway with `AG_TEST_MODE=true`, as described under
[Prerequisites](#prerequisites-1).

### Tests fail with "Unauthorized"

Check that `AG_TEST_TOKEN` matches between gateway and test environment.

### Screenshots are blank

Ensure the page has fully loaded before taking screenshots:

```typescript
await page.waitForLoadState('networkidle');
```

### Tests timeout

Increase timeout in `playwright.config.ts` or individual tests:

```typescript
test.setTimeout(60000); // 60 seconds
```

## License

Same as parent project.
