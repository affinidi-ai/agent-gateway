# DID:webvh UI Component Tests

This directory contains unit tests for the DID:webvh identity management UI components.

## Overview

The tests cover the following components:

- **TrustScoreModal** - Trust score visualization with radar charts and component breakdown
- **VersionHistoryModal** - Version history timeline with integrity verification
- **CreateIdentityWizard** - 3-step wizard for creating new DID:webvh identities
- **IdentitiesPage** - Main identity list page with trust scores and actions

## Test Framework

The tests use:

- **Jest** - Test runner (included with Create React App)
- **React Testing Library** - Component testing utilities
- **@testing-library/jest-dom** - Custom matchers for DOM assertions

## Prerequisites

Install testing dependencies if not already present:

```bash
cd agent-gateway/www/
npm install --save-dev @testing-library/react @testing-library/jest-dom @testing-library/user-event
```

## Running Tests

### Run all tests

```bash
npm test
```

### Run tests in watch mode (default)

```bash
npm test -- --watch
```

### Run tests once (CI mode)

```bash
npm test -- --watchAll=false
```

### Run specific test file

```bash
npm test TrustScoreModal
npm test CreateIdentityWizard
npm test VersionHistoryModal
npm test IdentitiesPage
```

### Run tests with coverage

```bash
npm test -- --coverage --watchAll=false
```

## Test Structure

### TrustScoreModal Tests

- ✅ Renders loading state initially
- ✅ Loads and displays trust score data
- ✅ Displays error message on API failure
- ✅ Calls onHide when close button clicked
- ✅ Refreshes trust score when refresh button clicked
- ✅ Does not load data when modal is not shown
- ✅ Displays weighted calculation correctly
- ✅ Shows correct trust score labels (TRUSTED, ACCEPTABLE, CAUTION, LOW TRUST)
- ✅ Displays TEE and cloud attestation status
- ✅ Renders radar chart component

### CreateIdentityWizard Tests

- ✅ Renders step 1 initially
- ✅ Shows DID preview when path is entered
- ✅ Disables Next button when required fields are empty
- ✅ Enables Next button when required fields are filled
- ✅ Navigates through 3 steps correctly
- ✅ Shows Previous button on step 2 and 3
- ✅ Shows review configuration on step 3
- ✅ Calls API and onSuccess when Create Identity clicked
- ✅ Shows error message when API call fails
- ✅ Closes modal when Cancel clicked
- ✅ Toggles capabilities checkboxes

### VersionHistoryModal Tests

- ✅ Renders loading state initially
- ✅ Loads and displays version history
- ✅ Displays error message on API failure
- ✅ Shows CURRENT badge for latest version
- ✅ Displays version details correctly
- ✅ Toggles version comparison UI
- ✅ Runs version comparison when button clicked
- ✅ Verifies chain integrity when Verify button clicked
- ✅ Shows verification error when verification fails
- ✅ Calls onHide when close button clicked
- ✅ Does not load data when modal is not shown
- ✅ Displays different operation badges (GENESIS, UPDATE, KEY ROTATION, TRANSFER)
- ✅ Expands and collapses metadata sections

### IdentitiesPage Tests

- ✅ Renders identities list
- ✅ Displays trust score progress bars
- ✅ Displays attestation icons (TEE, Cloud)
- ✅ Opens trust score modal when button clicked
- ✅ Opens version history modal when button clicked
- ✅ Opens create identity wizard when Create Identity clicked
- ✅ Displays correct trust score colors (high score = green, low score = yellow/red)
- ✅ Displays version badges
- ✅ Handles empty identities list
- ✅ Handles API error gracefully
- ✅ Copies identity link to clipboard
- ✅ Conditional rendering (no trust score button without score, no history button without uuid)

## Mocking Strategy

### API Client

All API calls are mocked using `jest.mock()`:

```typescript
jest.mock('../../../api', () => ({
  apiClient: {
    getIdentityTrustScore: jest.fn(),
    // ... other methods
  },
}));
```

### Utilities

Utility functions like `formatDateTime` are mocked for consistent test data:

```typescript
jest.mock('../../../utils', () => ({
  formatDateTime: jest.fn(date => `Formatted: ${date}`),
  timeAgo: jest.fn(date => '2 days ago'),
}));
```

## Writing New Tests

### Test File Template

```typescript
import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import YourComponent from '../YourComponent';
import { apiClient } from '../../../api';

jest.mock('../../../api', () => ({
  apiClient: {
    yourMethod: jest.fn(),
  },
}));

describe('YourComponent', () => {
  const defaultProps = {
    prop1: 'value1',
    onHide: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders correctly', () => {
    render(<YourComponent {...defaultProps} />);
    expect(screen.getByText('Expected Text')).toBeInTheDocument();
  });

  it('handles user interaction', async () => {
    render(<YourComponent {...defaultProps} />);

    const button = screen.getByText('Click Me');
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText('Result')).toBeInTheDocument();
    });
  });
});
```

### Common Testing Patterns

**1. Testing async data loading:**

```typescript
it('loads data on mount', async () => {
  (apiClient.getData as jest.Mock).mockResolvedValue(mockData);

  render(<Component show={true} />);

  await waitFor(() => {
    expect(screen.getByText('Loaded Data')).toBeInTheDocument();
  });
});
```

**2. Testing error states:**

```typescript
it('displays error message', async () => {
  (apiClient.getData as jest.Mock).mockRejectedValue(new Error('API Error'));

  render(<Component />);

  await waitFor(() => {
    expect(screen.getByText('API Error')).toBeInTheDocument();
  });
});
```

**3. Testing form interactions:**

```typescript
it('updates input value', () => {
  render(<Component />);

  const input = screen.getByLabelText('Field Name');
  fireEvent.change(input, { target: { value: 'New Value' } });

  expect(input).toHaveValue('New Value');
});
```

**4. Testing modal visibility:**

```typescript
it('does not load when hidden', () => {
  render(<Modal show={false} />);

  expect(apiClient.getData).not.toHaveBeenCalled();
});
```

## Troubleshooting

### Tests failing with "Cannot find module"

Make sure all dependencies are installed:

```bash
npm install
```

### Tests timeout

Increase the timeout in `waitFor()`:

```typescript
await waitFor(
  () => {
    expect(screen.getByText('Text')).toBeInTheDocument();
  },
  { timeout: 3000 }
);
```

### Mock not working

Ensure mock is defined before the component import:

```typescript
jest.mock('../../../api'); // This must be before component import
import YourComponent from '../YourComponent';
```

### Chart rendering issues

Make sure recharts is properly mocked as shown in the Mocking Strategy section.

## Coverage Goals

Aim for:

- **Statements**: > 80%
- **Branches**: > 75%
- **Functions**: > 80%
- **Lines**: > 80%

Run `npm test -- --coverage` to check current coverage.

## CI/CD Integration

Add to your CI pipeline:

```yaml
- name: Run UI Tests
  run: |
    cd agent-gateway/www/
    npm ci
    npm test -- --watchAll=false --coverage
```

## Related Documentation

- [React Testing Library Documentation](https://testing-library.com/docs/react-testing-library/intro/)
- [Jest Documentation](https://jestjs.io/docs/getting-started)
