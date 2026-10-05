// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toBeVisible()
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';

// Mock window.matchMedia (required for Bootstrap modals in tests)
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

// Mock IntersectionObserver (required for some chart components)
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  takeRecords() {
    return [];
  }
  unobserve() {}
} as any;

// Mock ResizeObserver (required for recharts)
global.ResizeObserver = class ResizeObserver {
  constructor(callback: any) {}
  disconnect() {}
  observe() {}
  unobserve() {}
} as any;

// Mock console methods to reduce noise in test output
const originalError = console.error;
const originalWarn = console.warn;

beforeAll(() => {
  console.error = (...args: any[]) => {
    // Suppress specific React errors that are expected in tests
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('Warning: ReactDOM.render') ||
        args[0].includes('Warning: useLayoutEffect') ||
        args[0].includes('Not implemented: HTMLFormElement.prototype.submit') ||
        args[0].includes('Warning: An update to') ||
        args[0].includes('ReactDOMTestUtils.act') ||
        args[0].includes('Failed to load trust score') ||
        args[0].includes('Failed to load version history') ||
        args[0].includes('Failed to verify chain') ||
        args[0].includes('Failed to create identity') ||
        args[0].includes('Error details:'))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };

  console.warn = (...args: any[]) => {
    // Suppress specific warnings
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('Warning: ComponentSuspense') ||
        args[0].includes('Warning: An update to') ||
        args[0].includes('React Router Future Flag'))
    ) {
      return;
    }
    originalWarn.call(console, ...args);
  };

  // Suppress console.log noise from components during tests
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
  console.error = originalError;
  console.warn = originalWarn;
});
