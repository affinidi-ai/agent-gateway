/**
 * Screenshot Helper
 *
 * Utilities for capturing and managing screenshots during tests.
 */

import {Page} from '@playwright/test';
import fs from 'fs';
import path from 'path';

const SCREENSHOT_DIR = 'test_results/latest/screenshots';

/**
 * Ensure screenshot directory exists
 */
export function ensureScreenshotDir(): void {
    if (!fs.existsSync(SCREENSHOT_DIR)) {
        fs.mkdirSync(SCREENSHOT_DIR, {recursive: true});
    }
}

/**
 * Generate a unique screenshot filename based on test name and timestamp
 */
export function generateScreenshotName(
    testName: string,
    suffix?: string
): string {
    const sanitizedName = testName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const suffixPart = suffix ? `-${suffix}` : '';

    return `${sanitizedName}${suffixPart}-${timestamp}.png`;
}

/**
 * Capture a full-page screenshot with consistent settings
 */
export async function captureFullPage(
    page: Page,
    name: string
): Promise<string> {
    ensureScreenshotDir();

    const filename = generateScreenshotName(name);
    const filepath = path.join(SCREENSHOT_DIR, filename);

    await page.screenshot({
        path: filepath,
        fullPage: true,
    });

    return filepath;
}

/**
 * Capture a screenshot of a specific element
 */
export async function captureElement(
    page: Page,
    selector: string,
    name: string
): Promise<string | null> {
    ensureScreenshotDir();

    const element = page.locator(selector).first();

    if (await element.count() === 0) {
        console.warn(`Element not found for screenshot: ${selector}`);
        return null;
    }

    const filename = generateScreenshotName(name, 'element');
    const filepath = path.join(SCREENSHOT_DIR, filename);

    await element.screenshot({
        path: filepath,
    });

    return filepath;
}

/**
 * Capture screenshots at multiple viewport sizes
 */
export async function captureResponsive(
    page: Page,
    name: string
): Promise<string[]> {
    ensureScreenshotDir();

    const viewports = [
        {width: 1920, height: 1080, name: 'desktop-large'},
        {width: 1366, height: 768, name: 'desktop'},
        {width: 1024, height: 768, name: 'tablet-landscape'},
        {width: 768, height: 1024, name: 'tablet-portrait'},
        {width: 414, height: 896, name: 'mobile-large'},
        {width: 375, height: 667, name: 'mobile'},
    ];

    const screenshots: string[] = [];

    for (const viewport of viewports) {
        await page.setViewportSize({width: viewport.width, height: viewport.height});
        await page.waitForLoadState('networkidle');

        const filename = generateScreenshotName(name, viewport.name);
        const filepath = path.join(SCREENSHOT_DIR, filename);

        await page.screenshot({
            path: filepath,
            fullPage: true,
        });

        screenshots.push(filepath);
    }

    return screenshots;
}

/**
 * Capture a screenshot on test failure
 */
export async function captureOnFailure(
    page: Page,
    testName: string,
    error: Error
): Promise<string> {
    ensureScreenshotDir();

    const filename = generateScreenshotName(testName, 'failure');
    const filepath = path.join(SCREENSHOT_DIR, filename);

    await page.screenshot({
        path: filepath,
        fullPage: true,
    });

    // Also capture console logs
    const consoleLogs = await page.evaluate(() => {
        return (window as any).__consoleLogs || [];
    });

    // Write error details alongside screenshot
    const errorFilepath = filepath.replace('.png', '.error.json');
    fs.writeFileSync(
        errorFilepath,
        JSON.stringify(
            {
                testName,
                error: {
                    message: error.message,
                    stack: error.stack,
                },
                consoleLogs,
                url: page.url(),
                timestamp: new Date().toISOString(),
            },
            null,
            2
        )
    );

    return filepath;
}

/**
 * Clean up old screenshots (older than specified days)
 */
export function cleanupOldScreenshots(daysOld: number = 7): void {
    if (!fs.existsSync(SCREENSHOT_DIR)) {
        return;
    }

    const now = Date.now();
    const maxAge = daysOld * 24 * 60 * 60 * 1000;

    const files = fs.readdirSync(SCREENSHOT_DIR);

    for (const file of files) {
        const filepath = path.join(SCREENSHOT_DIR, file);
        const stats = fs.statSync(filepath);

        if (now - stats.mtimeMs > maxAge) {
            fs.unlinkSync(filepath);
            console.log(`Cleaned up old screenshot: ${file}`);
        }
    }
}
