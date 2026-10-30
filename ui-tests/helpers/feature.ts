/**
 * Feature annotations and acceptance screenshots for the test report.
 *
 * `feature(...tags)` adds one `feature` annotation per tag to the running test, so
 * the HTML and JSON reports list the features a test proves. Call it at the start
 * of a test or in a `beforeEach`.
 *
 * `attachCriterion(tag, criterion, title, target)` attaches a screenshot to the
 * running test as `<tag> criterion <n>: <title>`: of the element when `target`
 * is a locator, or the PNG given. Take it of the area under test only, never of
 * a page that can show secret material.
 */

import {test, type Locator} from '@playwright/test';

export function feature(...tags: string[]): void {
    const info = test.info();
    for (const tag of tags) {
        info.annotations.push({type: 'feature', description: tag});
    }
}

export async function attachCriterion(
    tag: string,
    criterion: number,
    title: string,
    target: Locator | Buffer
): Promise<void> {
    const body = Buffer.isBuffer(target) ? target : await target.screenshot();
    await test.info().attach(`${tag} criterion ${criterion}: ${title}`, {body, contentType: 'image/png'});
}
