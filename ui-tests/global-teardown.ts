/**
 * Global Teardown for UI Tests
 *
 * This runs once after all tests complete. It:
 * 1. Generates test summary
 * 2. Cleans up temporary files
 * 3. Logs final statistics
 */

import fs from 'fs';
import path from 'path';

async function globalTeardown(): Promise<void> {
    console.log('\n🧹 Starting UI Test Suite Global Teardown...\n');

    const testResultsDir = path.join(__dirname, 'test_results');
    const logsDir = path.join(testResultsDir, 'logs');

    // 1. Update test run metadata with end time
    const metadataPath = path.join(logsDir, 'test-run-metadata.json');
    if (fs.existsSync(metadataPath)) {
        try {
            const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8'));
            metadata.endTime = new Date().toISOString();

            const startTime = new Date(metadata.startTime);
            const endTime = new Date(metadata.endTime);
            metadata.durationMs = endTime.getTime() - startTime.getTime();
            metadata.durationHuman = formatDuration(metadata.durationMs);

            fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
            console.log(`⏱️  Total test duration: ${metadata.durationHuman}`);
        } catch (error) {
            console.warn('Could not update test metadata:', error);
        }
    }

    // 2. Count test artifacts
    const screenshotsDir = path.join(testResultsDir, 'screenshots');
    const tracesDir = path.join(testResultsDir, 'traces');

    let screenshotCount = 0;
    let traceCount = 0;

    if (fs.existsSync(screenshotsDir)) {
        screenshotCount = fs.readdirSync(screenshotsDir).filter(f => f.endsWith('.png')).length;
    }

    if (fs.existsSync(tracesDir)) {
        traceCount = fs.readdirSync(tracesDir).filter(f => f.endsWith('.zip')).length;
    }

    // 3. Log summary
    console.log('\n📊 Test Run Summary:');
    console.log(`   📸 Screenshots captured: ${screenshotCount}`);
    console.log(`   🔍 Traces recorded: ${traceCount}`);

    // 4. Check if HTML report exists and log location
    const htmlReportPath = path.join(testResultsDir, 'html-report', 'index.html');
    if (fs.existsSync(htmlReportPath)) {
        console.log(`   📄 HTML Report: ${path.relative(process.cwd(), htmlReportPath)}`);
    }

    // 5. Check for test results JSON
    const jsonResultsPath = path.join(testResultsDir, 'test-results.json');
    if (fs.existsSync(jsonResultsPath)) {
        try {
            const results = JSON.parse(fs.readFileSync(jsonResultsPath, 'utf-8'));
            if (results.suites) {
                const stats = countTestResults(results);
                console.log('\n📈 Test Results:');
                console.log(`   ✅ Passed: ${stats.passed}`);
                console.log(`   ❌ Failed: ${stats.failed}`);
                console.log(`   ⏭️  Skipped: ${stats.skipped}`);
                console.log(`   📝 Total: ${stats.total}`);
            }
        } catch (error) {
            // Results might not be complete yet
        }
    }

    console.log('\n✨ Global teardown completed!\n');
}

function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    if (minutes > 0) {
        return `${minutes}m ${remainingSeconds}s`;
    }
    return `${seconds}s`;
}

interface TestStats {
    passed: number;
    failed: number;
    skipped: number;
    total: number;
}

function countTestResults(results: any): TestStats {
    const stats: TestStats = {passed: 0, failed: 0, skipped: 0, total: 0};

    function processSpecs(specs: any[]) {
        for (const spec of specs || []) {
            for (const test of spec.tests || []) {
                stats.total++;
                const status = test.status;
                if (status === 'expected' || status === 'passed') {
                    stats.passed++;
                } else if (status === 'unexpected' || status === 'failed') {
                    stats.failed++;
                } else if (status === 'skipped') {
                    stats.skipped++;
                }
            }
        }
    }

    function processSuites(suites: any[]) {
        for (const suite of suites || []) {
            processSpecs(suite.specs);
            processSuites(suite.suites);
        }
    }

    processSuites(results.suites);
    return stats;
}

export default globalTeardown;
