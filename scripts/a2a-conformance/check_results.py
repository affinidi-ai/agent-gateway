"""Score the suite's results against the direct run and the baselines.

A target that forwards to the suite's test agent is not scored on what fails:
that agent fails some checks with no gateway in front of it. It is scored on
how it differs from the direct run of the same suite against that agent. A
target that is an agent in its own right is scored on its own results:

  agents (direct, and those named by --agents)
                 every failure must be listed in the target's baseline, and
                 the number of passing tests must equal the baseline's
                 `passed`, so a test that stops running or starts being
                 skipped changes the count and fails the run. A pass lost and
                 a pass gained in the same run cancel out and are not seen.
  other targets  every test whose outcome differs from the direct run must be
                 listed, with that outcome, in the target's baseline

A listed entry that no longer happens fails the run too, so a baseline cannot
keep an entry the gateway has outgrown. Outcomes are pass, fail, skip and
xfail (a SHOULD-level check the suite reports without failing the run). A
test that passes directly and is skipped through the gateway is a difference:
the suite skips a test when the call it depends on did not work. An entry
whose outcome depends on timing lists each outcome it can have.

With --report the differences are written to a Markdown file and the exit code
is 0 unless results or a baseline could not be read.
"""

import argparse
import json
import sys
import tomllib
import xml.etree.ElementTree as ET

from dataclasses import dataclass, field
from pathlib import Path

OUTCOMES = ('pass', 'fail', 'skip', 'xfail')
DIRECT = 'direct'
TEST_PREFIX = 'tests.compatibility.'
MESSAGE_LIMIT = 300
DOCUMENT_TYPE = b'<!DOCTYPE'


@dataclass(frozen=True)
class Result:
    outcome: str
    message: str = ''


@dataclass(frozen=True)
class Expected:
    outcomes: tuple[str, ...]
    reason: str

    def __str__(self) -> str:
        return ' or '.join(self.outcomes)


@dataclass(frozen=True)
class Baseline:
    expected: dict[str, Expected] = field(default_factory=dict)
    passed: int | None = None


@dataclass(frozen=True)
class Difference:
    test: str
    direct: str
    result: Result
    reason: str | None


def short(message: str | None) -> str:
    text = ' '.join((message or '').split())
    return text if len(text) <= MESSAGE_LIMIT else f'{text[:MESSAGE_LIMIT]}...'


def junit_root(path: Path) -> ET.Element:
    """Parse a report that declares no document type, so the parser is given no entity to expand or fetch.

    A NUL byte is refused too: the parser reads UTF-16 without being told to,
    and a document type written in it is not found by a search of the bytes.
    Every UTF-16 report holds a NUL byte, and no other report may.
    """
    data = path.read_bytes()
    if DOCUMENT_TYPE in data or b'\x00' in data:
        raise ValueError(f'{path}: a JUnit report must not declare a document type or hold a NUL byte')
    return ET.fromstring(data)


def junit_results(path: Path) -> dict[str, Result]:
    results: dict[str, Result] = {}
    for case in junit_root(path).iter('testcase'):
        test = f'{case.get("classname", "").removeprefix(TEST_PREFIX)}::{case.get("name")}'
        result = Result('pass')
        for child in case:
            if child.tag in ('failure', 'error'):
                result = Result('fail', short(child.get('message')))
                break
            if child.tag == 'skipped':
                outcome = 'xfail' if child.get('type') == 'pytest.xfail' else 'skip'
                result = Result(outcome, short(child.get('message')))
        results[test] = result
    return results


def probe_results(path: Path) -> dict[str, Result]:
    if not path.exists():
        raise FileNotFoundError(f'no probe results at {path}')
    entries = json.loads(path.read_text())
    if not isinstance(entries, list):
        raise ValueError(f'{path}: the probe results must be a list')
    results = {}
    for entry in entries:
        named = isinstance(entry, dict) and isinstance(entry.get('test'), str)
        if not named or entry.get('outcome') not in OUTCOMES or not isinstance(entry.get('message', ''), str):
            raise ValueError(f'{path}: each probe result needs test, outcome ({", ".join(OUTCOMES)}) and a text message: {entry}')
        results[entry['test']] = Result(entry['outcome'], short(entry.get('message')))
    return results


def load_results(directory: Path) -> dict[str, Result]:
    """Read every JUnit report in the directory (a suite run in parts leaves several) and the probes."""
    reports = sorted(directory.glob('junit*.xml'))
    if not reports:
        raise FileNotFoundError(f'no suite results in {directory}')
    results: dict[str, Result] = {}
    for report in reports:
        results |= junit_results(report)
    if not results:
        raise ValueError(f'the reports in {directory} hold no test results')
    return results | probe_results(directory / 'probes.json')


def load_baseline(path: Path, is_agent: bool) -> Baseline:
    """Read a baseline: [[expected]] entries naming one `test` or several `tests` that share a reason.

    `outcome` is one outcome, or a list when timing decides between several. An
    agent's baseline lists failures only and must set `passed`, the number of
    tests that pass; a forwarding target's baseline may be absent, which means
    no differences.
    """
    if not path.exists():
        if is_agent:
            raise FileNotFoundError(f'{path} is missing: an agent target needs a baseline that sets passed')
        return Baseline()
    document = tomllib.loads(path.read_text())
    unknown = sorted(document.keys() - {'expected', 'passed'})
    if unknown:
        raise ValueError(f'{path}: unknown key(s) {", ".join(unknown)}; a baseline holds expected and, for an agent, passed')
    passed = document.get('passed')
    if is_agent and not (type(passed) is int and passed > 0):
        raise ValueError(f'{path}: the baseline of an agent target needs passed, a whole number above 0')
    if not is_agent and passed is not None:
        raise ValueError(f'{path}: the baseline of a forwarding target must not set passed')
    allowed = ('fail',) if is_agent else OUTCOMES
    entries = document.get('expected', [])
    if not (isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries)):
        raise ValueError(f'{path}: expected must be a list of [[expected]] entries')
    expected: dict[str, Expected] = {}
    for entry in entries:
        tests = entry.get('tests', [entry['test']] if 'test' in entry else [])
        outcome, reason = entry.get('outcome'), entry.get('reason')
        outcomes = tuple(outcome) if isinstance(outcome, list) else (outcome,)
        named = isinstance(tests, list) and bool(tests) and all(isinstance(test, str) for test in tests)
        known = bool(outcomes) and all(item in allowed for item in outcomes)
        reason = reason.strip() if isinstance(reason, str) else ''
        if not named or ('test' in entry and 'tests' in entry) or not known or not reason:
            raise ValueError(f'{path}: each entry needs test or tests, outcome ({", ".join(allowed)}) and reason: {entry}')
        for test in tests:
            if test in expected:
                raise ValueError(f'{path}: {test} is listed twice')
            expected[test] = Expected(outcomes, reason)
    return Baseline(expected, passed)


def differences(is_agent: bool, results: dict[str, Result], direct: dict[str, Result]) -> dict[str, tuple[str, Result]]:
    """Map each test that counts against the target to (direct outcome, result)."""
    if is_agent:
        return {test: ('', result) for test, result in results.items() if result.outcome == 'fail'}
    found = {}
    for test in sorted(results.keys() | direct.keys()):
        before = direct[test].outcome if test in direct else 'absent'
        after = results.get(test, Result('absent'))
        if before != after.outcome:
            found[test] = (before, after)
    return found


def tally(results: dict[str, Result]) -> dict[str, int]:
    return {outcome: sum(1 for result in results.values() if result.outcome == outcome) for outcome in OUTCOMES}


def score(is_agent: bool, results: dict[str, Result], direct: dict[str, Result], expected: dict[str, Expected]):
    found = differences(is_agent, results, direct)
    listed, unlisted, stale = [], [], []
    for test, (before, result) in found.items():
        entry = expected.get(test)
        if entry is not None and result.outcome in entry.outcomes:
            listed.append(Difference(test, before, result, entry.reason))
        else:
            unlisted.append(Difference(test, before, result, None))
    for test, entry in expected.items():
        if test not in found:
            stale.append(f'{test}: listed as {entry}, but it no longer differs')
        elif found[test][1].outcome not in entry.outcomes:
            stale.append(f'{test}: listed as {entry}, but it is now {found[test][1].outcome}')
    return listed, unlisted, stale


def describe(is_agent: bool, difference: Difference) -> str:
    change = difference.result.outcome if is_agent else f'{difference.direct} -> {difference.result.outcome}'
    detail = f': {difference.result.message}' if difference.result.message else ''
    return f'{difference.test} ({change}){detail}'


def report_section(
    target: str, is_agent: bool, summary: str, listed: list[Difference], unlisted: list[Difference], notes: list[str],
) -> str:
    what = 'Failures of this agent on its own' if is_agent else 'Differences from the direct run'
    lines = [f'## {target}', '', summary, '', f'{what}: {len(listed) + len(unlisted)}.', '']
    for title, items in (('Not in the baseline', unlisted), ('In the baseline', listed)):
        if not items:
            continue
        lines += [f'### {title}', '']
        for item in items:
            lines.append(f'- `{item.test}`')
            if not is_agent:
                lines.append(f'  - direct run: {item.direct}; this target: {item.result.outcome}')
            if item.result.message:
                lines.append(f'  - suite message: {item.result.message}')
            if item.reason:
                lines.append(f'  - cause: {item.reason}')
        lines.append('')
    if notes:
        lines += ['### Baseline problems', ''] + [f'- {note}' for note in notes] + ['']
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--results', required=True, type=Path)
    parser.add_argument('--expected', required=True, type=Path)
    parser.add_argument('--targets', required=True, help='Comma-separated; direct must be one of them')
    parser.add_argument('--agents', default='', help='Comma-separated targets that are agents themselves')
    parser.add_argument('--report', type=Path, help='Write the differences here; exit 0 unless something could not be read')
    args = parser.parse_args()

    targets = args.targets.split(',')
    if DIRECT not in targets:
        print(f'FAIL  check-results: the {DIRECT} target is required; every other target is scored against it')
        return 1

    agents = {DIRECT, *filter(None, args.agents.split(','))}
    failed = unreadable = False
    sections = []
    direct: dict[str, Result] = {}
    for target in sorted(targets, key=lambda name: name != DIRECT):
        is_agent = target in agents
        try:
            results = load_results(args.results / target)
            baseline = load_baseline(args.expected / f'{target}.toml', is_agent)
        except (OSError, ValueError, ET.ParseError, tomllib.TOMLDecodeError) as error:
            print(f'FAIL  {target}: {error}')
            unreadable = True
            if target == DIRECT:
                break
            continue
        if target == DIRECT:
            direct = results
        listed, unlisted, stale = score(is_agent, results, direct, baseline.expected)
        totals = tally(results)
        notes = [f'stale baseline entry: {entry}' for entry in stale]
        if baseline.passed is not None and totals['pass'] != baseline.passed:
            notes.append(f'{totals["pass"]} tests passed where the baseline records passed = {baseline.passed}')
        noun = 'failure(s)' if is_agent else 'difference(s) from direct'
        summary = (f'{totals["pass"]} passed, {totals["fail"]} failed, {totals["skip"]} skipped, {totals["xfail"]} xfail; '
                   f'{len(listed)} expected {noun}')
        if not is_agent:
            shared = sum(1 for test, result in results.items()
                         if result.outcome == 'fail' and direct.get(test, Result('absent')).outcome == 'fail')
            summary += f'; {shared} fail without the gateway too'
        ok = not unlisted and not notes
        failed = failed or not ok
        print(f'{"PASS" if ok else "FAIL"}  {target}: {summary}')
        for item in unlisted:
            print(f'      not in the baseline: {describe(is_agent, item)}')
        for note in notes:
            print(f'      {note}')
        sections.append(report_section(target, is_agent, summary, listed, unlisted, notes))

    if unreadable:
        return 1
    if args.report is not None:
        args.report.write_text('# A2A conformance: differences by target\n\n' + '\n'.join(sections))
        print(f'report written to {args.report}')
        return 0
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
