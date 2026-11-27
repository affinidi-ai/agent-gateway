"""Self-tests for check_results.py; run.sh runs them before it scores anything."""

import contextlib
import io
import json
import sys
import tempfile
import unittest

from pathlib import Path

import check_results

from check_results import Baseline, Expected, Result

JUNIT = """<testsuites><testsuite>
<testcase classname="tests.compatibility.core.test_a.TestSend" name="test_ok[jsonrpc]"/>
<testcase classname="tests.compatibility.core.test_a.TestSend" name="test_bad">
  <failure message="AssertionError: expected   error\nbut it succeeded">trace</failure></testcase>
<testcase classname="tests.compatibility.core.test_a.TestSend" name="test_crash"><error message="boom">trace</error></testcase>
<testcase classname="tests.compatibility.core.test_a.TestSend" name="test_skipped">
  <skipped type="pytest.skip" message="send_message failed: timed out"/></testcase>
<testcase classname="tests.compatibility.core.test_a.TestSend" name="test_should">
  <skipped type="pytest.xfail" message="SHOULD not met"/></testcase>
</testsuite></testsuites>"""
NO_PROBES = '[]'
BOTH_WAYS = '(fail both ways, for another reason)'
SLASH_PROBE = [{'test': 'harness.entry_point::accepts_trailing_slash', 'outcome': 'fail', 'message': 'HTTP 404'}]


def results(**outcomes: str) -> dict[str, Result]:
    return {test: Result(outcome) for test, outcome in outcomes.items()}


def testcase(name: str, outcome: str = 'pass') -> str:
    body = '' if outcome == 'pass' else '<failure message="no ETag"/>'
    return f'<testcase classname="tests.compatibility.card" name="{name}">{body}</testcase>'


class Results(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_reads_each_outcome_and_shortens_the_test_name(self):
        (self.directory / 'junitreport.xml').write_text(JUNIT)
        parsed = check_results.junit_results(self.directory / 'junitreport.xml')
        self.assertEqual(parsed['core.test_a.TestSend::test_ok[jsonrpc]'], Result('pass'))
        self.assertEqual(parsed['core.test_a.TestSend::test_bad'],
                         Result('fail', 'AssertionError: expected error but it succeeded'))
        self.assertEqual(parsed['core.test_a.TestSend::test_crash'].outcome, 'fail')
        self.assertEqual(parsed['core.test_a.TestSend::test_skipped'], Result('skip', 'send_message failed: timed out'))
        self.assertEqual(parsed['core.test_a.TestSend::test_should'].outcome, 'xfail')

    def test_a_test_that_is_skipped_and_then_errors_counts_as_failed(self):
        (self.directory / 'junitreport.xml').write_text(
            '<testsuite><testcase classname="tests.compatibility.card" name="test_get">'
            '<skipped type="pytest.skip" message="no card"/><error message="teardown failed"/></testcase></testsuite>')
        parsed = check_results.junit_results(self.directory / 'junitreport.xml')
        self.assertEqual(parsed, {'card::test_get': Result('fail', 'teardown failed')})

    def test_a_test_outside_the_compatibility_tests_keeps_its_whole_name(self):
        (self.directory / 'junit-mandatory.xml').write_text(
            '<testsuite><testcase classname="tests.mandatory.protocol.test_card" name="test_get"/></testsuite>')
        parsed = check_results.junit_results(self.directory / 'junit-mandatory.xml')
        self.assertEqual(parsed, {'tests.mandatory.protocol.test_card::test_get': Result('pass')})

    def test_a_message_outside_ascii_is_read(self):
        (self.directory / 'junitreport.xml').write_text(
            '<?xml version="1.0" encoding="utf-8"?><testsuite><testcase classname="tests.compatibility.card" name="test_get">'
            '<failure message="naïve — 日本"/></testcase></testsuite>', encoding='utf-8')
        parsed = check_results.junit_results(self.directory / 'junitreport.xml')
        self.assertEqual(parsed, {'card::test_get': Result('fail', 'naïve — 日本')})

    def test_a_report_that_declares_a_document_type_is_refused(self):
        for declaration in ('<!DOCTYPE testsuite [<!ENTITY a "expanded">]>',
                            '<!DOCTYPE testsuite [<!ENTITY a SYSTEM "file:///etc/hostname">]>',
                            '<!DOCTYPE testsuite SYSTEM "http://127.0.0.1:9/suite.dtd">'):
            (self.directory / 'junitreport.xml').write_text(
                f'{declaration}<testsuite><testcase classname="tests.compatibility.card" name="test_get">'
                '<failure message="&a;"/></testcase></testsuite>')
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'must not declare a document type'):
                check_results.junit_results(self.directory / 'junitreport.xml')

    def test_a_document_type_written_in_utf_16_is_refused(self):
        report = ('<!DOCTYPE testsuite [<!ENTITY a "expanded">]><testsuite>'
                  '<testcase classname="tests.compatibility.card" name="&a;"/></testsuite>')
        for encoding in ('utf-16', 'utf-16-le', 'utf-16-be'):
            (self.directory / 'junitreport.xml').write_bytes(report.encode(encoding))
            with self.subTest(encoding=encoding), self.assertRaisesRegex(ValueError, 'hold a NUL byte'):
                check_results.junit_results(self.directory / 'junitreport.xml')

    def test_a_report_in_another_single_byte_encoding_is_still_read(self):
        (self.directory / 'junitreport.xml').write_bytes(
            '<?xml version="1.0" encoding="iso-8859-1"?><testsuite>'
            '<testcase classname="tests.compatibility.card" name="test_get"><failure message="naïve"/></testcase>'
            '</testsuite>'.encode('iso-8859-1'))
        parsed = check_results.junit_results(self.directory / 'junitreport.xml')
        self.assertEqual(parsed, {'card::test_get': Result('fail', 'naïve')})

    def test_a_long_message_is_cut_at_the_limit(self):
        self.assertEqual(check_results.short('x' * check_results.MESSAGE_LIMIT), 'x' * check_results.MESSAGE_LIMIT)
        self.assertEqual(check_results.short('x' * (check_results.MESSAGE_LIMIT + 1)),
                         'x' * check_results.MESSAGE_LIMIT + '...')

    def test_probe_results_are_scored_with_the_suite_results(self):
        (self.directory / 'junitreport.xml').write_text(JUNIT)
        (self.directory / 'probes.json').write_text(json.dumps(SLASH_PROBE))
        loaded = check_results.load_results(self.directory)
        self.assertEqual(loaded['harness.entry_point::accepts_trailing_slash'], Result('fail', 'HTTP 404'))
        self.assertEqual(len(loaded), 6)

    def test_a_suite_run_in_parts_is_read_as_one(self):
        (self.directory / 'junit-mandatory.xml').write_text(f'<testsuite>{testcase("test_a")}</testsuite>')
        (self.directory / 'junit-capabilities.xml').write_text(f'<testsuite>{testcase("test_b", "fail")}</testsuite>')
        (self.directory / 'probes.json').write_text(NO_PROBES)
        loaded = check_results.load_results(self.directory)
        self.assertEqual({test: result.outcome for test, result in loaded.items()},
                         {'card::test_a': 'pass', 'card::test_b': 'fail'})

    def test_missing_or_empty_results_are_errors(self):
        with self.assertRaises(FileNotFoundError):
            check_results.load_results(self.directory)
        (self.directory / 'junitreport.xml').write_text('<testsuite/>')
        with self.assertRaises(ValueError):
            check_results.load_results(self.directory)

    def test_missing_probe_results_or_an_unknown_probe_outcome_are_errors(self):
        (self.directory / 'junitreport.xml').write_text(JUNIT)
        with self.assertRaises(FileNotFoundError):
            check_results.load_results(self.directory)
        (self.directory / 'probes.json').write_text(json.dumps([{'test': 'harness.x::y', 'outcome': 'maybe'}]))
        with self.assertRaises(ValueError):
            check_results.load_results(self.directory)

    def test_probe_results_of_the_wrong_shape_are_errors(self):
        (self.directory / 'junitreport.xml').write_text(JUNIT)
        for text in ('not json', '{}', '[1]', '[{"outcome": "pass"}]', '[{"test": 7, "outcome": "pass"}]',
                     '[{"test": "harness.x::y", "outcome": ["pass"]}]',
                     '[{"test": "harness.x::y", "outcome": "fail", "message": 404}]'):
            (self.directory / 'probes.json').write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_results.load_results(self.directory)


class AgentScoring(unittest.TestCase):
    def test_a_listed_failure_is_expected_and_a_skip_is_not_a_failure(self):
        direct = results(a='pass', b='fail', c='skip')
        listed, unlisted, stale = check_results.score(True, direct, direct, {'b': Expected(('fail',), 'agent bug')})
        self.assertEqual([item.test for item in listed], ['b'])
        self.assertEqual((unlisted, stale), ([], []))

    def test_an_unlisted_failure_and_a_listed_test_that_now_passes_both_fail_the_run(self):
        direct = results(a='pass', b='fail')
        listed, unlisted, stale = check_results.score(True, direct, direct, {'a': Expected(('fail',), 'old')})
        self.assertEqual(listed, [])
        self.assertEqual([item.test for item in unlisted], ['b'])
        self.assertEqual(stale, ['a: listed as fail, but it no longer differs'])

    def test_an_agent_target_is_scored_on_its_failures_not_on_how_it_differs_from_direct(self):
        direct = results(a='pass', b='pass', c='fail')
        proxy = results(a='skip', b='fail', c='pass')
        listed, unlisted, stale = check_results.score(True, proxy, direct, {})
        self.assertEqual([(item.test, item.result.outcome) for item in unlisted], [('b', 'fail')])
        self.assertEqual((listed, stale), ([], []))


class GatewayScoring(unittest.TestCase):
    DIRECT = results(a='pass', b='fail', c='pass', d='skip')

    def test_a_failure_the_agent_has_on_its_own_does_not_count_against_the_gateway(self):
        gateway = results(a='pass', b='fail', c='pass', d='skip')
        self.assertEqual(check_results.score(False, gateway, self.DIRECT, {}), ([], [], []))

    def test_a_test_that_passes_directly_and_is_skipped_through_the_gateway_is_a_difference(self):
        gateway = results(a='skip', b='fail', c='pass', d='skip')
        listed, unlisted, stale = check_results.score(False, gateway, self.DIRECT, {})
        self.assertEqual([(item.test, item.direct, item.result.outcome) for item in unlisted], [('a', 'pass', 'skip')])
        self.assertEqual((listed, stale), ([], []))

    def test_a_listed_difference_passes_only_with_the_listed_outcome(self):
        gateway = results(a='fail', b='fail', c='pass', d='skip')
        listed, unlisted, stale = check_results.score(False, gateway, self.DIRECT, {'a': Expected(('fail',), 'why')})
        self.assertEqual(([item.reason for item in listed], unlisted, stale), (['why'], [], []))
        listed, unlisted, stale = check_results.score(False, gateway, self.DIRECT, {'a': Expected(('skip',), 'why')})
        self.assertEqual(listed, [])
        self.assertEqual([item.test for item in unlisted], ['a'])
        self.assertEqual(stale, ['a: listed as skip, but it is now fail'])

    def test_an_entry_whose_outcome_depends_on_timing_accepts_each_listed_outcome(self):
        either = {'a': Expected(('skip', 'fail'), 'buffered stream')}
        for outcome in ('skip', 'fail'):
            gateway = results(a=outcome, b='fail', c='pass', d='skip')
            listed, unlisted, stale = check_results.score(False, gateway, self.DIRECT, either)
            self.assertEqual(([item.test for item in listed], unlisted, stale), (['a'], [], []))
        gateway = results(a='xfail', b='fail', c='pass', d='skip')
        _, unlisted, stale = check_results.score(False, gateway, self.DIRECT, either)
        self.assertEqual([item.test for item in unlisted], ['a'])
        self.assertEqual(stale, ['a: listed as skip or fail, but it is now xfail'])

    def test_a_test_the_gateway_fixes_loses_or_adds_is_a_difference_too(self):
        gateway = results(a='pass', b='pass', d='skip', e='pass')
        _, unlisted, _ = check_results.score(False, gateway, self.DIRECT, {})
        self.assertEqual([(item.test, item.direct, item.result.outcome) for item in unlisted],
                         [('b', 'fail', 'pass'), ('c', 'pass', 'absent'), ('e', 'absent', 'pass')])

    def test_the_same_outcome_for_another_reason_is_a_difference(self):
        for outcome in ('fail', 'skip', 'xfail'):
            direct = {'a': Result(outcome, 'the agent accepts an unsupported media type')}
            gateway = {'a': Result(outcome, 'HTTP 500 from the gateway')}
            with self.subTest(outcome=outcome):
                listed, unlisted, stale = check_results.score(False, gateway, direct, {})
                self.assertEqual([(item.test, item.direct, item.result.outcome, item.direct_message) for item in unlisted],
                                 [('a', outcome, outcome, 'the agent accepts an unsupported media type')])
                self.assertEqual((listed, stale), ([], []))

    def test_the_same_outcome_with_the_same_message_is_not_a_difference(self):
        task = ('Task {} of {} is in terminal state: completed, <function is_success at {}>, '
                '400 Bad Request for url: {} and "{}", at {}: refused')
        directly = task.format('daeea35f-f00f-43d2-9109-9a0db0db13f9', 'tck-complete-task-3fa9c1b2', '0x10beb33d0',
                               'http://127.0.0.1:18860', '127.0.0.1:18860/', 'localhost:18860')
        forwarded = task.format('4EC59245-93D9-4C19-BBD7-6656797736C7', 'tck-complete-task-9d00aa11', '0x7f3a6c0',
                                'http://127.0.0.1:18870/conformance/a2a', 'localhost:18871/transit/conformance-a2a/',
                                'localhost:18870/conformance/a2a')
        skipped = Result('skip', 'Streaming is not supported')
        direct = {'a': Result('fail', directly), 'b': skipped, 'c': Result('pass', 'HTTP 200')}
        gateway = {'a': Result('fail', forwarded), 'b': skipped, 'c': Result('pass', 'HTTP 200 after a redirect')}
        self.assertEqual(check_results.score(False, gateway, direct, {}), ([], [], []))

    def test_what_is_masked_in_a_message_leaves_the_rest_to_compare(self):
        for direct, gateway in (('expected -32005, got -32602', 'expected -32005, got -32603'),
                                ('HTTP 400 for url: http://127.0.0.1:18860', 'HTTP 500 for url: http://127.0.0.1:18870/conformance/a2a'),
                                ('size 10x20', 'size 10x99'),
                                ('http://127.0.0.1:1/a?code=400', 'http://127.0.0.1:2/b?code=500'),
                                ('{url: http://127.0.0.1:1/a}; error 400', '{url: http://127.0.0.1:2/b}; error 500'),
                                ('notlocalhost:1 refused', 'notlocalhost:2 refused'),
                                ('Task tck-complete-task-3fa9c1b2 not found', 'Task tck-cancel-task-9d00aa11 was refused'),
                                ('', 'HTTP 500')):
            with self.subTest(direct=direct):
                unlisted = check_results.score(False, {'a': Result('fail', gateway)}, {'a': Result('fail', direct)}, {})[1]
                self.assertEqual([item.direct_message for item in unlisted], [direct])

    def test_the_direct_message_is_kept_only_for_a_test_with_the_same_outcome(self):
        unlisted = check_results.score(False, {'a': Result('fail', 'HTTP 500')}, {'a': Result('skip', 'no streaming')}, {})[1]
        self.assertEqual([(item.direct, item.direct_message) for item in unlisted], [('skip', None)])

    def test_a_message_is_compared_whole_not_as_it_is_shown(self):
        padding = 'x' * (check_results.MESSAGE_LIMIT - 10)
        direct = {'a': Result('fail', f'{padding} daeea35f-f00f-43d2-9109-9a0db0db13f9 then the agent refused')}
        same = {'a': Result('fail', f'{padding} 4ec59245-93d9-4c19-bbd7-6656797736c7 then the agent refused')}
        other = {'a': Result('fail', f'{padding} 4ec59245-93d9-4c19-bbd7-6656797736c7 then the gateway refused')}
        self.assertEqual(check_results.score(False, same, direct, {}), ([], [], []))
        self.assertEqual([item.test for item in check_results.score(False, other, direct, {})[1]], ['a'])

    def test_a_listed_difference_of_reason_passes_until_the_reasons_agree_again(self):
        direct = {'a': Result('fail', 'the agent accepts an unsupported media type')}
        entry = {'a': Expected(('fail',), 'the gateway refuses the part first')}
        listed, unlisted, stale = check_results.score(False, {'a': Result('fail', 'HTTP 415 from the gateway')}, direct, entry)
        self.assertEqual(([item.reason for item in listed], unlisted, stale), (['the gateway refuses the part first'], [], []))
        listed, unlisted, stale = check_results.score(False, direct, direct, entry)
        self.assertEqual((listed, unlisted, stale), ([], [], ['a: listed as fail, but it no longer differs']))

    def test_an_agent_target_is_not_scored_on_the_reason_of_a_listed_failure(self):
        direct = {'a': Result('fail', 'the agent accepts an unsupported media type')}
        proxy = {'a': Result('fail', 'got -32602')}
        listed, unlisted, stale = check_results.score(True, proxy, direct, {'a': Expected(('fail',), 'InvalidParams')})
        self.assertEqual(([(item.test, item.direct_message) for item in listed], unlisted, stale), ([('a', None)], [], []))


class Baselines(unittest.TestCase):
    ENTRY = '[[expected]]\ntest = "a"\noutcome = "fail"\nreason = "r"\n'

    def load(self, text: str, is_agent: bool = False) -> Baseline:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'target.toml'
            path.write_text(text)
            return check_results.load_baseline(path, is_agent)

    def test_reads_entries_and_treats_a_missing_forwarding_baseline_as_empty(self):
        loaded = self.load('[[expected]]\ntest = "a"\noutcome = "skip"\nreason = "buffered stream"\n')
        self.assertEqual(loaded, Baseline({'a': Expected(('skip',), 'buffered stream')}))
        self.assertEqual(check_results.load_baseline(Path('/nonexistent/target.toml'), False), Baseline())

    def test_an_outcome_can_be_a_list(self):
        loaded = self.load('[[expected]]\ntest = "a"\noutcome = ["skip", "fail"]\nreason = "timing"\n')
        self.assertEqual(loaded.expected, {'a': Expected(('skip', 'fail'), 'timing')})

    def test_one_entry_can_name_several_tests_that_share_a_reason(self):
        loaded = self.load('[[expected]]\ntests = ["a", "b"]\noutcome = "skip"\nreason = "buffered stream"\n')
        shared = Expected(('skip',), 'buffered stream')
        self.assertEqual(loaded.expected, {'a': shared, 'b': shared})

    def test_refuses_an_entry_without_a_reason_an_unknown_outcome_or_a_duplicate(self):
        for text in (
            '[[expected]]\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntest = "a"\ntests = ["b"]\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntests = ["a", "a"]\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntests = "ab"\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = "fail"\n',
            '[[expected]]\ntest = "a"\noutcome = "fail"\nreason = "  "\n',
            '[[expected]]\ntest = "a"\noutcome = "broken"\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = ["fail", "broken"]\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = []\nreason = "r"\n',
            self.ENTRY + self.ENTRY,
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_refuses_a_baseline_of_the_wrong_shape(self):
        for text in (
            'expected = "a"\n',
            'expected = [1]\n',
            '[expected]\ntest = "a"\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = "fail"\nreason = 5\n',
            '[[expected]]\ntest = 5\noutcome = "fail"\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = 5\nreason = "r"\n',
            '[[expected]]\ntest = "a"\noutcome = [["fail"]]\nreason = "r"\n',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_an_agent_baseline_sets_passed_and_lists_failures_only(self):
        self.assertEqual(self.load('passed = 7\n' + self.ENTRY, is_agent=True),
                         Baseline({'a': Expected(('fail',), 'r')}, 7))
        with self.assertRaises(ValueError):
            self.load('passed = 7\n' + self.ENTRY.replace('"fail"', '"skip"'), is_agent=True)
        with self.assertRaises(FileNotFoundError):
            check_results.load_baseline(Path('/nonexistent/target.toml'), True)

    def test_a_baseline_refuses_a_key_it_does_not_know(self):
        for text, is_agent in (('passed = 7\nminimum_passed = 5\n', True), ('pased = 7\n', False),
                               ('[[expect]]\ntest = "a"\noutcome = "fail"\nreason = "r"\n', False)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text, is_agent=is_agent)

    def test_an_agent_baseline_refuses_a_pass_count_that_would_check_nothing(self):
        for text in (
            self.ENTRY,
            'passed = "7"\n',
            'passed = 7.0\n',
            'passed = true\n',
            'passed = 0\n',
            'passed = -1\n',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text, is_agent=True)

    def test_a_forwarding_baseline_must_not_set_passed(self):
        with self.assertRaises(ValueError):
            self.load('passed = 7\n')


class Main(unittest.TestCase):
    LISTED = '[[expected]]\ntest = "card::test_etag"\noutcome = "fail"\nreason = "the gateway rebuilds the card"\n'

    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.work / 'expected').mkdir()
        self.baseline('direct', 'passed = 1\n')

    def baseline(self, target: str, text: str) -> None:
        (self.work / 'expected' / f'{target}.toml').write_text(text)

    def suite(self, target: str, *cases: str) -> None:
        directory = self.work / 'results' / target
        directory.mkdir(parents=True)
        (directory / 'junitreport.xml').write_text(f'<testsuite>{"".join(cases)}</testsuite>')
        (directory / 'probes.json').write_text(NO_PROBES)

    def main(self, targets: str, *extra: str) -> tuple[int, str]:
        output = io.StringIO()
        original = sys.argv
        sys.argv = ['check_results.py', '--results', str(self.work / 'results'), '--expected', str(self.work / 'expected'),
                    '--targets', targets, *extra]
        try:
            with contextlib.redirect_stdout(output):
                code = check_results.main()
        finally:
            sys.argv = original
        return code, output.getvalue()

    def proxy(self, passed: int, *cases: str) -> tuple[int, str]:
        self.baseline('direct', 'passed = 2\n')
        self.suite('direct', testcase('test_etag'), testcase('test_get'))
        self.suite('a2a-proxy', *cases)
        self.baseline('a2a-proxy', f'passed = {passed}\n' + self.LISTED)
        return self.main('direct,a2a-proxy', '--agents', 'a2a-proxy')

    def access_point(self, outcome: str, baseline: str, *extra: str) -> tuple[int, str]:
        self.suite('direct', testcase('test_etag'))
        self.suite('access-point', testcase('test_etag', outcome))
        self.baseline('access-point', baseline)
        return self.main('direct,access-point', *extra)

    def test_passes_when_every_difference_is_listed(self):
        code, output = self.access_point('fail', self.LISTED)
        self.assertEqual(code, 0)
        self.assertIn('PASS  access-point: 0 passed, 1 failed, 0 skipped, 0 xfail; 1 expected difference(s) from direct', output)

    def test_fails_and_names_the_test_when_a_difference_is_not_listed(self):
        code, output = self.access_point('fail', '')
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point', output)
        self.assertIn('not in the baseline: card::test_etag (pass -> fail): no ETag', output)

    def test_a_failing_target_fails_the_run_whatever_the_targets_after_it_do(self):
        self.suite('direct', testcase('test_etag'))
        self.suite('access-point', testcase('test_etag', 'fail'))
        self.suite('transit', testcase('test_etag'))
        code, output = self.main('direct,access-point,transit')
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point', output)
        self.assertIn('PASS  transit', output)

    def test_a_failure_the_agent_has_on_its_own_is_counted_apart_from_the_differences(self):
        self.baseline('direct', 'passed = 1\n' + self.LISTED)
        self.suite('direct', testcase('test_etag', 'fail'), testcase('test_get'))
        self.suite('access-point', testcase('test_etag', 'fail'), testcase('test_get'))
        code, output = self.main('direct,access-point')
        self.assertEqual(code, 0)
        self.assertIn('PASS  access-point: 1 passed, 1 failed, 0 skipped, 0 xfail; '
                      '0 expected difference(s) from direct; 1 fail without the gateway too', output)

    def other_reason(self, direct: str, gateway: str, baseline: str = '', *extra: str) -> tuple[int, str]:
        failure = '<testcase classname="tests.compatibility.card" name="test_etag"><failure message="{}"/></testcase>'
        self.baseline('direct', 'passed = 1\n' + self.LISTED)
        self.suite('direct', failure.format(direct), testcase('test_get'))
        self.suite('access-point', failure.format(gateway), testcase('test_get'))
        self.baseline('access-point', baseline)
        return self.main('direct,access-point', *extra)

    def test_fails_when_a_test_fails_both_ways_for_another_reason(self):
        limit = check_results.MESSAGE_LIMIT
        code, output = self.other_reason('no ETag ' + 'y' * limit, 'HTTP 500 ' + 'x' * limit)
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point: 1 passed, 1 failed, 0 skipped, 0 xfail; '
                      '0 expected difference(s) from direct; 0 fail without the gateway too', output)
        gateway = 'HTTP 500 ' + 'x' * (limit - len('HTTP 500 ')) + '...'
        direct = 'no ETag ' + 'y' * (limit - len('no ETag ')) + '...'
        self.assertIn(f'not in the baseline: card::test_etag {BOTH_WAYS}: {gateway} (directly: {direct})', output)

    def test_passes_when_the_other_reason_is_listed_and_reports_both_messages(self):
        limit = check_results.MESSAGE_LIMIT
        report = self.work / 'gaps.md'
        direct, gateway = 'no ETag ' + 'y' * limit, 'HTTP 500 ' + 'x' * limit
        code, output = self.other_reason(direct, gateway, self.LISTED, '--report', str(report))
        self.assertEqual(code, 0)
        self.assertIn('PASS  access-point: 1 passed, 1 failed, 0 skipped, 0 xfail; 1 expected difference(s) from direct', output)
        text = report.read_text()
        self.assertIn('  - direct run: fail; this target: fail, for another reason\n', text)
        self.assertIn('  - suite message: HTTP 500 ' + 'x' * (limit - len('HTTP 500 ')) + '...\n', text)
        self.assertIn('  - suite message of the direct run: no ETag ' + 'y' * (limit - len('no ETag ')) + '...\n', text)
        self.assertIn('  - cause: the gateway rebuilds the card', text)

    def test_messages_that_part_beyond_what_is_shown_are_shown_from_where_they_part(self):
        limit, context = check_results.MESSAGE_LIMIT, check_results.PARTING_CONTEXT
        start = 'x' * limit + ' task daeea35f-f00f-43d2-9109-9a0db0db13f9 ' + 'y' * context
        code, output = self.other_reason(start + 'the agent refused', start + 'the gateway refused')
        self.assertEqual(code, 1)
        lead = '...' + 'y' * (context - len('the '))
        self.assertIn(f'{BOTH_WAYS}: {lead}the gateway refused (directly: {lead}the agent refused)', output)

    def test_a_message_that_goes_on_where_the_other_ends_is_shown_from_there(self):
        limit, context = check_results.MESSAGE_LIMIT, check_results.PARTING_CONTEXT
        start = 'x' * limit + 'y' * context
        code, output = self.other_reason(start, start + ' and then the gateway refused')
        self.assertEqual(code, 1)
        lead = '...' + 'y' * context
        self.assertIn(f'{BOTH_WAYS}: {lead} and then the gateway refused (directly: {lead})', output)

    def test_messages_are_shown_as_they_are_compared(self):
        urls = ' '.join(f'http://127.0.0.1:1886{digit}/conformance/a2a/v1/tasks' for digit in range(10))
        code, output = self.other_reason(f'{urls} got 400', f'{urls.replace("/conformance/a2a", "")} got 500')
        self.assertEqual(code, 1)
        stars = ' '.join('*' * 10)
        self.assertIn(f'{BOTH_WAYS}: {stars} got 500 (directly: {stars} got 400)', output)

    def test_a_direct_failure_with_no_message_is_shown_as_such(self):
        code, output = self.other_reason('', 'HTTP 500')
        self.assertEqual(code, 1)
        self.assertIn(f'card::test_etag {BOTH_WAYS}: HTTP 500 (directly: no message)', output)

    def test_fails_on_a_baseline_entry_that_no_longer_applies(self):
        code, output = self.access_point('pass', self.LISTED)
        self.assertEqual(code, 1)
        self.assertIn('stale baseline entry: card::test_etag: listed as fail, but it no longer differs', output)

    def test_report_mode_writes_the_differences_and_exits_zero(self):
        report = self.work / 'gaps.md'
        code, output = self.access_point('fail', '', '--report', str(report))
        self.assertEqual(code, 0)
        self.assertIn('FAIL  access-point', output)
        self.assertIn('### Not in the baseline', report.read_text())
        self.assertIn('direct run: pass; this target: fail', report.read_text())

    def test_report_mode_still_fails_on_a_baseline_it_cannot_read(self):
        report = self.work / 'gaps.md'
        code, output = self.access_point('fail', '[[expected]]\ntest = "card::test_etag"\n', '--report', str(report))
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point', output)
        self.assertFalse(report.exists())

    def test_an_agent_target_passes_on_its_listed_failures_whatever_direct_does(self):
        code, output = self.proxy(1, testcase('test_etag', 'fail'), testcase('test_get'))
        self.assertEqual(code, 0)
        self.assertIn('PASS  a2a-proxy: 1 passed, 1 failed, 0 skipped, 0 xfail; 1 expected failure(s)', output)

    def test_an_agent_target_fails_when_fewer_tests_pass_than_its_baseline_records(self):
        code, output = self.proxy(2, testcase('test_etag', 'fail'), testcase('test_get'))
        self.assertEqual(code, 1)
        self.assertIn('FAIL  a2a-proxy', output)
        self.assertIn('1 tests passed where the baseline records passed = 2', output)

    def test_an_agent_target_fails_when_a_passing_test_is_skipped(self):
        skipped = '<testcase classname="tests.compatibility.card" name="test_get"><skipped message="timed out"/></testcase>'
        code, output = self.proxy(1, testcase('test_etag', 'fail'), skipped)
        self.assertEqual(code, 1)
        self.assertIn('0 tests passed where the baseline records passed = 1', output)

    def test_an_agent_target_fails_when_a_passing_test_becomes_an_expected_failure_of_the_suite(self):
        xfail = ('<testcase classname="tests.compatibility.card" name="test_get">'
                 '<skipped type="pytest.xfail" message="SHOULD not met"/></testcase>')
        code, output = self.proxy(1, testcase('test_etag', 'fail'), xfail)
        self.assertEqual(code, 1)
        self.assertIn('FAIL  a2a-proxy: 0 passed, 1 failed, 0 skipped, 1 xfail', output)
        self.assertIn('0 tests passed where the baseline records passed = 1', output)

    def test_an_agent_target_fails_when_more_tests_pass_than_its_baseline_records(self):
        code, output = self.proxy(1, testcase('test_etag', 'fail'), testcase('test_get'), testcase('test_list'))
        self.assertEqual(code, 1)
        self.assertIn('2 tests passed where the baseline records passed = 1', output)

    def test_report_mode_lists_a_pass_count_mismatch_and_exits_zero(self):
        report = self.work / 'gaps.md'
        self.baseline('direct', 'passed = 2\n')
        self.suite('direct', testcase('test_etag'), testcase('test_get'))
        self.suite('a2a-proxy', testcase('test_etag', 'fail'), testcase('test_get'))
        self.baseline('a2a-proxy', 'passed = 2\n' + self.LISTED)
        code, output = self.main('direct,a2a-proxy', '--agents', 'a2a-proxy', '--report', str(report))
        self.assertEqual(code, 0)
        self.assertIn('FAIL  a2a-proxy', output)
        self.assertIn('1 tests passed where the baseline records passed = 2', report.read_text())

    def test_an_unreadable_direct_run_fails_without_scoring_the_other_targets(self):
        self.suite('access-point', testcase('test_etag'))
        code, output = self.main('direct,access-point')
        self.assertEqual(code, 1)
        self.assertIn('FAIL  direct: no suite results', output)
        self.assertNotIn('access-point:', output)

    def test_direct_results_that_cannot_be_parsed_fail_the_run_in_both_modes(self):
        self.suite('access-point', testcase('test_etag'))
        directory = self.work / 'results' / 'direct'
        directory.mkdir(parents=True)
        (directory / 'junitreport.xml').write_text('<testsuite><testcase')
        (directory / 'probes.json').write_text(NO_PROBES)
        report = self.work / 'gaps.md'
        for extra in ((), ('--report', str(report))):
            with self.subTest(extra=extra):
                code, output = self.main('direct,access-point', *extra)
                self.assertEqual(code, 1)
                self.assertIn('FAIL  direct:', output)
                self.assertNotIn('access-point:', output)
                self.assertFalse(report.exists())

    def test_a_report_that_declares_a_document_type_is_reported_not_raised(self):
        self.suite('direct', testcase('test_etag'))
        directory = self.work / 'results' / 'access-point'
        directory.mkdir(parents=True)
        (directory / 'junitreport.xml').write_text(
            f'<!DOCTYPE testsuite [<!ENTITY a "x">]><testsuite>{testcase("test_etag")}</testsuite>')
        (directory / 'probes.json').write_text(NO_PROBES)
        code, output = self.main('direct,access-point')
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point:', output)
        self.assertIn('must not declare a document type', output)

    def test_a_baseline_of_the_wrong_shape_is_reported_not_raised(self):
        code, output = self.access_point('fail', 'expected = "card::test_etag"\n')
        self.assertEqual(code, 1)
        self.assertIn('FAIL  access-point:', output)
        self.assertIn('expected must be a list of [[expected]] entries', output)

    def test_the_direct_target_is_required(self):
        code, output = self.main('access-point')
        self.assertEqual(code, 1)
        self.assertIn('the direct target is required', output)


if __name__ == '__main__':
    unittest.main()
