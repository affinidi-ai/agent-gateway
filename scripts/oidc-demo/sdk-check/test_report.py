import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

SUMMARY = {
    "name": "A",
    "interfaces": ["https://h/a"],
    "schemes": {"s": {"type": "oauth2", "metadataUrl": "https://m", "flows": ["clientCredentials"], "scopes": ["x"]}},
    "requirements": [{"s": ["x"]}],
}


def result(summary=None, ok=True, error=None, sdk="a2a-python", version="1.2.2", mode="default"):
    r = {"sdk": sdk, "version": version, "mode": mode, "ok": ok}
    if ok:
        r["summary"] = SUMMARY if summary is None else summary
    else:
        r["error"] = error
    return r


class JudgeTests(unittest.TestCase):
    def test_matching_summary_passes(self):
        self.assertIsNone(report.judge(result(), SUMMARY))

    def test_parse_error_is_returned_verbatim(self):
        self.assertEqual(report.judge(result(ok=False, error="Boom: bad"), SUMMARY), "Boom: bad")

    def test_empty_interface_is_reported(self):
        broken = dict(SUMMARY, interfaces=[""])
        self.assertIn("interface urls are missing", report.judge(result(broken)))

    def test_requirement_for_unknown_scheme_is_reported(self):
        broken = dict(SUMMARY, requirements=[{"other": ["x"]}])
        self.assertIn("requirement names unknown scheme other", report.judge(result(broken)))

    def test_semantic_difference_is_reported(self):
        other = dict(SUMMARY, schemes={"s": dict(SUMMARY["schemes"]["s"], metadataUrl=None)})
        self.assertIn("schemes is", report.judge(result(other), SUMMARY))

    def test_without_expectation_only_consistency_is_checked(self):
        self.assertIsNone(report.judge(result(), None))


class ClassifyTests(unittest.TestCase):
    ENTRY = {"target": "t", "sdk": "a2a-python", "version": "0.3.25", "mode": "default", "match": "Field required", "reason": "no url"}

    def test_unlisted_failure_is_a_failure(self):
        rows = report.classify([("t", result(ok=False, error="x"))], [], SUMMARY)
        self.assertEqual(rows[0][0], "FAIL")

    def test_listed_failure_with_matching_problem_is_expected(self):
        run = result(ok=False, error="Field required: url", version="0.3.25")
        rows = report.classify([("t", run)], [self.ENTRY], SUMMARY)
        self.assertEqual((rows[0][0], rows[0][2]), ("EXPECTED-FAIL", "no url"))

    def test_listed_failure_with_other_problem_is_a_failure(self):
        run = result(ok=False, error="Timeout", version="0.3.25")
        self.assertEqual(report.classify([("t", run)], [self.ENTRY], SUMMARY)[0][0], "FAIL")

    def test_listed_failure_that_passes_is_stale(self):
        run = result(version="0.3.25")
        self.assertEqual(report.classify([("t", run)], [self.ENTRY], SUMMARY)[0][0], "STALE")

    def test_listed_failure_that_did_not_run_is_stale(self):
        rows = report.classify([("t", result())], [self.ENTRY], SUMMARY)
        self.assertEqual([r[0] for r in rows], ["PASS", "STALE"])

    def test_entry_for_another_target_is_ignored(self):
        entry = dict(self.ENTRY, target="other")
        self.assertEqual([r[0] for r in report.classify([("t", result())], [entry], SUMMARY)], ["PASS"])


if __name__ == "__main__":
    unittest.main()
