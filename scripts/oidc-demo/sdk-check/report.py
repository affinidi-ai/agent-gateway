#!/usr/bin/env python3
"""Judges the SDK card-parse results and prints a table.

Usage: report.py [--expect SUMMARY.json] [--expected-failures FILE] TARGET=RESULTS.jsonl ...

Each results file holds one JSON line per SDK run (see check_py.py and check_js.mjs). A run passes
when the SDK parsed the card, the card is internally consistent, and, with --expect, the parsed
summary equals the expected one. A failing run must be listed in the expected-failures file with
its target, SDK, version and mode and a substring of the observed problem; an unlisted failure, a
listed failure with a different problem, and a listed failure that now passes all exit non-zero.
"""

import argparse
import json
import sys

SEMANTIC_KEYS = ("name", "interfaces", "schemes", "requirements")


def consistency_problems(summary):
    problems = []
    if not summary.get("name"):
        problems.append("card name is empty")
    interfaces = summary.get("interfaces") or []
    if not interfaces or not all(interfaces):
        problems.append(f"interface urls are missing: {interfaces}")
    schemes = summary.get("schemes") or {}
    for requirement in summary.get("requirements") or []:
        for name in requirement:
            if name not in schemes:
                problems.append(f"requirement names unknown scheme {name}")
    return problems


def judge(result, expected=None):
    if not result.get("ok"):
        return result.get("error", "parse failed")
    summary = result["summary"]
    problems = consistency_problems(summary)
    if expected is not None:
        for key in SEMANTIC_KEYS:
            if summary.get(key) != expected.get(key):
                problems.append(f"{key} is {json.dumps(summary.get(key), sort_keys=True)}, expected {json.dumps(expected.get(key), sort_keys=True)}")
    return "; ".join(problems) or None


def run_key(target, result):
    return (target, result["sdk"], result["version"], result["mode"])


def entry_key(entry):
    return (entry["target"], entry["sdk"], entry["version"], entry["mode"])


def classify(runs, expected_failures, expected):
    listed = {entry_key(e): e for e in expected_failures}
    seen = set()
    rows = []
    for target, result in runs:
        key = run_key(target, result)
        problem = judge(result, expected)
        entry = listed.get(key)
        seen.add(key)
        if problem is None:
            status = "STALE" if entry else "PASS"
            detail = "listed as an expected failure but passes" if entry else result["summary"].get("schemeShape") or ""
        elif entry and entry["match"] in problem:
            status, detail = "EXPECTED-FAIL", entry["reason"]
        else:
            status, detail = "FAIL", problem
        rows.append((status, key, detail))
    for key, entry in listed.items():
        if key not in seen and key[0] in {t for t, _ in runs}:
            rows.append(("STALE", key, "listed as an expected failure but did not run"))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect")
    parser.add_argument("--expected-failures")
    parser.add_argument("targets", nargs="+")
    args = parser.parse_args(argv)

    expected = json.load(open(args.expect)) if args.expect else None
    expected_failures = json.load(open(args.expected_failures)) if args.expected_failures else []
    runs = []
    for spec in args.targets:
        target, _, path = spec.partition("=")
        with open(path) as handle:
            runs.extend((target, json.loads(line)) for line in handle if line.strip())

    rows = classify(runs, expected_failures, expected)
    for status, (target, sdk, version, mode), detail in rows:
        print(f"{status:<13} {target:<10} {sdk} {version} [{mode}] {detail}")
    bad = [r for r in rows if r[0] in ("FAIL", "STALE")]
    counts = {s: sum(1 for r in rows if r[0] == s) for s in ("PASS", "EXPECTED-FAIL", "FAIL", "STALE")}
    print(f"\n{counts['PASS']} passed, {counts['EXPECTED-FAIL']} expected failures, {counts['FAIL']} unexpected failures, {counts['STALE']} stale entries")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
