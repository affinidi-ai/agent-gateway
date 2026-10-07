#!/usr/bin/env python3
"""Validate .changelog/wip/*.yaml fragments.

Contributors can run this locally to self-check the changelog-fragment rule
described in CONTRIBUTING.md, without needing the internal release tooling:

    python3 .github/scripts/check_changelog_fragments.py

It checks that every work-in-progress fragment parses as YAML and has the
expected shape. It does NOT generate CHANGELOG.md (that happens at release).
"""
from __future__ import annotations

import glob
import sys
from datetime import datetime

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

BUCKETS = {"added", "changed", "fixed", "removed", "security", "breaking"}
REQUIRED_ENTRY_KEYS = {"title", "description"}


def check(path: str) -> list[str]:
    errors: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return [f"{path}: invalid YAML: {exc}"]

    if not isinstance(data, dict):
        return [f"{path}: top level must be a mapping"]
    if not isinstance(data.get("branch"), str) or not data["branch"].strip():
        errors.append(f"{path}: 'branch' must be a non-empty string")
    if "changes" not in data or not isinstance(data["changes"], dict):
        errors.append(f"{path}: missing 'changes' mapping")
        return errors

    unknown = set(data["changes"]) - BUCKETS
    if unknown:
        errors.append(f"{path}: unknown change buckets: {sorted(unknown)}")
    missing_buckets = BUCKETS - set(data["changes"])
    if missing_buckets:
        errors.append(f"{path}: missing change buckets: {sorted(missing_buckets)}")

    for bucket, entries in data["changes"].items():
        if entries is None:
            continue
        if not isinstance(entries, list):
            errors.append(f"{path}: '{bucket}' must be a list")
            continue
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                errors.append(f"{path}: {bucket}[{i}] must be a mapping")
                continue
            missing = REQUIRED_ENTRY_KEYS - set(entry)
            if missing:
                errors.append(f"{path}: {bucket}[{i}] missing keys {sorted(missing)}")
                continue
            title = entry["title"]
            description = entry["description"]
            timestamp = entry.get("timestamp")
            if timestamp is None:
                errors.append(f"{path}: {bucket}[{i}] missing key 'timestamp'")
            elif not isinstance(timestamp, str) or not timestamp.strip():
                errors.append(f"{path}: {bucket}[{i}] timestamp must be an RFC 3339 string")
            else:
                try:
                    parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"{path}: {bucket}[{i}] timestamp must be an RFC 3339 string")
                else:
                    if "T" not in timestamp or parsed_timestamp.tzinfo is None:
                        errors.append(f"{path}: {bucket}[{i}] timestamp must be an RFC 3339 string")
            if not isinstance(title, str) or not title.strip():
                errors.append(f"{path}: {bucket}[{i}] title must be a non-empty string")
            elif len(title) > 80:
                errors.append(f"{path}: {bucket}[{i}] title must be 80 characters or less")
            if not isinstance(description, str) or not description.strip():
                errors.append(f"{path}: {bucket}[{i}] description must be a non-empty string")
    return errors


def main() -> int:
    fragments = sys.argv[1:] or sorted(glob.glob(".changelog/wip/*.yaml"))
    if not fragments:
        print("No .changelog/wip/*.yaml fragments found — nothing to validate.")
        return 0

    all_errors: list[str] = []
    for path in fragments:
        all_errors.extend(check(path))

    if all_errors:
        for err in all_errors:
            print(f"::error::{err}")
        print(f"\n{len(all_errors)} problem(s) in changelog fragments.")
        return 1

    print(f"OK — {len(fragments)} changelog fragment(s) valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
