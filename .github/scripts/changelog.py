#!/usr/bin/env python3
"""Validate changelog fragments and fold them into CHANGELOG.md on release.

Usage:
    changelog.py check [--require BRANCH]
    changelog.py next-version CURRENT [--bump patch|minor|major]
    changelog.py release VERSION [--date YYYY-MM-DD] [--notes-out PATH]
    changelog.py notes VERSION
    changelog.py github-notes VERSION
"""

from __future__ import annotations

import argparse
import datetime
import shutil
import sys
from pathlib import Path

import yaml

from check_changelog_fragments import BUCKETS, check

ROOT = Path(__file__).resolve().parents[2]
WIP_DIR = ROOT / ".changelog" / "wip"
HISTORY_DIR = ROOT / ".changelog" / "history"
CHANGELOG = ROOT / "CHANGELOG.md"
SECTIONS = ["breaking", "security", "added", "changed", "fixed", "removed"]


def fragment_paths() -> list[Path]:
    return sorted(WIP_DIR.glob("*.yaml"))


def fragment_name(branch: str) -> str:
    return branch.replace("/", "_") + ".yaml"


def validate(path: Path) -> tuple[dict | None, list[str]]:
    errors = check(str(path))
    if errors:
        return None, errors
    return yaml.safe_load(path.read_text(encoding="utf-8")), []


def load_all() -> list[tuple[Path, dict]]:
    fragments: list[tuple[Path, dict]] = []
    errors: list[str] = []
    for path in fragment_paths():
        data, fragment_errors = validate(path)
        errors.extend(fragment_errors)
        if data is not None:
            fragments.append((path, data))
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
    return fragments


def cmd_check(args: argparse.Namespace) -> None:
    if args.require:
        name = fragment_name(args.require)
        path = WIP_DIR / name
        if not path.is_file():
            print(
                f"error: missing changelog fragment .changelog/wip/{name} "
                f"for branch '{args.require}'",
                file=sys.stderr,
            )
            raise SystemExit(1)
        data, errors = validate(path)
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            raise SystemExit(1)
        if data["branch"] != args.require:
            print(
                f"error: .changelog/wip/{name}: branch is '{data['branch']}', "
                f"expected '{args.require}'",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("ok: 1 changelog fragment valid")
        return

    fragments = load_all()
    print(f"ok: {len(fragments)} changelog fragment(s) valid")


def populated_sections(fragments: list[tuple[Path, dict]]) -> set[str]:
    return {
        section
        for _, data in fragments
        for section, entries in data["changes"].items()
        if entries
    }


def implied_bump(fragments: list[tuple[Path, dict]], current: tuple[int, int, int]) -> str:
    sections = populated_sections(fragments)
    if "breaking" in sections:
        return "minor" if current[0] == 0 else "major"
    if "added" in sections:
        return "minor"
    return "patch"


def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError
    values = tuple(int(part) for part in parts)
    return values[0], values[1], values[2]


def bump_version(current: tuple[int, int, int], kind: str) -> str:
    major, minor, patch = current
    if kind == "major":
        major, minor, patch = major + 1, 0, 0
    elif kind == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    return f"{major}.{minor}.{patch}"


def cmd_next_version(args: argparse.Namespace) -> None:
    fragments = load_all()
    if not fragments:
        print("error: no changelog fragments in .changelog/wip/", file=sys.stderr)
        raise SystemExit(1)
    try:
        current = parse_version(args.current)
    except ValueError:
        print(f"error: '{args.current}' is not a MAJOR.MINOR.PATCH version", file=sys.stderr)
        raise SystemExit(1)
    kind = args.bump or implied_bump(fragments, current)
    print(f"{kind} {bump_version(current, kind)}")


def render(version: str, date: str, fragments: list[tuple[Path, dict]]) -> str:
    merged = {section: [] for section in SECTIONS}
    for _, data in fragments:
        for section, entries in data["changes"].items():
            merged[section].extend(entries or [])

    lines = [f"## [{version}] - {date}", ""]
    for section in SECTIONS:
        if not merged[section]:
            continue
        lines += [f"### {section.capitalize()}", ""]
        for entry in merged[section]:
            title = entry["title"].strip()
            description = " ".join(entry["description"].split())
            lines.append(f"- **{title}** — {description}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def prepend_release(existing: str, block: str) -> str:
    first_release = existing.find("\n## [")
    if first_release == -1:
        return existing.rstrip() + "\n\n" + block
    insert_at = first_release + 1
    return existing[:insert_at] + block + "\n" + existing[insert_at:]


def archive_fragments(version: str, fragments: list[tuple[Path, dict]]) -> None:
    destination = HISTORY_DIR / version
    if destination.exists():
        raise SystemExit(f"error: changelog archive already exists: {destination.relative_to(ROOT)}")
    destination.mkdir(parents=True)
    for path, _ in fragments:
        shutil.move(str(path), destination / path.name)


def cmd_release(args: argparse.Namespace) -> None:
    fragments = load_all()
    if not fragments:
        print("error: no changelog fragments in .changelog/wip/", file=sys.stderr)
        raise SystemExit(1)
    block = render(args.version, args.date, fragments)
    existing = CHANGELOG.read_text(encoding="utf-8")
    CHANGELOG.write_text(prepend_release(existing, block), encoding="utf-8")
    if args.notes_out:
        Path(args.notes_out).write_text(block, encoding="utf-8")
    archive_fragments(args.version, fragments)
    print(f"released {args.version}: folded {len(fragments)} fragment(s) into CHANGELOG.md")


def notes_for_version(version: str) -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    section: list[str] = []
    found = False
    for line in text.splitlines():
        if line.startswith("## ["):
            if found:
                break
            found = line.startswith(f"## [{version}]")
        if found:
            section.append(line)
    if not found:
        print(f"error: no '## [{version}]' section in CHANGELOG.md", file=sys.stderr)
        raise SystemExit(1)
    return "\n".join(section).strip()


def cmd_notes(args: argparse.Namespace) -> None:
    print(notes_for_version(args.version))


def cmd_github_notes(args: argparse.Namespace) -> None:
    lines = notes_for_version(args.version).splitlines()
    body = "\n".join(lines[1:]).strip()
    print(f"## Changelog\n\n{body}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    check_parser = sub.add_parser("check", help="validate changelog fragments")
    check_parser.add_argument("--require", metavar="BRANCH")
    check_parser.set_defaults(func=cmd_check)

    next_version = sub.add_parser("next-version", help="print the selected bump and next version")
    next_version.add_argument("current")
    next_version.add_argument("--bump", choices=("patch", "minor", "major"))
    next_version.set_defaults(func=cmd_next_version)

    release = sub.add_parser("release", help="fold fragments into CHANGELOG.md")
    release.add_argument("version")
    release.add_argument("--date", default=datetime.date.today().isoformat())
    release.add_argument("--notes-out", metavar="PATH")
    release.set_defaults(func=cmd_release)

    notes = sub.add_parser("notes", help="print the CHANGELOG.md section for a version")
    notes.add_argument("version")
    notes.set_defaults(func=cmd_notes)

    github_notes = sub.add_parser(
        "github-notes", help="render a reviewed changelog section as a GitHub Release body"
    )
    github_notes.add_argument("version")
    github_notes.set_defaults(func=cmd_github_notes)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
