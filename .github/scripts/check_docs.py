#!/usr/bin/env python3

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")
MAKE_REFERENCE = re.compile(r"`make ([a-zA-Z0-9_-]+)(?:\s[^`]*)?`")
MAKE_TARGET = re.compile(r"^([a-zA-Z0-9_-]+)[^:=\n]*:", re.MULTILINE)
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def markdown_files() -> list[Path]:
    tracked = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return [ROOT / path for path in tracked if path != "CHANGELOG.md" and (ROOT / path).exists()]


def anchors(path: Path) -> set[str]:
    found = set()
    counts: dict[str, int] = {}
    for heading in HEADING.findall(path.read_text(encoding="utf-8")):
        slug = heading.strip().lower()
        slug = re.sub(r"[^\w\- ]", "", slug, flags=re.UNICODE)
        slug = re.sub(r"\s+", "-", slug)
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    return found


def validate_links(paths: list[Path]) -> list[str]:
    errors = []
    anchor_cache: dict[Path, set[str]] = {}
    for path in paths:
        for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            target_path, _, anchor = unquote(target).partition("#")
            resolved = (path.parent / target_path).resolve() if target_path else path.resolve()
            if not resolved.exists():
                errors.append(f"{path.relative_to(ROOT)}: missing link target {target_path}")
                continue
            if anchor and resolved.suffix.lower() == ".md":
                known = anchor_cache.setdefault(resolved, anchors(resolved))
                if anchor.lower() not in known:
                    errors.append(
                        f"{path.relative_to(ROOT)}: missing anchor #{anchor} in {resolved.relative_to(ROOT)}"
                    )
    return errors


def validate_make_targets(paths: list[Path]) -> list[str]:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    targets = set(MAKE_TARGET.findall(makefile))
    errors = []
    for path in paths:
        for target in MAKE_REFERENCE.findall(path.read_text(encoding="utf-8")):
            if target not in targets:
                errors.append(f"{path.relative_to(ROOT)}: unknown Make target {target}")
    return errors


def main() -> int:
    paths = markdown_files()
    errors = validate_links(paths) + validate_make_targets(paths)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"OK - validated {len(paths)} Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
