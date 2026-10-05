#!/usr/bin/env python3
"""Generate a BDD Gherkin step inventory for Agent Gateway."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable


STEP_KINDS = ("given", "when", "then")
FEATURE_STEP_RE = re.compile(r"^\s*(Given|When|Then|And|But)\s+(.+?)\s*$")
TAG_RE = re.compile(r"^\s*@")
SCENARIO_RE = re.compile(r"^\s*(Scenario(?: Outline)?):\s*(.+?)\s*$")
FEATURE_RE = re.compile(r"^\s*Feature:\s*(.+?)\s*$")
BACKGROUND_RE = re.compile(r"^\s*Background:\s*$")
EXAMPLES_RE = re.compile(r"^\s*Examples:\s*$")
TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")
ATTR_START_RE = re.compile(r"^\s*#\[(given|when|then)\b", re.IGNORECASE)
FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
TERM_WARNING_CATEGORIES_PATH = Path("scripts/bdd-gherkin-term-warnings.json")
KNOWN_TAGS = {"@wip", "@known-bug", "@trust-registry"}
KNOWN_TAG_PREFIXES = ("@contract:", "@topology:")
PLACEHOLDER_RE = re.compile(r"<([^>]+)>")


@dataclass(frozen=True)
class StepBinding:
    suite: str
    kind: str
    matcher: str
    expression: str
    file: str
    line: int
    function: str | None
    normalized: str


@dataclass(frozen=True)
class FeatureStep:
    suite: str
    kind: str
    keyword: str
    text: str
    file: str
    line: int
    feature: str | None
    scenario: str | None
    tags: tuple[str, ...]
    normalized: str


@dataclass(frozen=True)
class ScenarioStep:
    line: int
    keyword: str
    kind: str
    text: str


@dataclass(frozen=True)
class FeatureScenario:
    suite: str
    file: str
    line: int
    feature: str | None
    name: str
    tags: tuple[str, ...]
    is_outline: bool
    background_steps: tuple[ScenarioStep, ...]
    steps: tuple[ScenarioStep, ...]
    example_headers: tuple[str, ...]
    example_row_count: int


@dataclass(frozen=True)
class FeatureFile:
    suite: str
    file: str
    feature: str | None
    feature_line: int
    scenario_count: int
    background_line: int | None
    background_step_count: int


@dataclass(frozen=True)
class StepMatch:
    step_file: str
    step_line: int
    step_text: str
    step_kind: str
    tags: tuple[str, ...]
    match_count: int
    matches: tuple[str, ...]


@dataclass(frozen=True)
class NearDuplicate:
    kind: str
    score: float
    left: str
    right: str
    left_ref: str
    right_ref: str


@dataclass(frozen=True)
class InventoryData:
    root: Path
    bindings: list[StepBinding]
    feature_steps: list[FeatureStep]
    matches: list[StepMatch]
    exact_overlaps: dict[str, list[str]]
    near_duplicates: list[NearDuplicate]
    term_warnings: list[dict[str, str | int]]
    binding_counts: dict[str, int]
    function_refs: dict[str, int]
    scenarios: list[FeatureScenario]
    feature_files: list[FeatureFile]
    term_warning_categories: dict[str, tuple[str, ...]]


def repo_relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def markdown_code(text: str, *, table_cell: bool = False) -> str:
    escaped = text.replace("|", r"\|") if table_cell else text
    if "`" not in escaped:
        return f"`{escaped}`"
    return f"`` {escaped} ``"


def suite_for_path(path: Path) -> str:
    parts = path.parts
    # The MCP conformance harness runs its features through the g2g runner.
    if "mcp-conformance" in parts:
        return "g2g_bdd"
    if "surface_bdd" in parts or "surface" in parts:
        return "surface_bdd"
    if "g2g_bdd" in parts or "g2g" in parts:
        return "g2g_bdd"
    return "shared"


def parse_rust_string_at(text: str, index: int) -> tuple[str, int] | None:
    if index >= len(text):
        return None
    if text[index] == 'r':
        cursor = index + 1
        hashes = 0
        while cursor < len(text) and text[cursor] == '#':
            hashes += 1
            cursor += 1
        if cursor >= len(text) or text[cursor] != '"':
            return None
        cursor += 1
        terminator = '"' + ('#' * hashes)
        end = text.find(terminator, cursor)
        if end == -1:
            return None
        return text[cursor:end], end + len(terminator)
    if text[index] != '"':
        return None
    cursor = index + 1
    chars: list[str] = []
    while cursor < len(text):
        char = text[cursor]
        if char == '\\' and cursor + 1 < len(text):
            escaped = text[cursor + 1]
            replacements = {'n': '\n', 'r': '\r', 't': '\t', '"': '"', '\\': '\\'}
            chars.append(replacements.get(escaped, escaped))
            cursor += 2
            continue
        if char == '"':
            return ''.join(chars), cursor + 1
        chars.append(char)
        cursor += 1
    return None


def find_assignment_literal(attr: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*", attr)
    if not match:
        return None
    cursor = match.end()
    while cursor < len(attr) and attr[cursor].isspace():
        cursor += 1
    parsed = parse_rust_string_at(attr, cursor)
    return parsed[0] if parsed else None


def find_first_literal(attr: str) -> str | None:
    start = attr.find('(')
    if start == -1:
        return None
    cursor = start + 1
    while cursor < len(attr) and attr[cursor].isspace():
        cursor += 1
    parsed = parse_rust_string_at(attr, cursor)
    return parsed[0] if parsed else None


def extract_binding_expression(attr: str) -> tuple[str, str] | None:
    regex_expr = find_assignment_literal(attr, "regex")
    if regex_expr is not None:
        return "regex", regex_expr
    cucumber_expr = find_assignment_literal(attr, "expr")
    if cucumber_expr is not None:
        return "expr", cucumber_expr
    literal = find_first_literal(attr)
    if literal is not None:
        return "literal", literal
    return None


def parse_step_bindings(root: Path, paths: Iterable[Path]) -> list[StepBinding]:
    bindings: list[StepBinding] = []
    for path in sorted(paths):
        lines = path.read_text(encoding="utf-8").splitlines()
        index = 0
        while index < len(lines):
            line = lines[index]
            start = ATTR_START_RE.match(line)
            if not start:
                index += 1
                continue
            kind = start.group(1).lower()
            attr_lines = [line]
            attr_line_number = index + 1
            balance = line.count("[") - line.count("]")
            while balance > 0 and index + 1 < len(lines):
                index += 1
                attr_lines.append(lines[index])
                balance += lines[index].count("[") - lines[index].count("]")
            attr = "\n".join(attr_lines)
            expression = extract_binding_expression(attr)
            function_name = None
            for next_line in lines[index + 1 : min(index + 12, len(lines))]:
                fn_match = FN_RE.search(next_line)
                if fn_match:
                    function_name = fn_match.group(1)
                    break
            if expression is not None:
                matcher, text = expression
                bindings.append(
                    StepBinding(
                        suite=suite_for_path(path),
                        kind=kind,
                        matcher=matcher,
                        expression=text,
                        file=repo_relative(path, root),
                        line=attr_line_number,
                        function=function_name,
                        normalized=normalize_step_text(text),
                    )
                )
            index += 1
    return bindings


def parse_table_cells(line: str) -> list[str] | None:
    match = TABLE_ROW_RE.match(line)
    if not match:
        return None
    return [cell.strip() for cell in match.group(1).split("|")]


def substitute_outline_values(text: str, values: dict[str, str]) -> str:
    expanded = text
    for name, value in values.items():
        expanded = expanded.replace(f"<{name}>", value)
    return expanded


def append_scenario_steps(
    output: list[FeatureStep],
    *,
    suite: str,
    file: str,
    feature_name: str | None,
    scenario_name: str | None,
    scenario_tags: tuple[str, ...],
    scenario_steps: list[tuple[int, str, str, str]],
    example_rows: list[dict[str, str]],
) -> None:
    rows = example_rows or [{}]
    for values in rows:
        for line_number, keyword, kind, text in scenario_steps:
            expanded_text = substitute_outline_values(text, values)
            output.append(
                FeatureStep(
                    suite=suite,
                    kind=kind,
                    keyword=keyword,
                    text=expanded_text,
                    file=file,
                    line=line_number,
                    feature=feature_name,
                    scenario=scenario_name,
                    tags=scenario_tags,
                    normalized=normalize_step_text(expanded_text),
                )
            )


def scenario_step_records(items: list[tuple[int, str, str, str]]) -> tuple[ScenarioStep, ...]:
    return tuple(ScenarioStep(line=line, keyword=keyword, kind=kind, text=text) for line, keyword, kind, text in items)


def parse_feature_inventory(root: Path, paths: Iterable[Path]) -> tuple[list[FeatureStep], list[FeatureScenario], list[FeatureFile]]:
    steps: list[FeatureStep] = []
    scenarios: list[FeatureScenario] = []
    feature_files: list[FeatureFile] = []
    for path in sorted(paths):
        feature_name: str | None = None
        feature_line = 0
        scenario_name: str | None = None
        scenario_line = 0
        scenario_tags: tuple[str, ...] = ()
        scenario_is_outline = False
        pending_tags: list[str] = []
        background_line: int | None = None
        background_steps: list[tuple[int, str, str, str]] = []
        scenario_steps: list[tuple[int, str, str, str]] = []
        example_headers: list[str] | None = None
        example_rows: list[dict[str, str]] = []
        collecting_background = False
        in_examples = False
        last_kind: str | None = None
        suite = suite_for_path(path)
        file = repo_relative(path, root)

        def flush_scenario() -> None:
            nonlocal scenario_steps, example_headers, example_rows, in_examples
            if scenario_name is not None:
                append_scenario_steps(
                    steps,
                    suite=suite,
                    file=file,
                    feature_name=feature_name,
                    scenario_name=scenario_name,
                    scenario_tags=scenario_tags,
                    scenario_steps=background_steps + scenario_steps,
                    example_rows=example_rows,
                )
                scenarios.append(
                    FeatureScenario(
                        suite=suite,
                        file=file,
                        line=scenario_line,
                        feature=feature_name,
                        name=scenario_name,
                        tags=scenario_tags,
                        is_outline=scenario_is_outline,
                        background_steps=scenario_step_records(background_steps),
                        steps=scenario_step_records(scenario_steps),
                        example_headers=tuple(example_headers or ()),
                        example_row_count=len(example_rows),
                    )
                )
            scenario_steps = []
            example_headers = None
            example_rows = []
            in_examples = False

        def flush_feature_file() -> None:
            feature_files.append(
                FeatureFile(
                    suite=suite,
                    file=file,
                    feature=feature_name,
                    feature_line=feature_line,
                    scenario_count=sum(1 for scenario in scenarios if scenario.file == file and scenario.feature == feature_name),
                    background_line=background_line,
                    background_step_count=len(background_steps),
                )
            )

        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            feature_match = FEATURE_RE.match(line)
            if feature_match:
                flush_scenario()
                if feature_name is not None:
                    flush_feature_file()
                feature_name = feature_match.group(1)
                feature_line = line_number
                scenario_name = None
                scenario_tags = ()
                background_line = None
                background_steps = []
                pending_tags.clear()
                collecting_background = False
                last_kind = None
                continue
            if TAG_RE.match(line):
                pending_tags.extend(stripped.split())
                continue
            if BACKGROUND_RE.match(line):
                flush_scenario()
                collecting_background = True
                background_line = line_number
                last_kind = None
                continue
            scenario_match = SCENARIO_RE.match(line)
            if scenario_match:
                flush_scenario()
                scenario_name = scenario_match.group(2)
                scenario_line = line_number
                scenario_tags = tuple(pending_tags)
                scenario_is_outline = scenario_match.group(1) == "Scenario Outline"
                pending_tags.clear()
                collecting_background = False
                last_kind = None
                continue
            if EXAMPLES_RE.match(line):
                in_examples = True
                example_headers = None
                continue
            if in_examples:
                cells = parse_table_cells(line)
                if cells is not None:
                    if example_headers is None:
                        example_headers = cells
                    else:
                        example_rows.append(dict(zip(example_headers, cells, strict=False)))
                    continue
            step_match = FEATURE_STEP_RE.match(line)
            if not step_match:
                continue
            in_examples = False
            keyword = step_match.group(1)
            text = step_match.group(2)
            if keyword in ("And", "But"):
                kind = last_kind or "unknown"
            else:
                kind = keyword.lower()
                last_kind = kind
            if collecting_background:
                background_steps.append((line_number, keyword, kind, text))
            else:
                scenario_steps.append((line_number, keyword, kind, text))
        flush_scenario()
        flush_feature_file()
    return steps, scenarios, feature_files


def parse_feature_steps(root: Path, paths: Iterable[Path]) -> list[FeatureStep]:
    steps, _, _ = parse_feature_inventory(root, paths)
    return steps


def strip_regex_anchors(expression: str) -> str:
    value = expression
    if value.startswith("^"):
        value = value[1:]
    if value.endswith("$"):
        value = value[:-1]
    return value


def normalize_step_text(text: str) -> str:
    value = strip_regex_anchors(text).lower()
    replacements = [
        (r'"\(\[\^"\]\+\)"', '"{string}"'),
        (r'"\(\[\^"\]\*\)"', '"{string}"'),
        (r'"\[\^"\]\+"', '"{string}"'),
        (r'\{string\}', '"{string}"'),
        (r'\{int\}', '{int}'),
        (r'\{\}', '{value}'),
        (r'\(\?:([^)]*)\)', r'\1'),
        (r'\(\d\+\)', '{int}'),
        (r'\(-\?\\d\+\)', '{int}'),
        (r'\\d\+', '{int}'),
        (r'\(\[\^"\]\+\)', '{string}'),
        (r'\[\^"\]\+', '{string}'),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    value = value.replace('\\', '')
    value = re.sub(r'"[^"]*"', '"{string}"', value)
    value = re.sub(r'\b\d+\b', '{int}', value)
    value = re.sub(r'\s+', ' ', value)
    return value.strip()


def cucumber_expr_to_regex(expression: str) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)?\}", expression):
        pieces.append(re.escape(expression[cursor : match.start()]))
        name = match.group(1) or "anonymous"
        if name == "string":
            pieces.append(r'"[^"]*"')
        elif name in {"int", "float"}:
            pieces.append(r"-?\d+(?:\.\d+)?")
        elif name == "word":
            pieces.append(r"\S+")
        else:
            pieces.append(r".+")
        cursor = match.end()
    pieces.append(re.escape(expression[cursor:]))
    return "^" + "".join(pieces) + "$"


def binding_pattern(binding: StepBinding) -> re.Pattern[str] | None:
    if binding.matcher == "regex":
        pattern = binding.expression
    elif binding.matcher == "expr":
        pattern = cucumber_expr_to_regex(binding.expression)
    else:
        pattern = "^" + re.escape(binding.expression) + "$"
    try:
        return re.compile(pattern)
    except re.error:
        return None


def match_feature_steps(bindings: list[StepBinding], feature_steps: list[FeatureStep]) -> list[StepMatch]:
    compiled: list[tuple[StepBinding, re.Pattern[str]]] = []
    for binding in bindings:
        pattern = binding_pattern(binding)
        if pattern is not None:
            compiled.append((binding, pattern))
    results: list[StepMatch] = []
    for step in feature_steps:
        matches = []
        for binding, pattern in compiled:
            if binding.suite != step.suite or binding.kind != step.kind:
                continue
            if pattern.fullmatch(step.text):
                matches.append(f"{binding.file}:{binding.line} {binding.matcher} {binding.expression}")
        results.append(
            StepMatch(
                step_file=step.file,
                step_line=step.line,
                step_text=step.text,
                step_kind=step.kind,
                tags=step.tags,
                match_count=len(matches),
                matches=tuple(matches),
            )
        )
    return results


def has_tag(match: StepMatch, tag: str) -> bool:
    return tag in match.tags


def is_wip(match: StepMatch) -> bool:
    return has_tag(match, "@wip")


def is_known_bug(match: StepMatch) -> bool:
    return has_tag(match, "@known-bug")


def unmatched_required_steps(matches: list[StepMatch]) -> list[StepMatch]:
    return [match for match in matches if match.match_count == 0 and not is_wip(match)]


def unmatched_wip_steps(matches: list[StepMatch]) -> list[StepMatch]:
    return [match for match in matches if match.match_count == 0 and is_wip(match)]


def unmatched_known_bug_steps(matches: list[StepMatch]) -> list[StepMatch]:
    return [match for match in matches if match.match_count == 0 and is_known_bug(match)]


def tagged_scenarios(feature_steps: list[FeatureStep], tag: str) -> list[tuple[str, str | None]]:
    scenarios = {(step.file, step.scenario) for step in feature_steps if tag in step.tags}
    return sorted(scenarios)


def tagged_steps(feature_steps: list[FeatureStep], tag: str) -> list[FeatureStep]:
    return [step for step in feature_steps if tag in step.tags]


def find_exact_overlaps(bindings: list[StepBinding]) -> dict[str, list[str]]:
    by_text: dict[tuple[str, str], list[str]] = {}
    for binding in bindings:
        key = (binding.kind, binding.normalized)
        by_text.setdefault(key, []).append(f"{binding.suite} {binding.file}:{binding.line} {binding.expression}")
    return {f"{kind}: {text}": refs for (kind, text), refs in sorted(by_text.items()) if len({ref.split()[0] for ref in refs}) > 1}


def exact_cross_suite_keys(bindings: list[StepBinding]) -> set[tuple[str, str]]:
    suites_by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for binding in bindings:
        suites_by_key[(binding.kind, binding.normalized)].add(binding.suite)
    return {key for key, suites in suites_by_key.items() if len(suites) > 1}


def find_near_duplicates(bindings: list[StepBinding], limit: int = 60, threshold: float = 0.76) -> list[NearDuplicate]:
    candidates: list[NearDuplicate] = []
    exact_keys = exact_cross_suite_keys(bindings)
    for index, left in enumerate(bindings):
        for right in bindings[index + 1 :]:
            left_key = (left.kind, left.normalized)
            right_key = (right.kind, right.normalized)
            if (
                left.kind != right.kind
                or left.suite == right.suite
                or left.normalized == right.normalized
                or left_key in exact_keys
                or right_key in exact_keys
            ):
                continue
            score = SequenceMatcher(None, left.normalized, right.normalized).ratio()
            if score >= threshold:
                candidates.append(
                    NearDuplicate(
                        kind=left.kind,
                        score=round(score, 3),
                        left=left.expression,
                        right=right.expression,
                        left_ref=f"{left.suite} {left.file}:{left.line}",
                        right_ref=f"{right.suite} {right.file}:{right.line}",
                    )
                )
    candidates.sort(key=lambda item: (-item.score, item.kind, item.left_ref, item.right_ref))
    return candidates[:limit]


def load_term_warning_categories(root: Path) -> dict[str, tuple[str, ...]]:
    path = root / TERM_WARNING_CATEGORIES_PATH
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    categories: dict[str, tuple[str, ...]] = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{TERM_WARNING_CATEGORIES_PATH} must contain a JSON object")
    for category, value in raw.items():
        if not isinstance(category, str):
            raise ValueError(f"{TERM_WARNING_CATEGORIES_PATH} category names must be strings")
        terms = value.get("terms") if isinstance(value, dict) else value
        if not isinstance(terms, list) or not all(isinstance(term, str) for term in terms):
            raise ValueError(f"{TERM_WARNING_CATEGORIES_PATH} category {category!r} must define a string terms list")
        categories[category] = tuple(terms)
    return categories


def find_term_warnings(feature_steps: list[FeatureStep], terms_to_check: tuple[str, ...]) -> list[dict[str, str | int]]:
    warnings: list[dict[str, str | int]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for step in feature_steps:
        lowered = step.text.lower()
        terms = [term for term in terms_to_check if re.search(rf"\b{re.escape(term)}\b", lowered)]
        if not terms:
            continue
        key = (step.file, step.line, ", ".join(terms), step.text)
        if key in seen:
            continue
        seen.add(key)
        warnings.append({"file": step.file, "line": step.line, "terms": key[2], "text": step.text})
    return warnings


def feature_step_usage_counts(feature_steps: list[FeatureStep]) -> list[tuple[tuple[str, str, str], int]]:
    counter: Counter[tuple[str, str, str]] = Counter((step.suite, step.kind, step.normalized) for step in feature_steps)
    return sorted(counter.items(), key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2]))


def binding_usage_counts(bindings: list[StepBinding], matches: list[StepMatch]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    binding_refs = {f"{binding.file}:{binding.line}": binding for binding in bindings}
    for matched_step in matches:
        for match_ref in matched_step.matches:
            ref = match_ref.split()[0]
            if ref in binding_refs:
                counts[ref] += 1
    return counts


def function_reference_counts(root: Path, bindings: list[StepBinding]) -> dict[str, int]:
    rust_paths = list(root.glob("tests/surface_bdd/**/*.rs")) + list(root.glob("tests/g2g_bdd/**/*.rs")) + list(root.glob("tests/bdd_support/**/*.rs"))
    counts: dict[str, int] = {}
    for binding in bindings:
        ref = f"{binding.file}:{binding.line}"
        if binding.function is None:
            counts[ref] = 0
            continue
        call_count = 0
        call_pattern = re.compile(rf"\b{re.escape(binding.function)}\s*\(")
        definition_pattern = re.compile(rf"\bfn\s+{re.escape(binding.function)}\s*\(")
        for path in rust_paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                if definition_pattern.search(line):
                    continue
                call_count += len(call_pattern.findall(line))
        counts[ref] = call_count
    return counts


def collect_inventory(root: Path) -> InventoryData:
    binding_paths = list(root.glob("tests/surface_bdd/steps/*.rs")) + list(root.glob("tests/g2g_bdd/steps/*.rs"))
    # Features the MCP conformance harness runs through g2g_bdd live beside the
    # harness, outside tests/features, so the default g2g run skips them.
    feature_paths = list(root.glob("tests/features/**/*.feature")) + list(root.glob("scripts/mcp-conformance/*.feature"))
    bindings = parse_step_bindings(root, binding_paths)
    feature_steps, scenarios, feature_files = parse_feature_inventory(root, feature_paths)
    matches = match_feature_steps(bindings, feature_steps)
    exact_overlaps = find_exact_overlaps(bindings)
    near_duplicates = find_near_duplicates(bindings)
    term_warning_categories = load_term_warning_categories(root)
    term_warnings = find_term_warnings(feature_steps, term_warning_categories.get("suspicious terminology", ()))
    return InventoryData(
        root=root,
        bindings=bindings,
        feature_steps=feature_steps,
        matches=matches,
        exact_overlaps=exact_overlaps,
        near_duplicates=near_duplicates,
        term_warnings=term_warnings,
        binding_counts=binding_usage_counts(bindings, matches),
        function_refs=function_reference_counts(root, bindings),
        scenarios=scenarios,
        feature_files=feature_files,
        term_warning_categories=term_warning_categories,
    )


def render_inventory_context(data: InventoryData) -> str:
    lines: list[str] = []
    lines.append("# BDD DSL inventory context")
    lines.append("")
    lines.append("AI-oriented catalog for reusing existing Gherkin step language before drafting or renaming scenarios.")
    lines.append("Read the bound Rust function before reusing any non-trivial step; wording is the DSL contract, but behavior lives in the binding implementation.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Step bindings: {len(data.bindings)}")
    lines.append(f"- Feature step usages: {len(data.feature_steps)}")
    lines.append("")
    lines.append("## Step binding catalog")
    for suite in ("surface_bdd", "g2g_bdd", "shared"):
        suite_bindings = [binding for binding in data.bindings if binding.suite == suite]
        if not suite_bindings:
            continue
        lines.append("")
        lines.append(f"### {suite}")
        for kind in STEP_KINDS:
            kind_bindings = [binding for binding in suite_bindings if binding.kind == kind]
            if not kind_bindings:
                continue
            lines.append("")
            lines.append(f"#### {kind.title()}")
            for binding in kind_bindings:
                ref = f"{binding.file}:{binding.line}"
                usage_count = data.binding_counts.get(ref, 0)
                usage_label = "usage" if usage_count == 1 else "usages"
                internal_refs = data.function_refs.get(ref, 0)
                internal_label = "internal ref" if internal_refs == 1 else "internal refs"
                function = binding.function or "<unknown>"
                lines.append(
                    f"- {markdown_code(binding.expression)} ({binding.matcher}, {usage_count} {usage_label}, {internal_refs} {internal_label}) — {ref} `{function}`"
                )
    lines.append("")
    return "\n".join(lines)


def is_known_tag(tag: str) -> bool:
    return tag in KNOWN_TAGS or any(tag.startswith(prefix) for prefix in KNOWN_TAG_PREFIXES)


def scenario_ref(scenario: FeatureScenario) -> str:
    return f"{scenario.file}:{scenario.line} {scenario.name}"


def step_ref(scenario: FeatureScenario, step: ScenarioStep) -> str:
    return f"{scenario.file}:{step.line} {step.keyword} {step.text}"


def lint_step_ref(scenario: FeatureScenario, step: ScenarioStep, *, color: bool) -> str:
    return f"{scenario.file}:{step.line} {render_keyword(step.keyword, color=color)} {render_expression(step.text, color=color)}"


def placeholders_in_steps(steps: Iterable[ScenarioStep]) -> set[str]:
    return {match.group(1).strip() for step in steps for match in PLACEHOLDER_RE.finditer(step.text)}


def duplicate_items(items: Iterable[str]) -> list[str]:
    counts = Counter(items)
    return sorted(item for item, count in counts.items() if count > 1)


def is_broad_regex(expression: str) -> bool:
    return re.search(r"(?<!\\)\.\*|(?<!\\)\.\+", expression) is not None


def cucumber_expression_candidate(expression: str) -> str | None:
    value = strip_regex_anchors(expression)
    value = re.sub(r'"\(\[\^"\]\+\)"', "{string}", value)
    value = re.sub(r'"\(\[\^"\]\*\)"', "{string}", value)
    value = re.sub(r'\(\[\^"\]\+\)', "{string}", value)
    value = re.sub(r'\(\[\^"\]\*\)', "{string}", value)
    value = re.sub(r'\(-\?\\d\+\)', "{int}", value)
    value = re.sub(r'\(\\d\+\)', "{int}", value)
    value = value.replace(r"\ ", " ").replace(r'\"', '"')
    if re.search(r"[\[\]()|+*?^$]", value):
        return None
    return value if value != strip_regex_anchors(expression) else None


def color_text(text: str, code: str, *, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def render_expression(text: object, *, color: bool) -> str:
    return color_text(str(text), "36", color=color)


def render_keyword(text: object, *, color: bool) -> str:
    value = str(text)
    display = value.title() if value in STEP_KINDS else value
    return color_text(display, "35", color=color)


def render_term_list(terms: object, *, color: bool) -> str:
    values = [term.strip() for term in str(terms).split(",") if term.strip()]
    return ", ".join(color_text(term, "33", color=color) for term in values)


def render_term_warning(category: str, warning: dict[str, str | int], *, color: bool = False) -> str:
    terms = render_term_list(warning["terms"], color=color)
    label = "term" if "," not in str(warning["terms"]) else "terms"
    step = render_expression(warning["text"], color=color)
    return "\n".join(
        [
            f"{category}: {warning['file']}:{warning['line']}",
            f"  {label} {terms} in step: {step}",
        ]
    )


def should_color_output() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def render_lint(data: InventoryData, *, verbose: bool = False, color: bool = False) -> tuple[str, int]:
    unmatched = unmatched_required_steps(data.matches)
    unmatched_known_bug = unmatched_known_bug_steps(data.matches)
    ambiguous = [match for match in data.matches if match.match_count > 1]
    unmatched_wip = unmatched_wip_steps(data.matches)
    unused_bindings = [
        binding for binding in data.bindings if data.binding_counts.get(f"{binding.file}:{binding.line}", 0) == 0
    ]
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    known_bug_refs = {(match.step_file, match.step_line) for match in unmatched_known_bug}
    for item in unmatched:
        if (item.step_file, item.step_line) in known_bug_refs:
            continue
        errors.append(f"unmatched required step: {item.step_file}:{item.step_line} {render_keyword(item.step_kind, color=color)} {render_expression(item.step_text, color=color)}")
    for item in unmatched_known_bug:
        errors.append(f"unmatched @known-bug step: {item.step_file}:{item.step_line} {render_keyword(item.step_kind, color=color)} {render_expression(item.step_text, color=color)}")
    for item in ambiguous:
        errors.append(f"ambiguous step: {item.step_file}:{item.step_line} {render_expression(item.step_text, color=color)} ({item.match_count} matches)")
    for item in unmatched_wip:
        warnings.append(f"unmatched @wip draft step: {item.step_file}:{item.step_line} {render_keyword(item.step_kind, color=color)} {render_expression(item.step_text, color=color)}")

    scenario_matches: dict[tuple[str, str | None], list[StepMatch]] = defaultdict(list)
    for step, match in zip(data.feature_steps, data.matches, strict=True):
        scenario_matches[(step.file, step.scenario)].append(match)

    for feature_file in data.feature_files:
        if feature_file.scenario_count == 0:
            location = f"{feature_file.file}:{feature_file.feature_line}" if feature_file.feature_line else feature_file.file
            errors.append(f"feature file has no scenarios: {location}")
        if feature_file.background_line is not None and feature_file.background_step_count == 0:
            errors.append(f"background has no steps: {feature_file.file}:{feature_file.background_line}")

    scenarios_by_feature: dict[tuple[str, str | None], list[FeatureScenario]] = defaultdict(list)
    for scenario in data.scenarios:
        scenarios_by_feature[(scenario.file, scenario.feature)].append(scenario)
    for (file, feature), scenarios in scenarios_by_feature.items():
        for name in duplicate_items(scenario.name for scenario in scenarios):
            refs = ", ".join(f"{scenario.file}:{scenario.line}" for scenario in scenarios if scenario.name == name)
            warnings.append(f"duplicate scenario title in feature: {file} {feature or '<unnamed feature>'} {name} ({refs})")

    for scenario in data.scenarios:
        all_steps = list(scenario.background_steps) + list(scenario.steps)
        if not scenario.steps:
            errors.append(f"scenario has no steps: {scenario_ref(scenario)}")
        duplicate_tags = duplicate_items(scenario.tags)
        if duplicate_tags:
            warnings.append(f"duplicate scenario tags: {scenario_ref(scenario)} ({', '.join(duplicate_tags)})")
        background_action_or_assertion_steps = [step for step in scenario.background_steps if step.kind in {"when", "then"}]
        for step in background_action_or_assertion_steps:
            errors.append(f"background contains {render_keyword(step.kind, color=color)}: {lint_step_ref(scenario, step, color=color)}")
        when_steps = [step for step in all_steps if step.kind == "when"]
        if not when_steps and scenario.steps:
            errors.append(f"scenario has no {render_keyword('When', color=color)} step: {scenario_ref(scenario)}")
        if len(when_steps) > 1:
            refs = "; ".join(lint_step_ref(scenario, step, color=color) for step in when_steps)
            errors.append(f"scenario has multiple {render_keyword('When', color=color)} steps: {scenario_ref(scenario)} ({refs})")
        for section_name, section_steps in (("Background", scenario.background_steps), ("Scenario", scenario.steps)):
            for repeated_keyword in ("Given", "Then"):
                repeated_steps = [step for step in section_steps if step.keyword == repeated_keyword]
                if len(repeated_steps) > 1:
                    refs = ", ".join(f"{scenario.file}:{step.line}" for step in repeated_steps[1:])
                    errors.append(
                        "\n".join(
                            [
                                f"{section_name.lower()} repeats {render_keyword(repeated_keyword, color=color)}; use {render_keyword('And', color=color)} after the first {render_keyword(repeated_keyword, color=color)}: {scenario.file}:{scenario.line}",
                                f"  repeated {render_keyword(repeated_keyword, color=color)} at: {refs}",
                            ]
                        )
                    )
        highest_rank = -1
        step_ranks = {"given": 0, "when": 1, "then": 2}
        for step in scenario.steps:
            rank = step_ranks.get(step.kind)
            if rank is None:
                continue
            if rank < highest_rank:
                errors.append(f"step keywords out of logical order: {scenario_ref(scenario)} ({lint_step_ref(scenario, step, color=color)})")
                break
            highest_rank = max(highest_rank, rank)
        if not scenario.is_outline and (scenario.example_headers or scenario.example_row_count):
            errors.append(f"scenario has {render_keyword('Examples', color=color)} but is not a {render_keyword('Scenario Outline', color=color)}: {scenario_ref(scenario)}")
        if scenario.is_outline:
            headers = set(scenario.example_headers)
            placeholders = placeholders_in_steps(all_steps)
            missing = sorted(placeholders - headers)
            unused = sorted(headers - placeholders)
            if scenario.example_row_count == 0:
                errors.append(f"scenario outline has no examples: {scenario_ref(scenario)}")
            if missing:
                errors.append(f"scenario outline placeholders missing from {render_keyword('Examples', color=color)}: {scenario_ref(scenario)} ({', '.join(missing)})")
            if unused:
                errors.append(f"scenario outline has unused {render_keyword('Examples', color=color)} columns: {scenario_ref(scenario)} ({', '.join(unused)})")
        for tag in scenario.tags:
            if not is_known_tag(tag):
                warnings.append(f"unknown tag: {scenario.file}:{scenario.line} {tag} on {scenario.name}")
        matches_for_scenario = scenario_matches.get((scenario.file, scenario.name), [])
        if "@wip" in scenario.tags and matches_for_scenario and all(match.match_count > 0 for match in matches_for_scenario):
            warnings.append(f"fully bound @wip scenario: {scenario_ref(scenario)}")

    for binding in unused_bindings:
        ref = f"{binding.file}:{binding.line}"
        internal_refs = data.function_refs.get(ref, 0)
        if internal_refs == 0:
            errors.append(f"unused step binding: {ref} {render_keyword(binding.kind, color=color)} {render_expression(binding.expression, color=color)}")
        else:
            errors.append(
                f"unused step binding with internal helper refs: {ref} {render_keyword(binding.kind, color=color)} {render_expression(binding.expression, color=color)}; remove the Cucumber binding attribute"
            )
    for binding in data.bindings:
        if binding.matcher == "regex" and is_broad_regex(binding.expression):
            warnings.append(f"broad regex step binding: {binding.file}:{binding.line} {render_keyword(binding.kind, color=color)} {render_expression(binding.expression, color=color)}")
    for category, terms in data.term_warning_categories.items():
        term_warnings = data.term_warnings if category == "suspicious terminology" else find_term_warnings(data.feature_steps, terms)
        for warning in term_warnings:
            warnings.append(render_term_warning(category, warning, color=color))
    for item in data.near_duplicates:
        warnings.append(
            "\n".join(
                [
                    f"near-duplicate cross-suite binding ({item.score:.3f}, {render_keyword(item.kind, color=color)}):",
                    f"  left: {item.left_ref} — {render_expression(item.left, color=color)}",
                    f"  right: {item.right_ref} — {render_expression(item.right, color=color)}",
                ]
            )
        )

    lines: list[str] = []
    lines.append("BDD Gherkin lint")
    lines.append("")
    lines.append("validated:")
    lines.append(f"- step bindings: {len(data.bindings)}")
    lines.append(f"- feature step usages: {len(data.feature_steps)}")
    lines.append(f"- @wip scenarios: {len(tagged_scenarios(data.feature_steps, '@wip'))} ({len(tagged_steps(data.feature_steps, '@wip'))} expanded steps)")
    lines.append(f"- @known-bug scenarios: {len(tagged_scenarios(data.feature_steps, '@known-bug'))} ({len(tagged_steps(data.feature_steps, '@known-bug'))} expanded steps)")
    lines.append("")
    lines.append(f"errors: {len(errors)}")
    lines.append(f"warnings: {len(warnings)}")
    if verbose:
        for text in data.exact_overlaps:
            info.append(f"exact cross-suite overlap: {render_expression(text, color=color)}")
        for binding in data.bindings:
            if binding.matcher != "regex":
                continue
            candidate = cucumber_expression_candidate(binding.expression)
            if candidate is not None:
                info.append(f"regex step binding could be Cucumber expression: {binding.file}:{binding.line} {render_keyword(binding.kind, color=color)} {render_expression(candidate, color=color)}")
        lines.append(f"info: {len(info)}")
    sections = (("ERROR", errors), ("WARN", warnings), ("INFO", info)) if verbose else (("ERROR", errors), ("WARN", warnings))
    for label, items in sections:
        if not items:
            continue
        lines.append("")
        lines.append(f"## {label}")
        for item in items:
            lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines), len(errors)


def debug_payload(data: InventoryData) -> dict[str, object]:
    bindings = data.bindings
    feature_steps = data.feature_steps
    matches = data.matches
    return {
        "bindings": [asdict(binding) for binding in bindings],
        "feature_steps": [asdict(step) for step in feature_steps],
        "scenarios": [asdict(scenario) for scenario in data.scenarios],
        "feature_files": [asdict(feature_file) for feature_file in data.feature_files],
        "matches": [asdict(match) for match in matches],
        "exact_overlaps": data.exact_overlaps,
        "near_duplicates": [asdict(item) for item in data.near_duplicates],
        "feature_step_usage_counts": [
            {"suite": suite, "kind": kind, "normalized": text, "count": count}
            for (suite, kind, text), count in feature_step_usage_counts(feature_steps)
        ],
        "binding_usage_counts": data.binding_counts,
        "function_reference_counts": data.function_refs,
        "tagged_scenarios": {
            "wip": [{"file": file, "scenario": scenario} for file, scenario in tagged_scenarios(feature_steps, "@wip")],
            "known_bug": [
                {"file": file, "scenario": scenario} for file, scenario in tagged_scenarios(feature_steps, "@known-bug")
            ],
        },
        "unmatched_required_steps": [asdict(match) for match in unmatched_required_steps(matches)],
        "unmatched_wip_steps": [asdict(match) for match in unmatched_wip_steps(matches)],
        "unmatched_known_bug_steps": [asdict(match) for match in unmatched_known_bug_steps(matches)],
        "term_warning_categories": {category: list(terms) for category, terms in data.term_warning_categories.items()},
        "term_warnings": data.term_warnings,
        "summary": {
            "bindings": len(bindings),
            "feature_steps": len(feature_steps),
            "scenarios": len(data.scenarios),
            "feature_files": len(data.feature_files),
            "exact_cross_suite_overlaps": len(data.exact_overlaps),
            "near_duplicate_candidates": len(data.near_duplicates),
            "wip_scenarios": len(tagged_scenarios(feature_steps, "@wip")),
            "known_bug_scenarios": len(tagged_scenarios(feature_steps, "@known-bug")),
            "wip_feature_steps": len(tagged_steps(feature_steps, "@wip")),
            "known_bug_feature_steps": len(tagged_steps(feature_steps, "@known-bug")),
            "unmatched_required_feature_steps": len(unmatched_required_steps(matches)),
            "unmatched_wip_feature_steps": len(unmatched_wip_steps(matches)),
            "unmatched_known_bug_feature_steps": len(unmatched_known_bug_steps(matches)),
            "ambiguous_feature_steps": sum(1 for match in matches if match.match_count > 1),
            "unused_step_bindings": sum(1 for binding in bindings if data.binding_counts.get(f"{binding.file}:{binding.line}", 0) == 0),
            "term_warnings": len(data.term_warnings),
        },
    }


def write_debug_json(data: InventoryData, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(debug_payload(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> None:
    assert suite_for_path(Path("scripts/mcp-conformance/fabric.feature")) == "g2g_bdd"
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        steps_dir = root / "tests" / "surface_bdd" / "steps"
        g2g_steps_dir = root / "tests" / "g2g_bdd" / "steps"
        features_dir = root / "tests" / "features" / "surface"
        steps_dir.mkdir(parents=True)
        g2g_steps_dir.mkdir(parents=True)
        features_dir.mkdir(parents=True)
        term_warnings_path = root / TERM_WARNING_CATEGORIES_PATH
        term_warnings_path.parent.mkdir(parents=True)
        term_warnings_path.write_text(
            json.dumps(
                {
                    "suspicious terminology": {"terms": ["upstream"]},
                    "harness mechanics wording": {"terms": ["debug", "fixture", "bootstrapped"]},
                }
            ),
            encoding="utf-8",
        )
        (steps_dir / "then.rs").write_text(
            '\n'.join(
                [
                    'use cucumber::then;',
                    '#[when(expr = "the caller acts")]',
                    'fn caller_acts() {}',
                    '',
                    '#[then(expr = "the response status is {int}")]',
                    'fn response_status() {}',
                    '',
                    '#[then(regex = "^the response message is \\\"([^\\\"]+)\\\"$")]',
                    'fn response_message() {}',
                    '',
                    '#[then(regex = "^the debug value is (.+)$")]',
                    'fn debug_value() {}',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        (g2g_steps_dir / "then.rs").write_text(
            '\n'.join(
                [
                    'use cucumber::then;',
                    '#[then(expr = "the response status code is {int}")]',
                    'fn response_status_code() {}',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        (features_dir / "tagged.feature").write_text(
            '\n'.join(
                [
                    'Feature: tagged inventory validation',
                    '',
                    '  @wip',
                    '  Scenario: draft step may be unbound',
                    '    Then an unimplemented draft assertion exists',
                    '',
                    '  @known-bug',
                    '  Scenario: known bug still has executable bindings',
                    '    Then the response status is 500',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        bindings = parse_step_bindings(root, steps_dir.glob("*.rs"))
        feature_steps = parse_feature_steps(root, features_dir.glob("*.feature"))
        matches = match_feature_steps(bindings, feature_steps)
        assert len(unmatched_wip_steps(matches)) == 1, matches
        assert len(unmatched_required_steps(matches)) == 0, matches
        assert len(unmatched_known_bug_steps(matches)) == 0, matches

        (features_dir / "tagged.feature").write_text(
            '\n'.join(
                [
                    'Feature: tagged inventory validation',
                    '',
                    '  @known-bug',
                    '  Scenario: known bug must be bound',
                    '    Then an unimplemented known-bug assertion exists',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        feature_steps = parse_feature_steps(root, features_dir.glob("*.feature"))
        matches = match_feature_steps(bindings, feature_steps)
        assert len(unmatched_required_steps(matches)) == 1, matches
        assert len(unmatched_known_bug_steps(matches)) == 1, matches

        (features_dir / "shape.feature").write_text(
            '\n'.join(
                [
                    'Feature: scenario shape validation',
                    '',
                    '  Background:',
                    '    Then the response status is 200',
                    '',
                    '  @wip @wip @skip',
                    '  Scenario: fully bound draft',
                    '    When the caller acts',
                    '    Then the response status is 200',
                    '',
                    '  Scenario: multiple actions',
                    '    When the caller acts',
                    '    And the caller acts',
                    '    Then the response status is 200',
                    '',
                    '  Scenario: multiple actions',
                    '    When the caller acts',
                    '    Then the response status is 200',
                    '',
                    '  Scenario: repeated step keywords',
                    '    Given a prerequisite exists',
                    '    Given another prerequisite exists',
                    '    When the caller acts',
                    '    Then the response status is 200',
                    '    Then the response status is 201',
                    '',
                    '  Scenario: no action',
                    '    Then the response status is 200',
                    '',
                    '  Scenario: regex and harness wording',
                    '    Given a bootstrapped debug fixture exists',
                    '    When the caller acts',
                    '    Then the response message is "ok"',
                    '    And the debug value is raw',
                    '',
                    '  Scenario Outline: incomplete examples',
                    '    When the caller asks for <thing>',
                    '    Then the response status is 200',
                    '',
                    '    Examples:',
                    '      | extra |',
                    '      | unused |',
                    '',
                    '  Scenario: out of order',
                    '    When the caller acts',
                    '    Given a late prerequisite exists',
                    '    Then the response status is 200',
                    '',
                    '  Scenario: examples on plain scenario',
                    '    When the caller asks for <thing>',
                    '    Then the response status is 200',
                    '',
                    '    Examples:',
                    '      | thing |',
                    '      | item |',
                    '',
                    '  Scenario: empty scenario',
                    '',
                    '  Scenario Outline: no examples',
                    '    When the caller asks for <thing>',
                    '    Then the response status is 200',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        (features_dir / "empty_background.feature").write_text(
            '\n'.join(
                [
                    'Feature: empty background validation',
                    '',
                    '  Background:',
                    '',
                    '  Scenario: scenario after empty background',
                    '    When the caller acts',
                    '    Then the response status is 200',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        (features_dir / "no_scenarios.feature").write_text(
            '\n'.join(
                [
                    'Feature: no scenario validation',
                    '',
                    '  Rule: no scenarios here',
                    '',
                ]
            ),
            encoding="utf-8",
        )
        data = collect_inventory(root)
        output, error_count = render_lint(data)
        assert error_count > 0, output
        assert "background contains Then" in output, output
        assert "scenario has multiple When steps" in output, output
        assert "scenario repeats Given; use And after the first Given" in output, output
        assert "scenario repeats Then; use And after the first Then" in output, output
        assert "scenario has no When step" in output, output
        assert "broad regex step binding" in output, output
        assert "harness mechanics wording: tests/features/surface/shape.feature:31" in output, output
        assert "  terms debug, fixture, bootstrapped in step: a bootstrapped debug fixture exists" in output, output
        assert "step keywords out of logical order" in output, output
        assert "scenario has Examples but is not a Scenario Outline" in output, output
        assert "scenario has no steps" in output, output
        assert "scenario outline has no examples" in output, output
        assert "scenario outline placeholders missing from Examples" in output, output
        assert "background has no steps" in output, output
        assert "feature file has no scenarios" in output, output
        assert "scenario outline has unused Examples columns" in output, output
        assert "unknown tag" in output, output
        assert "duplicate scenario tags" in output, output
        assert "duplicate scenario title in feature" in output, output
        assert "fully bound @wip scenario" in output, output
        assert "near-duplicate cross-suite binding" in output, output
        assert "left: g2g_bdd tests/g2g_bdd/steps/then.rs:2 — the response status code is {int}" in output, output
        assert "right: surface_bdd tests/surface_bdd/steps/then.rs:5 — the response status is {int}" in output, output
        color_output, _ = render_lint(data, color=True)
        assert "\033[36mthe response status code is {int}\033[0m" in color_output, color_output
        assert "step: \033[36ma bootstrapped debug fixture exists\033[0m" in color_output, color_output
        assert "\033[35mGiven\033[0m" in color_output, color_output
        verbose_output, _ = render_lint(data, verbose=True)
        assert "regex step binding could be Cucumber expression" in verbose_output, verbose_output


def display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generat Agent Gateway BDD step inventory and lint diagnostics.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--inventory",
        nargs="?",
        const=Path(".bdd-gherkin/context.md"),
        type=Path,
        metavar="PATH",
        help="write the AI-oriented DSL inventory context, defaults to .bdd-gherkin/context.md",
    )
    mode.add_argument("--lint", action="store_true", help="print lint diagnostics and exit non-zero on errors")
    parser.add_argument("--verbose", action="store_true", help="include informational diagnostics with --lint")
    mode.add_argument(
        "--debug-json",
        nargs="?",
        const=Path(".bdd-gherkin/debug.json"),
        type=Path,
        metavar="PATH",
        help="write parser/debug data as JSON, defaults to .bdd-gherkin/debug.json",
    )
    mode.add_argument("--self-test", action="store_true", help="run built-in parser/tag accounting self-tests")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root, defaults to the current directory")
    args = parser.parse_args()
    if not any((args.inventory is not None, args.lint, args.debug_json is not None, args.self_test)):
        parser.print_help()
        return 0
    if args.verbose and not args.lint:
        parser.error("--verbose is only valid with --lint")
    if args.self_test:
        self_test()
        print("self-test passed")
        return 0
    root = args.root.resolve()
    if args.inventory is not None:
        data = collect_inventory(root)
        inventory_path = args.inventory if args.inventory.is_absolute() else root / args.inventory
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(render_inventory_context(data), encoding="utf-8")
        print(f"wrote {display_path(inventory_path, root)}")
        return 0
    if args.lint:
        data = collect_inventory(root)
        output, error_count = render_lint(data, verbose=args.verbose, color=should_color_output())
        print(output, end="")
        return 1 if error_count else 0
    if args.debug_json is not None:
        data = collect_inventory(root)
        debug_json_path = args.debug_json if args.debug_json.is_absolute() else root / args.debug_json
        write_debug_json(data, debug_json_path)
        print(f"wrote {display_path(debug_json_path, root)}")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
