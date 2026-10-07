import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import changelog
import yaml


def fragment(branch: str, section: str = "fixed") -> dict:
    changes = {name: [] for name in changelog.BUCKETS}
    changes[section] = [
        {
            "timestamp": "2026-10-05T00:00:00.000Z",
            "title": "Fix release behavior",
            "description": "Explain the reviewed release change.",
        }
    ]
    return {"branch": branch, "changes": changes}


class ChangelogTests(unittest.TestCase):
    def test_required_branch_validates_only_its_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wip = Path(directory)
            (wip / "feat_valid.yaml").write_text(yaml.safe_dump(fragment("feat/valid")))
            (wip / "legacy-invalid.yaml").write_text("not: the repository schema\n")
            args = type("Args", (), {"require": "feat/valid"})()
            with patch.object(changelog, "WIP_DIR", wip), patch("builtins.print") as output:
                changelog.cmd_check(args)
        output.assert_called_once_with("ok: 1 changelog fragment valid")

    def test_required_branch_rejects_mismatched_branch_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wip = Path(directory)
            (wip / "feat_valid.yaml").write_text(yaml.safe_dump(fragment("feat/other")))
            args = type("Args", (), {"require": "feat/valid"})()
            stderr = StringIO()
            with (
                patch.object(changelog, "WIP_DIR", wip),
                patch("sys.stderr", stderr),
                self.assertRaises(SystemExit),
            ):
                changelog.cmd_check(args)
        self.assertIn("branch is 'feat/other', expected 'feat/valid'", stderr.getvalue())

    def test_renders_repository_fragment_schema(self) -> None:
        rendered = changelog.render(
            "0.3.17",
            "2026-10-05",
            [(Path("fragment.yaml"), fragment("fix/release"))],
        )
        self.assertIn("## [0.3.17] - 2026-10-05", rendered)
        self.assertIn("### Fixed", rendered)
        self.assertIn("**Fix release behavior**", rendered)

    def test_prepends_release_after_existing_preamble(self) -> None:
        existing = "# Changelog\n\nProject preamble.\n\n## [0.3.16] - 2026-09-21\n"
        result = changelog.prepend_release(existing, "## [0.3.17] - 2026-10-05\n")
        self.assertTrue(result.startswith("# Changelog\n\nProject preamble.\n\n## [0.3.17]"))
        self.assertIn("## [0.3.16]", result)

    def test_github_notes_use_changelog_heading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changelog_file = Path(directory) / "CHANGELOG.md"
            changelog_file.write_text(
                "# Changelog\n\n## [0.3.17] - 2026-10-05\n\n"
                "### Added\n\n- **Add release flow** — Reviewed details.\n\n"
                "## [0.3.16] - 2026-09-21\n"
            )
            args = type("Args", (), {"version": "0.3.17"})()
            with (
                patch.object(changelog, "CHANGELOG", changelog_file),
                patch("builtins.print") as output,
            ):
                changelog.cmd_github_notes(args)

        output.assert_called_once_with(
            "## Changelog\n\n### Added\n\n"
            "- **Add release flow** — Reviewed details."
        )

    def test_manual_bump_overrides_fragment_inference(self) -> None:
        fragments = [(Path("fragment.yaml"), fragment("feat/x", "added"))]
        with patch.object(changelog, "load_all", return_value=fragments):
            args = type("Args", (), {"current": "0.3.16", "bump": "patch"})()
            with patch("builtins.print") as output:
                changelog.cmd_next_version(args)
        output.assert_called_once_with("patch 0.3.17")

    def test_archives_fragments_under_release_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wip" / "fix_release.yaml"
            source.parent.mkdir()
            source.write_text("fragment")
            history = root / "history"
            with patch.object(changelog, "HISTORY_DIR", history), patch.object(changelog, "ROOT", root):
                changelog.archive_fragments("0.3.17", [(source, {})])
            self.assertFalse(source.exists())
            self.assertTrue((history / "0.3.17" / source.name).exists())

    def test_release_consolidates_and_archives_reviewable_notes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wip = root / ".changelog" / "wip"
            history = root / ".changelog" / "history"
            changelog_file = root / "CHANGELOG.md"
            notes = root / "notes.md"
            wip.mkdir(parents=True)
            (wip / "fix_release.yaml").write_text(yaml.safe_dump(fragment("fix/release")))
            changelog_file.write_text(
                "# Changelog\n\nProject preamble.\n\n## [0.3.16] - 2026-09-21\n"
            )
            args = type(
                "Args",
                (),
                {"version": "0.3.17", "date": "2026-10-05", "notes_out": notes},
            )()
            with (
                patch.object(changelog, "ROOT", root),
                patch.object(changelog, "WIP_DIR", wip),
                patch.object(changelog, "HISTORY_DIR", history),
                patch.object(changelog, "CHANGELOG", changelog_file),
                patch("builtins.print") as output,
            ):
                changelog.cmd_release(args)

            output.assert_called_once_with(
                "released 0.3.17: folded 1 fragment(s) into CHANGELOG.md"
            )
            released = changelog_file.read_text()
            self.assertIn("Project preamble.\n\n## [0.3.17]", released)
            self.assertIn("## [0.3.16]", released)
            self.assertIn("## [0.3.17]", notes.read_text())
            self.assertFalse(any(wip.glob("*.yaml")))
            self.assertTrue((history / "0.3.17" / "fix_release.yaml").exists())


if __name__ == "__main__":
    unittest.main()
