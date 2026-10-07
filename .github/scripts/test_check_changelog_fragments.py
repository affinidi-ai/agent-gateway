import tempfile
import unittest
from pathlib import Path

from check_changelog_fragments import check


class ChangelogFragmentValidationTests(unittest.TestCase):
    def check_fragment(self, entry: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fragment.yaml"
            path.write_text(
                "branch: test/fragment\n"
                "changes:\n"
                "  added: []\n"
                "  changed: []\n"
                "  fixed:\n"
                f"{entry}"
                "  removed: []\n"
                "  security: []\n"
                "  breaking: []\n",
                encoding="utf-8",
            )
            return check(str(path))

    def test_accepts_non_empty_title_and_description(self) -> None:
        self.assertEqual(
            self.check_fragment(
                "    - title: Fix the thing\n"
                "      timestamp: '2026-09-21T00:00:00.000Z'\n"
                "      description: Explain why it changed.\n"
            ),
            [],
        )

    def test_rejects_missing_title(self) -> None:
        errors = self.check_fragment(
            "    - timestamp: '2026-09-21T00:00:00.000Z'\n"
            "      description: Explain why it changed.\n"
        )
        self.assertTrue(any("missing keys ['title']" in error for error in errors))

    def test_rejects_empty_title_and_description(self) -> None:
        errors = self.check_fragment(
            "    - title: '  '\n"
            "      timestamp: '2026-09-21T00:00:00.000Z'\n"
            "      description: ''\n"
        )
        self.assertTrue(any("title must be a non-empty string" in error for error in errors))
        self.assertTrue(any("description must be a non-empty string" in error for error in errors))

    def test_rejects_title_longer_than_80_characters(self) -> None:
        errors = self.check_fragment(
            f"    - title: {'x' * 81}\n"
            "      timestamp: '2026-09-21T00:00:00.000Z'\n"
            "      description: Explain why it changed.\n"
        )
        self.assertTrue(any("title must be 80 characters or less" in error for error in errors))

    def test_rejects_missing_timestamp(self) -> None:
        errors = self.check_fragment(
            "    - title: Fix the thing\n"
            "      description: Explain why it changed.\n"
        )
        self.assertTrue(any("missing key 'timestamp'" in error for error in errors))

    def test_rejects_missing_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fragment.yaml"
            path.write_text("changes:\n  fixed: []\n", encoding="utf-8")
            errors = check(str(path))
        self.assertTrue(any("'branch' must be a non-empty string" in error for error in errors))

    def test_rejects_removed_internal_bucket(self) -> None:
        errors = self.check_fragment(
            "    - title: Fix the thing\n"
            "      timestamp: '2026-09-21T00:00:00.000Z'\n"
            "      description: Explain why it changed.\n"
            "  internal:\n"
            "    - title: Internal note\n"
            "      timestamp: '2026-09-21T00:00:00.000Z'\n"
            "      description: Do not publish this.\n"
        )
        self.assertTrue(any("unknown change buckets" in error for error in errors))

    def test_rejects_invalid_timestamp(self) -> None:
        errors = self.check_fragment(
            "    - title: Fix the thing\n"
            "      timestamp: not-a-time\n"
            "      description: Explain why it changed.\n"
        )
        self.assertTrue(any("timestamp must be an RFC 3339 string" in error for error in errors))

    def test_rejects_date_without_time_or_timezone(self) -> None:
        errors = self.check_fragment(
            "    - title: Fix the thing\n"
            "      timestamp: '2026-09-21'\n"
            "      description: Explain why it changed.\n"
        )
        self.assertTrue(any("timestamp must be an RFC 3339 string" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
