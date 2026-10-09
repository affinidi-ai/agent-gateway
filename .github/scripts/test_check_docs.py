import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_docs


class AnchorsTests(unittest.TestCase):
    def test_slugifies_headings_and_dedupes_repeats(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.md"
            path.write_text("# Getting Started!\n\n## Getting Started!\n", encoding="utf-8")
            self.assertEqual(check_docs.anchors(path), {"getting-started", "getting-started-1"})


class ValidateLinksTests(unittest.TestCase):
    def test_ignores_external_and_mailto_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            doc = root / "doc.md"
            doc.write_text(
                "[site](https://example.com) [mail](mailto:a@example.com)\n", encoding="utf-8"
            )
            with patch.object(check_docs, "ROOT", root):
                self.assertEqual(check_docs.validate_links([doc]), [])

    def test_accepts_existing_target_and_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "target.md").write_text("# Section One\n", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text("[link](target.md#section-one)\n", encoding="utf-8")
            with patch.object(check_docs, "ROOT", root):
                self.assertEqual(check_docs.validate_links([doc]), [])

    def test_rejects_missing_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            doc = root / "doc.md"
            doc.write_text("[link](missing.md)\n", encoding="utf-8")
            with patch.object(check_docs, "ROOT", root):
                errors = check_docs.validate_links([doc])
            self.assertTrue(any("missing link target missing.md" in error for error in errors))

    def test_rejects_missing_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "target.md").write_text("# Section One\n", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text("[link](target.md#missing-section)\n", encoding="utf-8")
            with patch.object(check_docs, "ROOT", root):
                errors = check_docs.validate_links([doc])
            self.assertTrue(any("missing anchor #missing-section" in error for error in errors))


class ValidateMakeTargetsTests(unittest.TestCase):
    def test_accepts_known_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "Makefile").write_text("build: ## Build\n\techo build\n", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text("Run `make build` to compile.\n", encoding="utf-8")
            with patch.object(check_docs, "ROOT", root):
                self.assertEqual(check_docs.validate_make_targets([doc]), [])

    def test_rejects_unknown_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "Makefile").write_text("build: ## Build\n\techo build\n", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text("Run `make deploy` to ship.\n", encoding="utf-8")
            with patch.object(check_docs, "ROOT", root):
                errors = check_docs.validate_make_targets([doc])
            self.assertTrue(any("unknown Make target deploy" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
