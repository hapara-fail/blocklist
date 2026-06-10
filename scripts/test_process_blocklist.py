from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts import process_blocklist


def validate_lines(lines: list[str]):
    validator = process_blocklist.BlocklistValidator()
    validator.reset(Path("fixture.txt"))
    for line_num, line in enumerate(lines, 1):
        validator.validate_line(line, line_num)
    return validator.result


class BlocklistValidatorTests(unittest.TestCase):
    def test_dns_compatible_domain_rules_pass(self) -> None:
        result = validate_lines([
            "||example.com^\n",
            "@@||pass.example.com^\n",
        ])

        self.assertEqual(result.errors, [])
        self.assertEqual(result.rule_counts, {"block": 1, "allow": 1})

    def test_browser_only_abp_rules_are_counted_but_fail_dns_compatibility(self) -> None:
        cases = [
            ("example.com##.ad\n", "cosmetic", "E014"),
            ("example.com#?#.ad:-abp-has(.sponsored)\n", "extended-css", "E014"),
            ("example.com#$#hide-if-contains\n", "scriptlet", "E014"),
            ("||example.com/banner.js\n", "block", "E015"),
            ("/ads/*$script\n", "block", "E015"),
            ("@@advice\n", "allow", "E015"),
            (r"/ad\d+/$image" + "\n", "regex", "E015"),
            ("||example.com^$csp=script-src 'none'\n", "block", "E015"),
        ]

        for line, category, code in cases:
            with self.subTest(line=line.strip()):
                result = validate_lines([line])
                self.assertEqual(result.rule_counts.get(category), 1)
                self.assertIn(code, {diag.code for diag in result.errors})

    def test_malformed_rules_fail_with_specific_diagnostics(self) -> None:
        cases = [
            ("##\n", "E006"),
            ("#@#\n", "E006"),
            ("/[/\n", "E011"),
            ("0.0.0.0 example.com\n", "E003"),
        ]

        for line, code in cases:
            with self.subTest(line=line.strip()):
                result = validate_lines([line])
                self.assertIn(code, {diag.code for diag in result.errors})

    def test_duplicate_rules_are_detected(self) -> None:
        result = validate_lines([
            "||example.com^\n",
            "||EXAMPLE.com^\n",
        ])

        duplicates = [diag for diag in result.errors if diag.code == "E008"]
        self.assertEqual(len(duplicates), 1)
        self.assertTrue(duplicates[0].fixable)

    def test_simple_missing_separator_remains_fixable(self) -> None:
        result = validate_lines(["||example.com\n"])

        self.assertIn("W004", {diag.code for diag in result.warnings})
        self.assertNotIn("E015", {diag.code for diag in result.errors})

    def test_unknown_options_warn_and_alias_conflicts_error(self) -> None:
        unknown = validate_lines(["||example.com^$not-a-standard-option\n"])
        self.assertIn("W006", {diag.code for diag in unknown.warnings})

        conflict = validate_lines(["||example.com^$third-party,~3p\n"])
        self.assertIn("E012", {diag.code for diag in conflict.errors})

    def test_process_file_revalidates_after_fixing_safe_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture = Path(tmp_dir) / "fixture.txt"
            fixture.write_text(
                "\n".join([
                    "[Adblock Plus]",
                    "! Number of entries: 0",
                    "! Last modified: old",
                    "! Version: old",
                    "",
                    "||example.com",
                    "||EXAMPLE.com^",
                    "||EXAMPLE.com^",
                ]) + "\n",
                encoding="utf-8",
            )

            with redirect_stdout(io.StringIO()):
                result = process_blocklist.process_file(
                    fixture,
                    fix=True,
                    dry_run=False,
                    rel_path="fixture.txt",
                )

            self.assertTrue(result.is_valid())
            self.assertEqual(result.total_rules, 1)
            self.assertIn("! Number of entries: 1", fixture.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
