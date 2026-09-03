from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from scripts import generate_blocklist as generator


HEADER = "action,domain,service,category,description,source,added\n"
NOW = datetime(2026, 9, 3, 20, 0, tzinfo=timezone.utc)


def load_fixture(body: str) -> list[generator.Entry]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "entries.csv"
        path.write_text(HEADER + body, encoding="utf-8", newline="")
        return generator.load_entries(path)


class CanonicalValidationTests(unittest.TestCase):
    def test_valid_rows_are_normalized_and_sorted(self) -> None:
        entries = load_fixture(
            "block,Z.example,Product,monitoring,,,\n"
            "allow,bücher.example,Product,monitoring,Needed exception,https://example.com/evidence,2026-09-03\n"
        )
        self.assertEqual([entry.domain for entry in entries], ["xn--bcher-kva.example", "z.example"])
        self.assertEqual(entries[0].unicode_domain, "bücher.example")

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        entries = load_fixture("# grouped entries\n\nblock,example.com,Product,filtering,,,\n")
        self.assertEqual(len(entries), 1)

    def test_invalid_domains_are_rejected(self) -> None:
        for domain in ("example", "https://example.com", "*.example.com", "bad_.example", "127.0.0.1"):
            with self.subTest(domain=domain):
                with self.assertRaises(generator.ValidationError):
                    load_fixture(f"block,{domain},Product,filtering,,,\n")

    def test_duplicate_normalized_domains_are_rejected(self) -> None:
        with self.assertRaisesRegex(generator.ValidationError, "duplicate domain"):
            load_fixture(
                "block,EXAMPLE.com,Product,filtering,,,\n"
                "block,example.com,Product,filtering,,,\n"
            )

    def test_required_and_structured_metadata_are_validated(self) -> None:
        invalid_rows = (
            "block,example.com,,filtering,,,\n",
            "block,example.com,Product,unknown,,,\n",
            "block,example.com,Product,filtering,,not-a-url,\n",
            "block,example.com,Product,filtering,,,09/03/2026\n",
        )
        for row in invalid_rows:
            with self.subTest(row=row):
                with self.assertRaises(generator.ValidationError):
                    load_fixture(row)


class FormatGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = load_fixture(
            "block,sub.example.com,Product,filtering,Telemetry,https://example.com/source,2026-09-03\n"
            "allow,pass.example.com,Product,filtering,Required endpoint,,\n"
            "block,example.com,Product,filtering,,,\n"
        )
        self.outputs = generator.render_outputs(self.entries, NOW)

    def test_every_documented_output_is_generated(self) -> None:
        self.assertEqual(
            set(self.outputs),
            {"adblock.txt", "domains.txt", "hosts.txt", "dnsmasq.conf", "unbound.conf", "blocklist.rpz", "blocklist.json", "blocklist.csv"},
        )

    def test_adblock_syntax_and_exception(self) -> None:
        output = self.outputs["adblock.txt"]
        self.assertTrue(output.startswith("[Adblock Plus 2.0]\n"))
        self.assertIn("||example.com^\n", output)
        self.assertIn("@@||pass.example.com^\n", output)

    def test_plain_domains_are_block_only_and_sorted(self) -> None:
        self.assertEqual(self.outputs["domains.txt"], "example.com\nsub.example.com\n")

    def test_hosts_uses_zero_address_and_exact_hostnames(self) -> None:
        output = self.outputs["hosts.txt"]
        self.assertIn("0.0.0.0 example.com\n", output)
        self.assertNotIn("pass.example.com", output)

    def test_dnsmasq_uses_nxdomain_zone_syntax(self) -> None:
        output = self.outputs["dnsmasq.conf"]
        self.assertIn("address=/example.com/\n", output)
        self.assertNotIn("address=/example.com/#", output)

    def test_unbound_uses_always_nxdomain_local_zones(self) -> None:
        output = self.outputs["unbound.conf"]
        self.assertIn('local-zone: "example.com." always_nxdomain\n', output)

    def test_rpz_has_structure_and_both_qname_triggers(self) -> None:
        output = self.outputs["blocklist.rpz"]
        self.assertIn("$ORIGIN rpz.hapara.fail.\n", output)
        self.assertIn("@ IN SOA localhost. hostmaster.hapara.fail. (\n", output)
        self.assertIn("1788465600 ; serial (Unix timestamp)\n", output)
        self.assertIn("example.com CNAME .\n*.example.com CNAME .\n", output)

    def test_json_matches_stable_shape_and_metadata(self) -> None:
        payload = json.loads(self.outputs["blocklist.json"])
        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertEqual(payload["list_version"], "202609032000")
        self.assertEqual(payload["update_interval_hours"], 72)
        self.assertEqual(payload["entry_count"], 3)
        self.assertEqual(payload["block_entry_count"], 2)
        self.assertEqual(payload["allow_entry_count"], 1)
        self.assertEqual(payload["entries"][0]["description"], "")

    def test_csv_is_valid_and_preserves_metadata(self) -> None:
        rows = list(csv.DictReader(io.StringIO(self.outputs["blocklist.csv"])))
        self.assertEqual(len(rows), 3)
        telemetry = next(row for row in rows if row["domain"] == "sub.example.com")
        self.assertEqual(telemetry["description"], "Telemetry")

    def test_csv_escapes_commas_in_metadata(self) -> None:
        entries = load_fixture('block,example.com,Product,filtering,"Telemetry, API",,\n')
        output = generator.render_outputs(entries, NOW)["blocklist.csv"]
        row = next(csv.DictReader(io.StringIO(output)))
        self.assertEqual(row["description"], "Telemetry, API")

    def test_json_schema_declares_the_generated_contract(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "blocklist.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        payload = json.loads(self.outputs["blocklist.json"])
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
        self.assertEqual(set(payload), set(schema["required"]))
        self.assertEqual(
            set(payload["entries"][0]),
            set(schema["$defs"]["entry"]["required"]),
        )

    def test_generation_is_deterministic_for_a_fixed_timestamp(self) -> None:
        self.assertEqual(self.outputs, generator.render_outputs(reversed(self.entries), NOW))

    def test_write_and_check_cover_every_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_dir = root / "dist"
            legacy = root / "blocklist.txt"
            generator.write_outputs(self.outputs, output_dir, legacy)
            self.assertEqual(generator.check_outputs(self.outputs, output_dir, legacy), [])
            (output_dir / "hosts.txt").write_text("stale\n", encoding="utf-8")
            self.assertEqual(generator.check_outputs(self.outputs, output_dir, legacy), [output_dir / "hosts.txt"])


if __name__ == "__main__":
    unittest.main()
