import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("merge_sarif", Path(__file__).with_name("merge-sarif.py"))
merger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merger)


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.codeql = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]}
        self.secrets = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks", "rules": [{"id": "github-pat"}]}}, "results": []}]}

    def merge(self):
        codeql_path, secrets_path = self.root / "codeql.sarif", self.root / "secrets.sarif"
        codeql_path.write_text(json.dumps(self.codeql), encoding="utf-8")
        secrets_path.write_text(json.dumps(self.secrets), encoding="utf-8")
        return merger.merge_reports(codeql_path, secrets_path, self.root)

    def test_preserves_codeql_and_classifies_redacted_secrets(self):
        self.codeql["runs"][0]["results"] = [{"ruleId": "js/reflected-xss", "codeFlows": [{"threadFlows": []}]}]
        self.secrets["runs"][0]["results"] = [{
            "ruleId": "github-pat", "message": {"text": "Original message"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(self.root / "settings.env")},
                "region": {"startLine": 3, "snippet": {"text": "synthetic-sensitive-value"}},
                "contextRegion": {"snippet": {"text": "synthetic-sensitive-value"}},
            }}],
        }]
        merged = self.merge()
        self.assertEqual(merged["runs"][0], self.codeql["runs"][0])
        secret_run = merged["runs"][1]
        self.assertIn("security", secret_run["tool"]["driver"]["rules"][0]["properties"]["tags"])
        self.assertNotIn("synthetic-sensitive-value", json.dumps(merged))
        physical = secret_run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"]["uri"], "settings.env")
        self.assertEqual(physical["region"]["startLine"], 3)

    def test_clean_secret_scan_still_has_a_run(self):
        merged = self.merge()
        self.assertEqual(len(merged["runs"]), 2)
        self.assertEqual(merged["runs"][1]["results"], [])

    def test_failed_execution_is_rejected(self):
        self.codeql["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        with self.assertRaisesRegex(ValueError, "execution failed"):
            self.merge()

    def test_error_diagnostics_are_rejected(self):
        self.codeql["runs"][0]["invocations"] = [{"toolExecutionNotifications": [{"level": "error"}]}]
        with self.assertRaisesRegex(ValueError, "error diagnostic"):
            self.merge()

    def test_missing_results_is_rejected(self):
        self.secrets["runs"][0].pop("results")
        with self.assertRaisesRegex(ValueError, "results array"):
            self.merge()

    def test_wrong_secret_scanner_is_rejected(self):
        self.secrets["runs"][0]["tool"]["driver"]["name"] = "other"
        with self.assertRaisesRegex(ValueError, "Expected a Gitleaks"):
            self.merge()


if __name__ == "__main__":
    unittest.main()
