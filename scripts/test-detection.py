#!/usr/bin/env python3
"""Run real scanner regressions against synthetic vulnerable/fixed controls."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import string
import subprocess
import tempfile


def run(command, expected=(0,), env=None):
    completed = subprocess.run([str(arg) for arg in command], env=env)
    if completed.returncode not in expected:
        raise RuntimeError(f"Scanner exited {completed.returncode}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--codeql", help="Also verify reflected and DOM XSS with a real CodeQL bundle")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    (repo / ".cache").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="detection-", dir=repo / ".cache"))
    source = work / "source"
    shutil.copytree(repo / "testdata/scanning", source)
    # This randomly generated token has a provider-shaped format but was never
    # issued by any provider. Do not test with real credentials.
    token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (source / "vulnerable/settings.env").write_text(f"SERVICE_API_KEY={token}\n", encoding="utf-8")
    (source / "fixed/settings.env").write_text("SERVICE_API_KEY=${SERVICE_API_KEY}\n", encoding="utf-8")
    secret_report = work / "secrets.sarif"
    run([args.gitleaks, "dir", source, "--config", repo / "config/gitleaks.toml",
         "--report-format=sarif", f"--report-path={secret_report}", "--redact=100",
         "--no-banner", "--no-color", "--exit-code=10"], expected=(10,))
    raw = secret_report.read_text(encoding="utf-8")
    assert token not in raw, "Secret must not be retained in SARIF"
    secret_results = json.loads(raw)["runs"][0]["results"]
    assert any(r["ruleId"] == "github-pat" for r in secret_results), "Synthetic API key was missed"
    assert all("fixed/" not in json.dumps(r).replace("\\\\", "/") for r in secret_results), "Secret false positive in fixed control"
    print("PASS: real Gitleaks detected the synthetic API key, redacted it, and passed the fixed control.", flush=True)

    if args.codeql:
        env = dict(os.environ)
        temp = work / "tmp"
        temp.mkdir()
        env.update(TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
        common = f"--common-caches={work / 'codeql-cache'}"
        database, codeql_report = work / "database", work / "codeql.sarif"
        run([args.codeql, "database", "create", database, "--language=javascript-typescript",
             f"--source-root={source}", f"--codescanning-config={repo / 'codeql/javascript-config.yml'}", common], env=env)
        run([args.codeql, "database", "analyze", database,
             "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
             "--format=sarifv2.1.0", f"--output={codeql_report}", "--threads=2", "--ram=2048",
             "--sarif-add-baseline-file-info", common], env=env)
        results = [result for report_run in json.loads(codeql_report.read_text(encoding="utf-8"))["runs"] for result in report_run["results"]]
        for rule, file in (("js/reflected-xss", "vulnerable/server.ts"), ("js/xss", "vulnerable/browser.js")):
            assert any(result.get("ruleId") == rule and any(
                location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "").endswith(file)
                for location in result.get("locations", [])) for result in results), f"Missed {rule} in {file}"
        assert not any(result.get("ruleId") in ("js/reflected-xss", "js/xss") and any(
            "/fixed/" in "/" + location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            for location in result.get("locations", [])) for result in results), "XSS false positive in fixed control"
        spec = importlib.util.spec_from_file_location("merge_sarif", repo / "scripts/merge-sarif.py")
        merger = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(merger)
        combined = merger.merge_reports(codeql_report, secret_report, source)
        (work / "combined.sarif").write_text(json.dumps(combined), encoding="utf-8")
        print("PASS: real CodeQL detected reflected/DOM XSS and passed the fixed controls.", flush=True)
    print(f"Reports and fixtures: {work}")


if __name__ == "__main__":
    main()
