#!/usr/bin/env python3
"""Preserve complete CodeQL runs and append redacted secret-scanner results."""

import json
from pathlib import Path
import sys


def read_report(path):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if report.get("version") != "2.1.0" or not report.get("runs"):
        raise ValueError(f"{path}: expected SARIF 2.1.0 with at least one run")
    for run in report["runs"]:
        if not run.get("tool", {}).get("driver", {}).get("name"):
            raise ValueError(f"{path}: missing scanner identity")
        if not isinstance(run.get("results"), list):
            raise ValueError(f"{path}: missing results array")
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise ValueError(f"{path}: scanner execution failed")
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                if any(n.get("level") == "error" for n in invocation.get(key, [])):
                    raise ValueError(f"{path}: scanner reported an error diagnostic")
    return report


def merge_reports(codeql_path, secrets_path, source_root):
    codeql = read_report(codeql_path)
    secrets = read_report(secrets_path)
    source_root = Path(source_root).resolve()
    for run in secrets["runs"]:
        driver = run["tool"]["driver"]
        if driver["name"].lower() != "gitleaks":
            raise ValueError("Expected a Gitleaks report for secret findings")
        # Gitleaks omits security tags and severity metadata in SARIF. Enrich
        # classification, without inventing a CVSS score for a pattern match.
        for rule in driver.get("rules", []):
            properties = rule.setdefault("properties", {})
            tags = properties.setdefault("tags", [])
            if "security" not in tags:
                tags.append("security")
            rule.setdefault("defaultConfiguration", {})["level"] = "warning"
        for result in run["results"]:
            result["message"] = {"text": "Potential exposed credential detected. Review this location."}
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                physical.pop("contextRegion", None)
                physical.get("region", {}).pop("snippet", None)
                artifact = physical.get("artifactLocation", {})
                uri = artifact.get("uri", "")
                try:
                    artifact["uri"] = Path(uri).relative_to(source_root).as_posix()
                except ValueError:
                    pass
        # The caller only invokes this merger for successful scans (exit 0 or
        # the configured findings exit code), including reports with no leaks.
        if not run.get("invocations"):
            run["invocations"] = [{"executionSuccessful": True}]
    codeql["runs"].extend(secrets["runs"])
    return codeql


def main():
    if len(sys.argv) != 5:
        raise ValueError("Usage: merge-sarif.py CODEQL.sarif SECRETS.sarif SOURCE_ROOT OUTPUT.sarif")
    combined = merge_reports(*sys.argv[1:4])
    output = Path(sys.argv[4])
    output.parent.mkdir(parents=True, exist_ok=True)
    # Never reuse or overwrite an older build's report.
    with output.open("x", encoding="utf-8") as handle:
        json.dump(combined, handle, separators=(",", ":"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Cannot produce combined SARIF: {error}", file=sys.stderr)
        sys.exit(2)
