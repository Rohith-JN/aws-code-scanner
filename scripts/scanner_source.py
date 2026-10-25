"""Trusted files required by the CodeBuild scanner at runtime."""

SCANNER_FILES = (
    "scripts/install-scanners.sh",
    "scripts/scan-image.sh",
    "scripts/scan-source.sh",
    "scripts/scan-javascript.sh",
    "scripts/merge-sarif.py",
    "config/gitleaks.toml",
    "codeql/javascript-config.yml",
)
