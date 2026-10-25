#!/usr/bin/env python3
"""Package the trusted CodeBuild scanner source for an S3 source project."""

from pathlib import Path
import sys
import zipfile

from scanner_source import SCANNER_FILES

repo = Path(__file__).resolve().parent.parent
files = ["buildspec.yml", *SCANNER_FILES]
if len(sys.argv) != 2:
    sys.exit("Usage: package-scanner.py OUTPUT.zip")
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
    for name in files:
        archive.write(repo / name, name)
print(output.resolve())
