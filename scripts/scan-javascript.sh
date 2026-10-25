#!/usr/bin/env bash
# Run inside the Linux CodeBuild scanner after docker cp has extracted /app/.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: bash scripts/scan-javascript.sh SOURCE_ROOT DATABASE_DIR REPORT.sarif" >&2
  exit 2
fi

command -v codeql >/dev/null || { echo "CodeQL CLI bundle is required." >&2; exit 2; }
command -v node >/dev/null || { echo "Node.js is required for TypeScript extraction." >&2; exit 2; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
config="$script_dir/../codeql/javascript-config.yml"
source_root=$(realpath -e -- "$1")
database=$(realpath -m -- "$2")
report=$(realpath -m -- "$3")
suite=${CODEQL_SUITE:-security-extended}
require_typescript=${REQUIRE_TYPESCRIPT:-0}

[[ -d "$source_root" ]] || { echo "Source root must be a directory." >&2; exit 2; }
[[ ! -e "$database" && ! -e "$report" ]] || {
  echo "Database and report paths must be new to prevent reuse of stale scan results." >&2
  exit 2
}
for output in "$database" "$report"; do
  if [[ "$output" == "$source_root" || "$output" == "$source_root/"* ]]; then
    echo "Database and report must be outside the source root." >&2
    exit 2
  fi
done
case "$suite" in
  code-scanning|security-extended|security-and-quality) ;;
  *) echo "Unsupported CODEQL_SUITE: $suite" >&2; exit 2 ;;
esac
case "$require_typescript" in
  0|1) ;;
  *) echo "REQUIRE_TYPESCRIPT must be 0 or 1." >&2; exit 2 ;;
esac

# Use the same exclusions as javascript-config.yml, and do not count .d.ts
# declaration files as proof that application TypeScript survived the image build.
source_files=0
typescript_files=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.d.ts|*.d.mts|*.d.cts) continue ;;
    *.ts|*.tsx|*.mts|*.cts) typescript_files=$((typescript_files + 1)) ;;
  esac
  source_files=$((source_files + 1))
done < <(find "$source_root" \
  -type d \( -name node_modules -o -name dist -o -name build -o -name coverage -o -name .git \) -prune -o \
  -type f \( -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' \
    -o -name '*.ts' -o -name '*.tsx' -o -name '*.mts' -o -name '*.cts' \) -print0)
# Process substitutions do not inherit errexit into the parent shell. Ensure an
# unreadable directory cannot silently turn the inventory into a partial scan.
wait "$!"

if (( source_files == 0 )); then
  echo "No application JavaScript/TypeScript found. Check the image stage and docker cp source path." >&2
  exit 2
fi
if [[ "$require_typescript" == 1 ]] && (( typescript_files == 0 )); then
  echo "TypeScript source is missing. Build and push the Docker builder stage, retaining the raw source." >&2
  exit 2
fi

echo "Source preflight: $source_files JavaScript/TypeScript files, including $typescript_files TypeScript files."
echo "These counts are source inventory, not proof of successful CodeQL extraction."
codeql version
node --version

codeql database create "$database" \
  --language=javascript-typescript \
  --source-root="$source_root" \
  --codescanning-config="$config"

# JavaScript/TypeScript extraction must not be replaced with --command='npm ...'.
# The bundle must contain a compatible codeql/javascript-queries pack.
mkdir -p -- "$(dirname -- "$report")"
codeql database analyze "$database" \
  "codeql/javascript-queries:codeql-suites/javascript-$suite.qls" \
  --format=sarifv2.1.0 \
  --output="$report" \
  --sarif-add-baseline-file-info \
  --sarif-include-query-help=always \
  --threads="${CODEQL_THREADS:-2}"

[[ -s "$report" ]] || { echo "CodeQL did not produce a SARIF report." >&2; exit 2; }
echo "SARIF report: $report"
