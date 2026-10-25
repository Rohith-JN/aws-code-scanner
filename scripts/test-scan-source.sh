#!/usr/bin/env bash
# Exercise the multi-engine scanner with fake engines; no Docker or AWS calls.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$repo/.cache"
scratch=$(mktemp -d "$repo/.cache/source-contract.XXXXXX")
mkdir -p "$scratch/bin" "$scratch/source"
export MOCK_LOG="$scratch/commands.log"
printf 'export const name = "test";\n' > "$scratch/source/app.ts"
cat > "$scratch/bin/codeql" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_LOG"
if [[ "${2:-}" == "${MOCK_CODEQL_FAIL:-never}" ]]; then exit 17; fi
if [[ "$1" == database && "$2" == analyze ]]; then
  for arg in "$@"; do
    if [[ "$arg" == --output=* ]]; then
      printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[]}]}' > "${arg#--output=}"
    fi
  done
fi
MOCK
cat > "$scratch/bin/gitleaks" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" != version ]] || exit 0
printf '%s\n' "$*" >> "$MOCK_LOG"
for arg in "$@"; do
  if [[ "$arg" == --report-path=* ]]; then
    printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[]}},"results":[]}]}' > "${arg#--report-path=}"
  fi
done
exit "${MOCK_GITLEAKS_STATUS:-0}"
MOCK
chmod +x "$scratch/bin/codeql" "$scratch/bin/gitleaks"
export PATH="$scratch/bin:$PATH"
scanner="$repo/scripts/scan-source.sh"

expect_status() {
  local expected=$1
  shift
  local actual=0
  "$@" > "$scratch/output.log" 2>&1 || actual=$?
  if [[ "$actual" != "$expected" ]]; then
    cat "$scratch/output.log" >&2
    echo "Expected exit $expected, got $actual: $*" >&2
    exit 1
  fi
}

expect_status 0 env LANGUAGE=typescript BUILD_COMMAND='must-not-run' REQUIRE_TYPESCRIPT=1 \
  bash "$scanner" "$scratch/source" "$scratch/analysis" "$scratch/combined.sarif"
grep -q -- '--redact=100' "$MOCK_LOG"
if grep -q -- '--command' "$MOCK_LOG"; then echo 'Unexpected JS build command' >&2; exit 1; fi
"${PYTHON_BINARY:-python3}" -c 'import json,sys; assert len(json.load(open(sys.argv[1]))["runs"]) == 2' "$scratch/combined.sarif"
expect_status 0 env MOCK_GITLEAKS_STATUS=10 bash "$scanner" "$scratch/source" "$scratch/findings" "$scratch/findings.sarif"
expect_status 1 env MOCK_GITLEAKS_STATUS=1 bash "$scanner" "$scratch/source" "$scratch/secret-failure" "$scratch/secret-failure.sarif"
[[ ! -e "$scratch/secret-failure.sarif" ]]
expect_status 17 env MOCK_CODEQL_FAIL=create bash "$scanner" "$scratch/source" "$scratch/extract-failure" "$scratch/extract-failure.sarif"
[[ ! -e "$scratch/extract-failure.sarif" ]]
expect_status 17 env MOCK_CODEQL_FAIL=analyze bash "$scanner" "$scratch/source" "$scratch/query-failure" "$scratch/query-failure.sarif"
[[ ! -e "$scratch/query-failure.sarif" ]]
expect_status 2 bash "$scanner" "$scratch/source" "$scratch/retry" "$scratch/combined.sarif"
expect_status 2 env LANGUAGE=unsupported bash "$scanner" "$scratch/source" "$scratch/unsupported" "$scratch/unsupported.sarif"
expect_status 0 env LANGUAGE=java-kotlin BUILD_COMMAND='mvn compile' \
  bash "$scanner" "$scratch/source" "$scratch/java" "$scratch/java.sarif"
grep -q -- 'java-security-extended.qls' "$MOCK_LOG"
grep -q -- '--command=mvn compile' "$MOCK_LOG"

# Run image extraction from an isolated copy of the scanner source. The fake
# Docker engine checks that /app/. is copied and never starts the target image.
cloud="$scratch/cloud"
mkdir -p "$cloud/scripts" "$cloud/codeql" "$cloud/config"
cp "$repo/scripts/scan-image.sh" "$repo/scripts/scan-source.sh" "$repo/scripts/scan-javascript.sh" "$repo/scripts/merge-sarif.py" "$cloud/scripts/"
cp "$repo/codeql/javascript-config.yml" "$cloud/codeql/"
cp "$repo/config/gitleaks.toml" "$cloud/config/"
export MOCK_SOURCE="$scratch/source"
cat > "$scratch/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
case "$1" in
  pull|rm) ;;
  create) echo mock-container ;;
  cp)
    [[ "$2" == 'mock-container:/app/.' ]] || exit 19
    cp "$MOCK_SOURCE/app.ts" "$3/app.ts"
    ;;
  *) echo 'Unexpected Docker command' >&2; exit 19 ;;
esac
MOCK
chmod +x "$scratch/bin/docker"
expect_status 0 env IMAGE_URI=example.registry/user-2/app:scan ECR_REGISTRY=example.registry \
  bash "$cloud/scripts/scan-image.sh"
[[ -s "$cloud/report.sarif" ]]
grep -q -- 'docker cp mock-container:/app/.' "$MOCK_LOG"

# Check the actual post_build shell block against a fake AWS CLI. This extracts
# our fixed block layout; it is not a general YAML parser.
"${PYTHON_BINARY:-python3}" -c 'import pathlib,sys,textwrap; text=pathlib.Path(sys.argv[1]).read_text(); block=text.split("  post_build:\n",1)[1].split("      - |\n",1)[1]; pathlib.Path(sys.argv[2]).write_text(textwrap.dedent(block))' \
  "$repo/buildspec.yml" "$scratch/post-build.sh"
cat > "$scratch/bin/aws" <<'MOCK'
#!/usr/bin/env bash
printf 'aws %s\n' "$*" >> "$MOCK_LOG"
exit "${MOCK_AWS_STATUS:-0}"
MOCK
chmod +x "$scratch/bin/aws"
pushd "$cloud" >/dev/null
export IMAGE_URI=example.registry/user-2/app:scan BUCKET_NAME=reports-bucket
export CODEBUILD_BUILD_ID=code-scanner:fixture SCAN_REGION=ap-south-2
expect_status 0 env CODEBUILD_BUILD_SUCCEEDING=1 bash "$scratch/post-build.sh"
grep -q -- 's3://reports-bucket/reports/user-2/codeql-scan-code-scanner:fixture.sarif' "$MOCK_LOG"
upload_count=$(grep -c '^aws ' "$MOCK_LOG")
expect_status 1 env CODEBUILD_BUILD_SUCCEEDING=0 bash "$scratch/post-build.sh"
[[ "$(grep -c '^aws ' "$MOCK_LOG")" == "$upload_count" ]]
expect_status 17 env CODEBUILD_BUILD_SUCCEEDING=1 MOCK_AWS_STATUS=17 bash "$scratch/post-build.sh"
popd >/dev/null
echo "Multi-engine scanner contract tests passed. Fixtures: $scratch"
