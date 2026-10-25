#!/usr/bin/env bash
# Contract tests for scan orchestration; the fake CodeQL does not analyze code.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$repo/.cache"
scratch=$(mktemp -d "$repo/.cache/scanner-contract.XXXXXX")
mkdir -p "$scratch/bin" "$scratch/typescript" "$scratch/javascript" "$scratch/empty" "$scratch/declarations" "$scratch/generated/dist"
export MOCK_LOG="$scratch/codeql.log"
cat > "$scratch/bin/codeql" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_LOG"
if [[ "${2:-}" == "${MOCK_FAIL_STEP:-never}" ]]; then exit 17; fi
if [[ "$1" == database && "$2" == analyze ]]; then
  for arg in "$@"; do
    if [[ "$arg" == --output=* ]]; then printf '{}\n' > "${arg#--output=}"; fi
  done
fi
MOCK
chmod +x "$scratch/bin/codeql"
export PATH="$scratch/bin:$PATH"
printf 'export const name: string = "test";\n' > "$scratch/typescript/app.ts"
printf 'console.log("test");\n' > "$scratch/javascript/app.js"
printf 'declare const name: string;\n' > "$scratch/declarations/app.d.ts"
printf 'console.log("test");\n' > "$scratch/generated/dist/app.js"
scanner="$repo/scripts/scan-javascript.sh"

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

expect_status 0 env REQUIRE_TYPESCRIPT=1 bash "$scanner" "$scratch/typescript" "$scratch/ts-db" "$scratch/ts.sarif"
grep -q -- '--language=javascript-typescript' "$MOCK_LOG"
grep -q -- 'javascript-security-extended.qls' "$MOCK_LOG"
grep -q -- '--sarif-add-baseline-file-info' "$MOCK_LOG"
if grep -q -- '--command' "$MOCK_LOG"; then echo 'Unexpected build command' >&2; exit 1; fi
expect_status 0 env CODEQL_SUITE=security-and-quality bash "$scanner" "$scratch/javascript" "$scratch/js-db" "$scratch/js.sarif"
grep -q -- 'javascript-security-and-quality.qls' "$MOCK_LOG"
expect_status 2 env REQUIRE_TYPESCRIPT=1 bash "$scanner" "$scratch/javascript" "$scratch/missing-ts-db" "$scratch/missing-ts.sarif"
expect_status 2 env REQUIRE_TYPESCRIPT=1 bash "$scanner" "$scratch/declarations" "$scratch/decl-db" "$scratch/decl.sarif"
expect_status 2 bash "$scanner" "$scratch/empty" "$scratch/empty-db" "$scratch/empty.sarif"
expect_status 2 bash "$scanner" "$scratch/generated" "$scratch/generated-db" "$scratch/generated.sarif"
expect_status 2 bash "$scanner" "$scratch/typescript" "$scratch/typescript/nested-db" "$scratch/nested.sarif"
expect_status 2 bash "$scanner" "$scratch/typescript" "$scratch/new-db" "$scratch/ts.sarif"
expect_status 2 env CODEQL_SUITE=invalid bash "$scanner" "$scratch/typescript" "$scratch/suite-db" "$scratch/suite.sarif"
expect_status 2 env REQUIRE_TYPESCRIPT=invalid bash "$scanner" "$scratch/typescript" "$scratch/flag-db" "$scratch/flag.sarif"

: > "$MOCK_LOG"
expect_status 17 env MOCK_FAIL_STEP=create bash "$scanner" "$scratch/typescript" "$scratch/fail-db" "$scratch/fail.sarif"
if grep -q -- 'database analyze' "$MOCK_LOG"; then echo 'Analysis ran after extraction failed' >&2; exit 1; fi
expect_status 17 env MOCK_FAIL_STEP=analyze bash "$scanner" "$scratch/typescript" "$scratch/analyze-db" "$scratch/analyze.sarif"
[[ ! -e "$scratch/analyze.sarif" ]]
echo "Scanner orchestration contract tests passed. Fixtures: $scratch"
