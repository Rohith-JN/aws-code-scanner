#!/usr/bin/env bash
# Analyze an already-extracted source tree, then merge results for the Go CLI.
set -euo pipefail
[[ $# == 3 ]] || { echo 'Usage: scan-source.sh SOURCE_ROOT WORK_DIR REPORT.sarif' >&2; exit 2; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_root=$(realpath -e -- "$1")
work_dir=$(realpath -m -- "$2")
report=$(realpath -m -- "$3")
[[ -d "$source_root" && ! -e "$work_dir" && ! -e "$report" ]] || {
  echo 'Source must exist; work directory and report must be new.' >&2; exit 2;
}
for output in "$work_dir" "$report"; do
  [[ "$output" != "$source_root" && "$output" != "$source_root/"* ]] || {
    echo 'Work directory and report must be outside the source root.' >&2; exit 2;
  }
done
language=${LANGUAGE:-javascript-typescript}
case "$language" in
  javascript|typescript|javascript-typescript) language=javascript-typescript; suite_language=javascript ;;
  python|go|ruby|csharp|swift|rust) suite_language=$language ;;
  java|kotlin|java-kotlin) language=java-kotlin; suite_language=java ;;
  c|cpp|c-cpp) language=c-cpp; suite_language=cpp ;;
  *) echo "Unsupported CodeQL language: $language" >&2; exit 2 ;;
esac
suite=${CODEQL_SUITE:-security-extended}
case "$suite" in
  code-scanning|security-extended|security-and-quality) ;;
  *) echo "Unsupported CODEQL_SUITE: $suite" >&2; exit 2 ;;
esac
mkdir -p "$work_dir"

if [[ "$language" == javascript-typescript ]]; then
  if [[ -n "${BUILD_COMMAND:-}" ]]; then
    echo 'Ignoring BUILD_COMMAND for JavaScript/TypeScript: extraction reads source directly.'
  fi
  bash "$script_dir/scan-javascript.sh" "$source_root" "$work_dir/codeql-db" "$work_dir/codeql.sarif"
else
  create_args=(database create "$work_dir/codeql-db" "--language=$language" "--source-root=$source_root")
  if [[ "$language" != python && "$language" != ruby && -n "${BUILD_COMMAND:-}" ]]; then
    create_args+=("--command=$BUILD_COMMAND")
  fi
  codeql "${create_args[@]}"
  codeql database analyze "$work_dir/codeql-db" \
    "codeql/$suite_language-queries:codeql-suites/$suite_language-$suite.qls" \
    --format=sarifv2.1.0 --output="$work_dir/codeql.sarif" \
    --sarif-add-baseline-file-info --sarif-include-query-help=always \
    --threads="${CODEQL_THREADS:-2}"
fi

gitleaks version
secret_status=0
gitleaks dir "$source_root" \
  --config="$script_dir/../config/gitleaks.toml" \
  --report-format=sarif --report-path="$work_dir/secrets.sarif" \
  --redact=100 --no-banner --no-color --ignore-gitleaks-allow \
  --exit-code=10 || secret_status=$?
if [[ "$secret_status" != 0 && "$secret_status" != 10 ]]; then
  echo "Secret scanner failed (exit $secret_status); refusing to publish a partial report." >&2
  exit "$secret_status"
fi

"${PYTHON_BINARY:-python3}" "$script_dir/merge-sarif.py" \
  "$work_dir/codeql.sarif" "$work_dir/secrets.sarif" "$source_root" "$report"
echo "Combined report: $report"
