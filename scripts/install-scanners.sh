#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: install-scanners.sh TOOLS_DIR' >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'This installer requires a Linux x86_64 CodeBuild environment.' >&2
  exit 2
}
for tool in curl tar sha256sum python3 node docker aws; do
  command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 2; }
done

tools=$(realpath -m -- "$1")
mkdir -p "$tools/bin"

# Update each version and checksum together. Keep the bundled queries matched
# to the CLI rather than downloading arbitrary newer packs during analysis.
codeql_version=2.27.3
codeql_sha256=64518dc413c8e7b5733fee2489e830a899bb1e3f28c8873b5869d5cc90164c5c
gitleaks_version=8.30.1
gitleaks_sha256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

curl --fail --location --retry 3 \
  "https://github.com/github/codeql-action/releases/download/codeql-bundle-v$codeql_version/codeql-bundle-linux64.tar.gz" \
  --output "$tools/codeql.tar.gz"
printf '%s  %s\n' "$codeql_sha256" "$tools/codeql.tar.gz" | sha256sum --check -
tar -xzf "$tools/codeql.tar.gz" -C "$tools"

curl --fail --location --retry 3 \
  "https://github.com/gitleaks/gitleaks/releases/download/v$gitleaks_version/gitleaks_${gitleaks_version}_linux_x64.tar.gz" \
  --output "$tools/gitleaks.tar.gz"
printf '%s  %s\n' "$gitleaks_sha256" "$tools/gitleaks.tar.gz" | sha256sum --check -
tar -xzf "$tools/gitleaks.tar.gz" -C "$tools/bin" gitleaks

"$tools/codeql/codeql" version
"$tools/bin/gitleaks" version
