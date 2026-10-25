# AWS Code Scanner

The Go CLI obtains temporary AWS credentials, pushes a local Docker image to ECR,
starts the `code-scanner` CodeBuild project, and displays SARIF from S3. The new
scanner runs CodeQL for semantic vulnerabilities and Gitleaks for exposed API
keys, tokens, and other supported credential patterns.

## Findings from the supplied buildspec

The original `security-and-quality` suite already included security checks.
Unused-variable findings do not demonstrate that security queries were omitted,
and selecting a broader suite alone cannot repair a missed XSS flow.

- CodeQL was pinned to 2.15.5. The replacement pins 2.27.3 with its matching query
  packs and a verified download checksum.
- Copying `container:/app/` could create an `app` subfolder, while cleanup targeted
  `extracted-source/dist`. The replacement copies `/app/.` into a fresh source root
  and excludes generated output during CodeQL extraction.
- A nonempty `BUILD_COMMAND` could override JavaScript/TypeScript extraction.
  These languages must use their source extractor directly. The replacement
  ignores that override for JavaScript/TypeScript, Python, and Ruby.
- Interpolating `javascript-typescript` into a suite filename produces the wrong
  name. Language aliases now map to canonical query-pack paths.
- There was no dedicated secret detector. Gitleaks now scans the extracted
  filesystem, including .env and configuration files. Dependencies and Git
  internals are excluded; compiled output remains in secret coverage.
- Upload was unconditional. The replacement publishes only after both engines
  finish and their reports merge successfully.

The target application's vulnerable samples are not in this repository. Add
custom TypeGraphQL/TypeORM models after reproducing a concrete missed flow with
the updated engine.

## CLI usage

Build the target application's source-bearing stage:

```sh
docker build --target builder -t project:scan .
```

Run the whole Go package:

```powershell
go run . --image project:scan --lang javascript-typescript --user user-2 --require-typescript
```

The CLI pushes an existing image; it does not select a Dockerfile stage. Verify
that the selected stage retains /app source, tsconfig.json, and package manifests.
A stage named builder alone does not guarantee this.

The default `--query-suite` is `security-extended`. Alternatives are
`code-scanning` and `security-and-quality`. `--require-typescript` fails if no
application TypeScript survives extraction; declaration files alone do not count.
JavaScript-only applications should omit that flag.

The client reads LAMBDA_URL and BUCKET_NAME from the environment or .env, uses
region ap-south-2, and retains the existing S3 key:
`reports/<user>/codeql-scan-<CodeBuild build ID>.sarif`.

### Interrupted Docker uploads

Transient network failures such as a broken pipe, connection reset, or truncated
push response are retried up to three attempts, with 2-second and 4-second waits.
Each failed response is closed before retrying. Authentication, permission,
certificate, and unknown errors stop immediately. CodeBuild starts only after a
push succeeds.

A failure on `192.168.65.1:3128` happens on Docker Desktop's proxy connection
during upload. Repeated failures require checking Docker Desktop's proxy settings
and network connectivity. Rerun the CLI after resolving the connection issue;
the source-stage image does not need to be rebuilt solely because a push failed.
See [Docker Desktop proxy settings](https://docs.docker.com/desktop/settings-and-maintenance/settings/#proxies).

## CodeBuild setup

The replacement buildspec.yml invokes trusted scanner files from this repository.
It downloads CodeQL 2.27.3 and Gitleaks 8.30.1, verifies pinned SHA-256 checksums,
extracts source, scans, combines SARIF runs, and uploads to the existing S3 key.

Findings do not fail the cloud job: the local CLI receives them and applies its
failure policy. Engine failures fail the cloud job and prevent partial uploads.

CodeBuild needs Linux x86_64, Docker privileged mode, AWS CLI, Bash, GNU utilities,
Python 3, and Node.js supported by the pinned CodeQL version. Other language modes
need their respective toolchains. Use adequate memory for CodeQL and budget
timeouts and temporary credential duration for the scan. For repeated scans,
preinstall the pinned tools in a scanner image to avoid downloading every build.

If the project uses **NO_SOURCE** or does not download this repository, paste the
entire contents of **buildspec.inline.yml** into its inline buildspec editor.
This version creates the trusted scanner scripts and configuration before running
installation. It does not need a source ZIP or a change to the source provider.
Pasting only buildspec.yml into an empty-source project fails with
`scripts/install-scanners.sh: No such file or directory`.

The inline buildspec is generated from the same production files; regenerate it
after changing those files:

```powershell
python scripts/generate-inline-buildspec.py buildspec.inline.yml
```

If this repository is CodeBuild's source, select buildspec.yml. Alternatively,
package a trusted S3 source archive:

```powershell
python scripts/package-scanner.py .cache/scanner-source.zip
```

Upload that ZIP to a location readable by CodeBuild, select it as the project's
S3 source, and select buildspec.yml. The ZIP contains production scripts and
configuration at its root. These local changes do not deploy AWS resources.

The defaults retain the supplied registry, region, and bucket.
CONTAINER_SOURCE_PATH overrides /app. The CLI passes LANGUAGE, BUILD_COMMAND,
CODEQL_SUITE, and REQUIRE_TYPESCRIPT as build overrides. CODEQL_THREADS overrides
the default of two query threads.

The scanner creates a container without starting it, copies /app/. into fresh
source, and keeps databases/reports outside that source. CodeQL exclusions live
in codeql/javascript-config.yml. Adjust the conventional dist, build, and coverage
exclusions if authored source lives there. Source inventory counts do not prove
successful extraction; inspect CodeQL diagnostics and baselines for coverage.

Gitleaks uses config/gitleaks.toml with its provider and generic rules. It redacts
detected values, and the merger removes secret snippets while retaining rule IDs
and locations. Matches require review; the scanner does not contact providers to
check validity. The filesystem snapshot excludes Git history and deleted image
layers. Source .gitleaksignore entries remain supported by Gitleaks.

## Terminal reports

Replay a downloaded report without AWS or Docker:

```powershell
go run . --sarif .\report.sarif --verbose
```

The reader handles all runs, driver/extension rule metadata, severity inheritance,
accepted suppressions, and security/quality/unclassified counts. Verbose mode
shows data-flow paths. The merger tags Gitleaks rules as security without
inventing CVSS scores. Informational extraction baselines are not errors.

| Exit code | Meaning |
| --- | --- |
| 0 | Report processed; security policy passed or was disabled. |
| 1 | Active security or unclassified warnings/errors with --fail-on-vuln=true. |
| 2 | Invalid/incomplete SARIF; never bypassed by --fail-on-vuln=false. |

Quality findings and security notes do not fail the security policy. Other CLI
infrastructure errors exit 1. Build with `go build .` for exact CI exit codes;
`go run` wraps nonzero program exits. Empty report objects are rejected. A valid
report with no findings does not prove the application is secure.

## Verification

```powershell
go test ./...
go vet ./...
python -m pip install -r requirements-test.txt
python -m unittest discover -s scripts -p 'test_*.py'
```

PyYAML is a local test dependency; the production scanner uses Python's standard
library. Set SCANNER_TEST_BASH to a Bash executable to run the inline bootstrap
test, which recreates every production scanner file in an empty directory and
checks each phase's shell syntax without downloading tools or calling AWS.

Bash contract tests use fake engines to test orchestration and failure handling:

```sh
bash scripts/test-scan-javascript.sh
bash scripts/test-scan-source.sh
```

With Git Bash on Windows, set PYTHON_BINARY=python for the second test if needed.

Run real detection regressions against installed binaries:

```sh
python scripts/test-detection.py --gitleaks /path/to/gitleaks --codeql /path/to/codeql
```

Fixtures include reflected/DOM XSS and fixed controls. The test generates a
provider-shaped token that was never issued and verifies detection and redaction.
Omit --codeql to test Gitleaks alone. Fixtures/reports stay under .cache. These
tests do not exercise AWS or prove coverage of the user's application.

Local validation with CodeQL 2.27.3 and Gitleaks 8.30.1 extracted all four fixture
source files and detected reflected XSS, DOM XSS, and the synthetic token, with
clean fixed controls. The combined report displayed three security findings in
the Go CLI and returned exit 1. Linux CodeBuild deployment has not been run here.

For framework regressions, add vulnerable/fixed pairs for decorated GraphQL input
flowing through helpers to TypeORM raw SQL. Verify extraction, query execution,
and recognized sources/sinks before extending models. GraphQL JSON containing a
string alone does not establish where a browser renders unsafe HTML.

Upstream references:

- [CodeQL bundle](https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.27.3)
- [Preparing code for analysis](https://docs.github.com/en/code-security/tutorials/customize-code-scanning/prepare-code-for-analysis)
- [JavaScript query suites](https://codeql.github.com/codeql-query-help/javascript/)
- [Reflected XSS query](https://codeql.github.com/codeql-query-help/javascript/js-reflected-xss/)
- [JavaScript models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-javascript/)
- [Gitleaks release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)

