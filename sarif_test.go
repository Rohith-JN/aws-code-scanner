package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func sarifWith(rules, results, extra string) string {
	return fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":%s}},"results":%s%s}]}`, rules, results, extra)
}

func TestPrintReport(t *testing.T) {
	securityRule := `[{"id":"js/sql-injection","defaultConfiguration":{"level":"error"},"properties":{"tags":["security"],"security-severity":"8.8"}}]`
	tests := []struct {
		name       string
		body       string
		reportOnly bool
		wantCode   int
		wantText   []string
	}{
		{"invalid JSON", `{`, false, 2, []string{"Invalid SARIF JSON"}},
		{"empty object", `{}`, false, 2, []string{"Invalid report"}},
		{"no runs", `{"version":"2.1.0","runs":[]}`, false, 2, nil},
		{"wrong version", `{"version":"1.0.0","runs":[{}]}`, false, 2, nil},
		{"missing run data", `{"version":"2.1.0","runs":[{}]}`, false, 2, []string{"INCOMPLETE"}},
		{"missing results", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}}}]}`, false, 2, nil},
		{"valid empty report", sarifWith(`[]`, `[]`, ""), false, 0, []string{"Security: 0", "COMPLETED"}},
		{"inherited rule severity by index", sarifWith(securityRule, `[{"ruleIndex":0,"message":{"text":"Unsafe SQL"}}]`, ""), false, 1, []string{"[ERROR]", "js/sql-injection", "high, score 8.8", "Security: 1"}},
		{"inherited rule severity by ID", sarifWith(securityRule, `[{"ruleId":"js/sql-injection"}]`, ""), false, 1, []string{"[ERROR]"}},
		{"explicit level overrides rule", sarifWith(securityRule, `[{"ruleId":"js/sql-injection","level":"note"}]`, ""), false, 0, []string{"[NOTE]", "Security: 1"}},
		{"report only", sarifWith(securityRule, `[{"ruleIndex":0}]`, ""), true, 0, []string{"Security: 1"}},
		{"quality does not block security policy", sarifWith(`[{"id":"js/unused-variable","properties":{"tags":["maintainability"]}}]`, `[{"ruleId":"js/unused-variable"}]`, ""), false, 0, []string{"Quality: 1", "Security: 0"}},
		{"missing metadata is conservative", sarifWith(`[]`, `[{"ruleId":"custom/rule"}]`, ""), false, 1, []string{"Unclassified: 1"}},
		{"arbitrary tags remain unclassified", sarifWith(`[{"id":"custom/rule","properties":{"tags":["custom"]}}]`, `[{"ruleIndex":0}]`, ""), false, 1, []string{"Unclassified: 1"}},
		{"accepted suppressions", sarifWith(securityRule, `[{"ruleIndex":0,"suppressions":[{"status":"accepted"}]}]`, ""), false, 0, []string{"Suppressed: 1", "Security: 0"}},
		{"suppression without status", sarifWith(securityRule, `[{"ruleIndex":0,"suppressions":[{"kind":"inSource"}]}]`, ""), false, 0, []string{"Suppressed: 1"}},
		{"rejected suppressions", sarifWith(securityRule, `[{"ruleIndex":0,"suppressions":[{"status":"rejected"}]}]`, ""), false, 1, []string{"Security: 1"}},
		{"pending suppressions", sarifWith(securityRule, `[{"ruleIndex":0,"suppressions":[{"status":"underReview"}]}]`, ""), false, 1, nil},
		{"failed invocation", sarifWith(`[]`, `[]`, `,"invocations":[{"executionSuccessful":false}]`), true, 2, []string{"scanner execution failed", "INCOMPLETE"}},
		{"error diagnostic", sarifWith(`[]`, `[]`, `,"invocations":[{"toolExecutionNotifications":[{"level":"error","message":{"text":"Extraction failed"}}]}]`), true, 2, []string{"Extraction failed", "Diagnostics: 1"}},
		{"configuration error", sarifWith(`[]`, `[]`, `,"invocations":[{"toolConfigurationNotifications":[{"level":"error","message":{"text":"Invalid query"}}]}]`), true, 2, []string{"Invalid query"}},
		{"extraction baseline is informational", sarifWith(`[]`, `[{"ruleId":"cli/expected-extracted-files/javascript","level":"none","message":{"text":"Expected files"}}]`, ""), false, 0, []string{"Expected files", "Diagnostics: 1", "Security: 0"}},
		{"result diagnostic error", sarifWith(`[{"id":"js/diagnostics/extraction-errors","defaultConfiguration":{"level":"error"}}]`, `[{"ruleIndex":0,"message":{"text":"Failed to extract source"}}]`, ""), true, 2, []string{"Failed to extract source", "Security: 0"}},
		{"no rule identifier", sarifWith(`[]`, `[{}]`, ""), false, 2, []string{"no rule identifier"}},
		{"negative rule index", sarifWith(securityRule, `[{"ruleIndex":-1}]`, ""), false, 2, []string{"invalid rule index"}},
		{"out of bounds rule index", sarifWith(securityRule, `[{"ruleIndex":9}]`, ""), false, 2, []string{"invalid rule index"}},
		{"conflicting rule ID and index", sarifWith(securityRule, `[{"ruleId":"other","ruleIndex":0}]`, ""), false, 2, []string{"does not match"}},
		{"invalid severity", sarifWith(securityRule, `[{"ruleIndex":0,"level":"high"}]`, ""), false, 2, []string{"invalid result level"}},
		{"non-alert kinds", sarifWith(securityRule, `[{"ruleIndex":0,"kind":"pass"},{"ruleIndex":0,"kind":"notApplicable"},{"ruleIndex":0,"level":"none"}]`, ""), false, 0, []string{"Security: 0"}},
		{"markdown fallback and location", sarifWith(securityRule, `[{"ruleIndex":0,"message":{"markdown":"**Unsafe query**"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/resolver.ts"},"region":{"startLine":42}}}]}]`, ""), false, 1, []string{"**Unsafe query**", "src/resolver.ts:42"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if got := printReport(&out, []byte(tt.body), !tt.reportOnly, false); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d; output:\n%s", got, tt.wantCode, out.String())
			}
			for _, want := range tt.wantText {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output missing %q:\n%s", want, out.String())
				}
			}
		})
	}
}

func TestMultipleRunsAndExtensionRules(t *testing.T) {
	body := `{"version":"2.1.0","runs":[
		{"tool":{"driver":{"name":"CodeQL"}},"results":[]},
		{"tool":{"driver":{"name":"CodeQL"},"extensions":[{"name":"codeql/javascript-queries","rules":[{"id":"js/sql-injection","defaultConfiguration":{"level":"error"},"properties":{"tags":["security"]}}]}]},"results":[
			{"rule":{"index":0,"toolComponent":{"index":0}}},
			{"rule":{"id":"js/sql-injection","toolComponent":{"name":"codeql/javascript-queries"}}}
		]}
	]}`
	var out bytes.Buffer
	if code := printReport(&out, []byte(body), true, false); code != 1 {
		t.Fatalf("exit = %d; output:\n%s", code, &out)
	}
	if !strings.Contains(out.String(), "Runs: 2 | Security: 2") {
		t.Fatalf("missing results from second run: %s", &out)
	}
}

func TestVerboseDataFlow(t *testing.T) {
	body := sarifWith(`[]`, `[{"ruleId":"js/sql-injection","codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/input.ts"},"region":{"startLine":7}},"message":{"text":"User input"}}}]}]}]}]`, "")
	for _, verbose := range []bool{false, true} {
		var out bytes.Buffer
		printReport(&out, []byte(body), false, verbose)
		if strings.Contains(out.String(), "src/input.ts:7 User input") != verbose {
			t.Fatalf("unexpected flow output (verbose=%v): %s", verbose, &out)
		}
	}
}

func TestSecuritySeverity(t *testing.T) {
	for score, want := range map[string]string{"9.8": "critical", "9": "critical", "7": "high", "4": "medium", "0": "low", "bad": "unknown", "NaN": "unknown", "11": "unknown", "-1": "unknown"} {
		if got := securitySeverity(score); got != want {
			t.Errorf("securitySeverity(%q) = %q, want %q", score, got, want)
		}
	}
}
