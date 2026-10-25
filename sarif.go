package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// This models the SARIF fields used by the CLI. Unknown fields remain in the
// original report and do not prevent reports from newer CodeQL versions loading.
type sarifReport struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver     sarifComponent   `json:"driver"`
		Extensions []sarifComponent `json:"extensions"`
	} `json:"tool"`
	Results     []sarifResult `json:"results"`
	Invocations []struct {
		ExecutionSuccessful *bool               `json:"executionSuccessful"`
		Notifications       []sarifNotification `json:"toolExecutionNotifications"`
		Configuration       []sarifNotification `json:"toolConfigurationNotifications"`
	} `json:"invocations"`
}

type sarifComponent struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string `json:"id"`
	HelpURI              string `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		Tags             []string `json:"tags"`
		Kind             string   `json:"kind"`
		SecuritySeverity string   `json:"security-severity"`
	} `json:"properties"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

func (m sarifMessage) String() string {
	if m.Text != "" {
		return m.Text
	}
	return m.Markdown
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
	Message sarifMessage `json:"message"`
}

func (l sarifLocation) String() string {
	uri := l.PhysicalLocation.ArtifactLocation.URI
	if uri == "" {
		return "Unknown location"
	}
	if line := l.PhysicalLocation.Region.StartLine; line > 0 {
		return fmt.Sprintf("%s:%d", uri, line)
	}
	return uri
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Rule      *struct {
		ID            string `json:"id"`
		Index         *int   `json:"index"`
		ToolComponent *struct {
			Name  string `json:"name"`
			Index *int   `json:"index"`
		} `json:"toolComponent"`
	} `json:"rule"`
	Level        string          `json:"level"`
	Kind         string          `json:"kind"`
	Message      sarifMessage    `json:"message"`
	Locations    []sarifLocation `json:"locations"`
	Suppressions []struct {
		Status string `json:"status"`
	} `json:"suppressions"`
	CodeFlows []struct {
		ThreadFlows []struct {
			Locations []struct {
				Location sarifLocation `json:"location"`
			} `json:"locations"`
		} `json:"threadFlows"`
	} `json:"codeFlows"`
}

type sarifNotification struct {
	Level      string       `json:"level"`
	Message    sarifMessage `json:"message"`
	Descriptor struct {
		ID string `json:"id"`
	} `json:"descriptor"`
}

// Resolve rules from either the driver or a query-pack extension. Never use an
// invalid index as rule zero, or borrow metadata from a different component.
func (run sarifRun) ruleFor(result sarifResult) (sarifRule, error) {
	component := run.Tool.Driver
	id, index := result.RuleID, result.RuleIndex
	if ref := result.Rule; ref != nil {
		if ref.ID != "" {
			id = ref.ID
		}
		if ref.Index != nil {
			index = ref.Index
		}
		if tc := ref.ToolComponent; tc != nil {
			if tc.Index != nil {
				if *tc.Index < 0 || *tc.Index >= len(run.Tool.Extensions) {
					return sarifRule{}, fmt.Errorf("invalid tool component index %d", *tc.Index)
				}
				component = run.Tool.Extensions[*tc.Index]
			} else if tc.Name != "" && tc.Name != component.Name {
				found := false
				for _, extension := range run.Tool.Extensions {
					if extension.Name == tc.Name {
						component, found = extension, true
						break
					}
				}
				if !found {
					return sarifRule{}, fmt.Errorf("unknown tool component %q", tc.Name)
				}
			}
		}
	}
	if index != nil {
		if *index < 0 || *index >= len(component.Rules) {
			return sarifRule{}, fmt.Errorf("invalid rule index %d", *index)
		}
		rule := component.Rules[*index]
		if id != "" && rule.ID != id {
			return sarifRule{}, fmt.Errorf("rule ID %q does not match index %d (%q)", id, *index, rule.ID)
		}
		return rule, nil
	}
	for _, rule := range component.Rules {
		if rule.ID == id {
			return rule, nil
		}
	}
	if id == "" {
		return sarifRule{}, fmt.Errorf("result has no rule identifier")
	}
	// SARIF producers can omit rule metadata. Keep such findings unclassified,
	// rather than claiming they are security findings or silently dropping them.
	return sarifRule{ID: id}, nil
}

func findingCategory(rule sarifRule) string {
	if rule.Properties.SecuritySeverity != "" {
		return "security"
	}
	for _, tag := range rule.Properties.Tags {
		if tag == "security" || strings.HasPrefix(tag, "external/cwe/") {
			return "security"
		}
	}
	for _, tag := range rule.Properties.Tags {
		switch tag {
		case "maintainability", "reliability", "correctness", "readability":
			return "quality"
		}
	}
	return "unclassified"
}

func securitySeverity(score string) string {
	value, err := strconv.ParseFloat(score, 64)
	if err != nil || math.IsNaN(value) || value < 0 || value > 10 {
		return "unknown"
	}
	switch {
	case value >= 9:
		return "critical"
	case value >= 7:
		return "high"
	case value >= 4:
		return "medium"
	default:
		return "low"
	}
}

// Exit codes: 0 = completed, 1 = findings rejected by policy, 2 = invalid or
// incomplete scan. --fail-on-vuln=false never masks a scanner failure.
func printReport(out io.Writer, body []byte, failOnVuln, verbose bool) int {
	var report sarifReport
	if err := json.Unmarshal(body, &report); err != nil {
		fmt.Fprintf(out, "Invalid SARIF JSON: %v\n", err)
		return 2
	}
	if report.Version != "2.1.0" || len(report.Runs) == 0 {
		fmt.Fprintln(out, "Invalid report: expected SARIF 2.1.0 with at least one run.")
		return 2
	}
	fmt.Fprintf(out, "\n%s%s====================== SCAN RESULTS ======================%s\n", colorBold, colorCyan, colorReset)
	security, quality, unclassified, suppressed, diagnostics, blocking := 0, 0, 0, 0, 0, 0
	incomplete := false
	for runIndex, run := range report.Runs {
		if run.Tool.Driver.Name == "" || run.Results == nil {
			fmt.Fprintf(out, "Run %d: missing tool driver name or results array; scan completeness is unknown.\n", runIndex+1)
			incomplete = true
		}
		for _, invocation := range run.Invocations {
			if invocation.ExecutionSuccessful != nil && !*invocation.ExecutionSuccessful {
				fmt.Fprintf(out, "Run %d: scanner execution failed.\n", runIndex+1)
				incomplete = true
			}
			for _, notification := range append(invocation.Notifications, invocation.Configuration...) {
				diagnostics++
				fmt.Fprintf(out, "[DIAGNOSTIC %s] %s %s\n", notification.Level, notification.Descriptor.ID, notification.Message)
				if notification.Level == "error" {
					incomplete = true
				}
			}
		}
		for _, result := range run.Results {
			rule, err := run.ruleFor(result)
			if err != nil {
				fmt.Fprintf(out, "Run %d: invalid result metadata: %v\n", runIndex+1, err)
				incomplete = true
				continue
			}
			level := result.Level
			if level == "" {
				level = rule.DefaultConfiguration.Level
			}
			if level == "" {
				level = "warning"
			}
			if level != "none" && level != "note" && level != "warning" && level != "error" {
				fmt.Fprintf(out, "Run %d: invalid result level %q.\n", runIndex+1, level)
				incomplete = true
				continue
			}
			if rule.Properties.Kind == "diagnostic" || strings.Contains(rule.ID, "/diagnostics/") || strings.Contains(rule.ID, "expected-extracted") {
				diagnostics++
				fmt.Fprintf(out, "[DIAGNOSTIC %s] %s: %s\n", level, rule.ID, result.Message)
				if level == "error" {
					incomplete = true
				}
				continue
			}
			if rule.Properties.Kind == "metric" || level == "none" || (result.Kind != "" && result.Kind != "fail") {
				continue
			}
			isSuppressed := false
			for _, suppression := range result.Suppressions {
				if suppression.Status == "" || suppression.Status == "accepted" {
					isSuppressed = true
				}
			}
			if isSuppressed {
				suppressed++
				continue
			}
			category := findingCategory(rule)
			switch category {
			case "security":
				security++
			case "quality":
				quality++
			default:
				unclassified++
			}
			if category != "quality" && (level == "warning" || level == "error") {
				blocking++
			}
			color := colorYellow
			if level == "error" {
				color = colorRed
			} else if level == "note" {
				color = colorCyan
			}
			fmt.Fprintf(out, "%s[%s]%s %s (%s", color, strings.ToUpper(level), colorReset, rule.ID, category)
			if rule.Properties.SecuritySeverity != "" {
				fmt.Fprintf(out, ", %s, score %s", securitySeverity(rule.Properties.SecuritySeverity), rule.Properties.SecuritySeverity)
			}
			fmt.Fprintln(out, ")")
			for _, location := range result.Locations {
				fmt.Fprintf(out, "   --> %s\n", location)
			}
			fmt.Fprintf(out, "   %s\n", result.Message)
			if rule.HelpURI != "" {
				fmt.Fprintf(out, "   Help: %s\n", rule.HelpURI)
			}
			if verbose {
				for _, flow := range result.CodeFlows {
					for _, thread := range flow.ThreadFlows {
						fmt.Fprintln(out, "   Data flow:")
						for _, step := range thread.Locations {
							fmt.Fprintf(out, "     %s %s\n", step.Location, step.Location.Message)
						}
					}
				}
			}
			fmt.Fprintln(out)
		}
	}
	fmt.Fprintf(out, "Runs: %d | Security: %d | Quality: %d | Unclassified: %d | Suppressed: %d | Diagnostics: %d\n", len(report.Runs), security, quality, unclassified, suppressed, diagnostics)
	if incomplete {
		fmt.Fprintln(out, "INCOMPLETE: Scanner or extraction errors prevent a reliable scan result.")
		return 2
	}
	if failOnVuln && blocking > 0 {
		fmt.Fprintf(out, "FAILED: %d security or unclassified warnings/errors require review.\n", blocking)
		return 1
	}
	fmt.Fprintln(out, "COMPLETED: Review the reported findings and diagnostics; absence of findings does not prove the application is secure.")
	return 0
}
