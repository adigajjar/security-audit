package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adigajjar/security-audit/rules"
)

// GenerateVAPTReport generates a comprehensive markdown report for the audit findings and chaos experiments.
func GenerateVAPTReport(findings []rules.RuleResult, outputPath string) error {
	var builder strings.Builder

	builder.WriteString("# Vulnerability Assessment & Penetration Testing (VAPT) Report\n")
	builder.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format(time.RFC1123)))

	builder.WriteString("## Executive Summary\n")
	builder.WriteString("This report summarizes the results of an automated security audit and subsequent chaos engineering experiments. It details identified vulnerabilities, misconfigurations, and validated exploits alongside detailed experiment tracking.\n\n")

	// Group findings by status
	passed := 0
	failed := 0
	errorCount := 0
	for _, f := range findings {
		if f.Status == "PASS" {
			passed++
		} else if f.Status == "FAIL" {
			failed++
		} else if f.Status == "ERROR" {
			errorCount++
		}
	}

	builder.WriteString("### Summary Statistics\n")
	builder.WriteString(fmt.Sprintf("- **Total Rules Evaluated:** %d\n", len(findings)))
	builder.WriteString(fmt.Sprintf("- **Passed:** %d\n", passed))
	builder.WriteString(fmt.Sprintf("- **Failed:** %d\n", failed))
	builder.WriteString(fmt.Sprintf("- **Error:** %d\n\n", errorCount))

	builder.WriteString("## Detailed Findings with Verified Exploit Testing\n\n")

	for i, f := range findings {
		if f.Status == "PASS" {
			// We only detail failed findings or errors
			continue 
		}
		
		builder.WriteString(fmt.Sprintf("### %d. %s (Rule ID: %s)\n", i+1, f.RuleName, f.RuleID))
		builder.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
		builder.WriteString(fmt.Sprintf("- **Status:** %s\n", f.Status))
		builder.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Message))
		if f.Remediation != "" {
			builder.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
		}
		builder.WriteString("\n")

		if len(f.Experiments) > 0 {
			builder.WriteString("#### Chaos Engineering Experiments Conducted\n")
			for j, exp := range f.Experiments {
				builder.WriteString(fmt.Sprintf("##### Experiment %d: `%s`\n", j+1, exp.Type))
				builder.WriteString(fmt.Sprintf("- **Experiment ID:** `%s`\n", exp.ExperimentID))
				builder.WriteString(fmt.Sprintf("- **Target ID:** `%s`\n", exp.TargetID))
				builder.WriteString(fmt.Sprintf("- **Status:** `%s`\n", exp.Status))
				builder.WriteString(fmt.Sprintf("- **Impact:** `%s`\n\n", exp.Impact))

				if len(exp.Observations) > 0 {
					builder.WriteString("**Observations Log:**\n\n")
					builder.WriteString("| Timestamp | Event | Detail |\n")
					builder.WriteString("| :--- | :--- | :--- |\n")
					for _, obs := range exp.Observations {
						builder.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", obs.Timestamp.Format(time.Kitchen), obs.Event, obs.Detail))
					}
					builder.WriteString("\n")
				}
			}
		}
		builder.WriteString("---\n\n")
	}

	return os.WriteFile(outputPath, []byte(builder.String()), 0644)
}