package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ShubhankarSalunke/lucifer/connectors"
	"github.com/adigajjar/security-audit/report"
	"github.com/adigajjar/security-audit/rules"
	"github.com/adigajjar/security-audit/scanner"
)

func main() {
	ctx := context.Background()

	if len(os.Args) < 2 {
		fmt.Println("Usage: security-audit <provider> [services...]")
		fmt.Println("  Providers: aws, gcp")
		fmt.Println("  Examples:")
		fmt.Println("    security-audit aws")
		fmt.Println("    security-audit aws iam s3")
		fmt.Println("    security-audit gcp")
		fmt.Println("    security-audit gcp iam")
		os.Exit(1)
	}

	provider := os.Args[1]
	servicesToScan := []string{"all"}
	if len(os.Args) > 2 {
		servicesToScan = os.Args[2:]
	}

	switch provider {
	case "aws":
		runAWS(ctx, servicesToScan)
	case "gcp":
		runGCP(ctx, servicesToScan)
	default:
		fmt.Printf("Error: Provider '%s' is not supported. Use 'aws' or 'gcp'.\n", provider)
		os.Exit(1)
	}
}

// ─────────────────────────────────────────────
// AWS path (unchanged)
// ─────────────────────────────────────────────
func runAWS(ctx context.Context, servicesToScan []string) {
	awsConfig := connectors.AWSConfig{
		RoleARN:    "arn:aws:iam::633825695905:role/VAPTAuditRole",
		ExternalID: "VAPTAgent",
	}

	cfg, err := connectors.ConnectAws(ctx, awsConfig)
	if err != nil {
		fmt.Printf("Failed to connect to AWS: %v\n", err)
		os.Exit(1)
	}

	scannedResults, err := scanner.RunAudit(ctx, cfg, servicesToScan...)
	if err != nil {
		fmt.Printf("AWS scan failed: %v\n", err)
		os.Exit(1)
	}

	ru, err := rules.LoadRulesFromDirectory("./rules/aws")
	if err != nil {
		fmt.Printf("Error loading AWS rules: %v\n", err)
		os.Exit(1)
	}

	filteredRules := filterRules(ru, servicesToScan)
	findings, _ := rules.Evaluate(filteredRules, scannedResults, cfg)

	b, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println("AWS Rule findings (JSON):", string(b))

	reportPath := "vapt_report_aws.md"
	if err := report.GenerateVAPTReport(findings, reportPath); err != nil {
		fmt.Printf("Failed to generate AWS VAPT report: %v\n", err)
	} else {
		fmt.Printf("Generated AWS VAPT report at %s\n", reportPath)
	}
}

// ─────────────────────────────────────────────
// GCP path
// ─────────────────────────────────────────────
func runGCP(ctx context.Context, servicesToScan []string) {
	// Credentials resolved from GOOGLE_APPLICATION_CREDENTIALS env var (ADC)
	// Project resolved from GCP_PROJECT_ID env var
	gcpClient, err := connectors.ConnectGCP(ctx, connectors.GCPConfig{})
	if err != nil {
		fmt.Printf("Failed to connect to GCP: %v\n", err)
		fmt.Println("Ensure GOOGLE_APPLICATION_CREDENTIALS and GCP_PROJECT_ID are set.")
		os.Exit(1)
	}

	fmt.Printf("Connected to GCP project: %s\n", gcpClient.ProjectID)

	gcpResults, err := scanner.RunGCPAudit(ctx, gcpClient, servicesToScan...)
	if err != nil {
		fmt.Printf("GCP scan failed: %v\n", err)
		os.Exit(1)
	}

	ru, err := rules.LoadRulesFromDirectory("./rules/gcp")
	if err != nil {
		fmt.Printf("Error loading GCP rules: %v\n", err)
		os.Exit(1)
	}

	filteredRules := filterRules(ru, servicesToScan)
	findings, _ := rules.EvaluateGCP(filteredRules, gcpResults)

	b, _ := json.MarshalIndent(findings, "", "  ")
	fmt.Println("GCP Rule findings (JSON):", string(b))

	// Convert GCPRuleResult → RuleResult for the shared report generator
	var sharedFindings []rules.RuleResult
	for _, f := range findings {
		sharedFindings = append(sharedFindings, rules.RuleResult{
			RuleID:      f.RuleID,
			RuleName:    f.RuleName,
			Severity:    f.Severity,
			Status:      f.Status,
			Message:     f.Message,
			Remediation: f.Remediation,
			Experiments: f.Experiments,
		})
	}

	reportPath := "vapt_report_gcp.md"
	if err := report.GenerateVAPTReport(sharedFindings, reportPath); err != nil {
		fmt.Printf("Failed to generate GCP VAPT report: %v\n", err)
	} else {
		fmt.Printf("Generated GCP VAPT report at %s\n", reportPath)
	}
}

// ─────────────────────────────────────────────
// Shared helper
// ─────────────────────────────────────────────
func filterRules(ru map[string]rules.Rules, servicesToScan []string) map[string]rules.Rules {
	for _, s := range servicesToScan {
		if s == "all" {
			return ru
		}
	}
	filtered := make(map[string]rules.Rules)
	for _, s := range servicesToScan {
		if r, ok := ru[s]; ok {
			filtered[s] = r
		} else {
			fmt.Printf("No rules found for service: %s\n", s)
		}
	}
	return filtered
}

