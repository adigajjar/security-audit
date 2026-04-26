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
		os.Exit(1)
	}

	provider := os.Args[1]
	servicesToScan := []string{"all"}
	if len(os.Args) > 2 {
		servicesToScan = os.Args[2:]
	}

	// Currently only AWS is fully wired up with connector and scanner logic
	if provider != "aws" {
		fmt.Printf("Error: Provider '%s' is not supported yet. Only 'aws' is supported.\n", provider)
		os.Exit(1)
	}

	awsConfig := connectors.AWSConfig{
		RoleARN:    "arn:aws:iam::633825695905:role/VAPTAuditRole",
		ExternalID: "VAPTAgent",
	}

	cfg, err := connectors.ConnectAws(ctx, awsConfig)
	if err != nil {
		panic(err)
	}

	scannedResults, err := scanner.RunAudit(ctx, cfg, servicesToScan...)
	if err != nil {
		panic(err)
	}

	rulesDir := fmt.Sprintf("./rules/%s", provider)
	ru, err := rules.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		fmt.Printf("Error loading rules: %v\n", err)
	} else {
		filteredRules := make(map[string]rules.Rules)
		isAll := false
		for _, s := range servicesToScan {
			if s == "all" {
				isAll = true
				break
			}
		}

		if isAll {
			filteredRules = ru
		} else {
			for _, s := range servicesToScan {
				if r, ok := ru[s]; ok {
					filteredRules[s] = r
				} else {
					fmt.Printf("No rules found or loaded for service: %s\n", s)
				}
			}
		}

		findings, _ := rules.Evaluate(filteredRules, scannedResults, cfg)
		b, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println("Rule findings (JSON):", string(b))

		// Generate the markdown report
		reportPath := "vapt_report.md"
		err = report.GenerateVAPTReport(findings, reportPath)
		if err != nil {
			fmt.Printf("Failed to generate VAPT report: %v\n", err)
		} else {
			fmt.Printf("Generated comprehensive VAPT report at %s\n", reportPath)
		}
	}
}
