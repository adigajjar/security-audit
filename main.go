package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/adigajjar/security-audit/connector"
	"github.com/adigajjar/security-audit/rules"
	"github.com/adigajjar/security-audit/scanner"
)

func main() {
	ctx := context.Background()

	roleArn := "arn:aws:iam::633825695905:role/VAPTAuditRole"
	externalId := "VAPTAgent"

	cfg, err := connector.ConnectAws(ctx, roleArn, externalId)
	if err != nil {
		panic(err)
	}
	
	scannedResults, err := scanner.RunAudit(ctx, cfg)
	if err != nil {
		panic(err)
	}

	ru, err := rules.LoadRulesFromDirectory("./rules/aws")
	if err != nil {
		fmt.Printf("Error loading rules: %v\n", err)
	} else {
		findings, _ := rules.Evaluate(ru, scannedResults, cfg)
		b, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println("Rule findings:", string(b))
	}

	// b, _ := json.MarshalIndent(scannedResults, "", "  ")
	// fmt.Println("Scanner results:", string(b))
}