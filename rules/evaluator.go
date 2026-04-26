package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
	chaosec2 "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments/aws/ec2"
	chaoslambda "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments/aws/lambda"
	chaosrds "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments/aws/rds"
	chaoss3 "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments/aws/s3"
)

func init() {
	// SimulationRegistry["simulate_brute_force_exposure"] = chaosec2.SimulateBruteForceExposure
	SimulationRegistry["simulate_ssrf_metadata_theft"] = chaosec2.SimulateSSRFMetadataTheft
	// SimulationRegistry["simulate_snapshot_exfiltration"] = chaosec2.SimulateEBSUnencryptedAccess
	// SimulationRegistry["simulate_public_snapshot_scrape"] = chaosec2.SimulatePublicSnapshotScrape
	// SimulationRegistry["simulate_data_exfiltration"] = chaoss3.SimulateDataExfiltration
	// SimulationRegistry["simulate_unencrypted_write"] = chaoss3.SimulateUnencryptedWrite
	// SimulationRegistry["simulate_ransomware_delete"] = chaoss3.SimulateRansomwareDelete
	SimulationRegistry["simulate_silent_exfiltration"] = chaoss3.SimulateSilentExfiltration

	// RDS Attack Functions
	SimulationRegistry["simulate_db_brute_force"] = chaosrds.SimulateDBBruteForce
	SimulationRegistry["simulate_db_corruption"] = chaosrds.SimulateDBCorruption
	SimulationRegistry["simulate_snapshot_data_leak"] = chaosrds.SimulateSnapshotDataLeak
	SimulationRegistry["simulate_az_failure"] = chaosrds.SimulateAZFailure
	SimulationRegistry["simulate_internal_lateral_db_access"] = chaosrds.SimulateInternalLateralDBAccess

	// Lambda Attack Functions - wrapped to match SimulationFunction signature
	SimulationRegistry["simulate_lambda_role_abuse"] = func(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
		// Extract Lambda client from context - for now, create a new one
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		lambdaClient := awslambda.NewFromConfig(cfg)
		return chaoslambda.SimulateLambdaRoleAbuse(lambdaClient, data)
	}
	SimulationRegistry["simulate_env_var_secret_harvest"] = func(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		lambdaClient := awslambda.NewFromConfig(cfg)
		return chaoslambda.SimulateEnvVarSecretHarvest(lambdaClient, data)
	}
	SimulationRegistry["simulate_unauthenticated_invocation"] = func(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		lambdaClient := awslambda.NewFromConfig(cfg)
		return chaoslambda.SimulateUnauthenticatedInvocation(lambdaClient, data)
	}
	SimulationRegistry["simulate_silent_function_failure"] = func(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		lambdaClient := awslambda.NewFromConfig(cfg)
		return chaoslambda.SimulateSilentFunctionFailure(lambdaClient, data)
	}
	SimulationRegistry["simulate_supply_chain_exploit"] = func(client *awsec2.Client, data interface{}) ([]*auditexperiments.ExperimentResult, error) {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		lambdaClient := awslambda.NewFromConfig(cfg)
		return chaoslambda.SimulateSupplyChainExploit(lambdaClient, data)
	}
}

type RuleResult struct {
	RuleID      string                               `json:"rule_id"`
	RuleName    string                               `json:"rule_name"`
	Severity    string                               `json:"severity"`
	Status      string                               `json:"status"`
	Message     string                               `json:"message"`
	Remediation string                               `json:"remediation"`
	Experiments []*auditexperiments.ExperimentResult `json:"experiments"`
}

func Evaluate(rules map[string]Rules, scannedData scanner.FullAuditResults, cfg aws.Config) ([]RuleResult, error) {
	var results []RuleResult

	client := awsec2.NewFromConfig(cfg)

	for service, ruleSet := range rules {
		if ruleSet.Rules == nil {
			continue
		}

		data := scannedData.Get(service)
		if data == nil {
			continue
		}

		for _, rule := range ruleSet.Rules {
			result := evaluateRule(rule, data, client)
			results = append(results, result)
		}
	}

	return results, nil
}

func evaluateRule(rule Rule, data interface{}, client *awsec2.Client) RuleResult {
	handler, ok := registry[rule.Type]
	if !ok {
		return RuleResult{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: rule.Severity,
			Status:   "ERROR",
			Message:  fmt.Sprintf("unknown rule type: %s", rule.Type),
		}
	}

	values := handler(data)

	if Compare(values, rule.Check.Operator, rule.Check.Value) {

		var experiments []*auditexperiments.ExperimentResult
		if rule.ChaosTrigger != nil && rule.ChaosTrigger.Experiment != nil {
			var err error
			experiments, err = rule.ChaosTrigger.Experiment(client, data)
			if err != nil {
				fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
			}
		}

		return RuleResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Status:      "FAIL",
			Message:     rule.Description,
			Remediation: rule.Remediation,
			Experiments: experiments,
		}
	}

	return RuleResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Severity: rule.Severity,
		Status:   "PASS",
	}
}

func Compare(values []interface{}, operator string, expected interface{}) bool {
	if len(values) == 0 {
		return false
	}

	for _, actual := range values {
		if compareSingle(actual, operator, expected) {
			return true
		}
	}
	return false
}

func compareSingle(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "equals":
		return actual == expected
	case "not_equals":
		return actual != expected
	case "contains":
		return strings.Contains(actual.(string), expected.(string))
	case "exists":
		return actual != nil
	case "greater_than":
		return actual.(int) > expected.(int)
	case "less_than":
		return actual.(int) < expected.(int)
	default:
		return false
	}
}
