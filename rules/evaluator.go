package rules

import (
	"fmt"
	"strings"

	chaosec2 "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments/aws/ec2"
	"github.com/adigajjar/security-audit/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
)

type RuleResult struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}



func Evaluate(rules map[string]Rules, scannedData scanner.FullAuditResults, cfg aws.Config) ([]RuleResult, error) {
	var results []RuleResult

	client := awsec2.NewFromConfig(cfg)
	
	for service, ruleSet := range rules {
		if ruleSet.Rules == nil{
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

func evaluateRule(rule Rule, data interface{}, client *awsec2.Client) RuleResult{
	handler, ok := registry[rule.Type]
	if !ok{
		return RuleResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Status:      "ERROR",
			Message:     fmt.Sprintf("unknown rule type: %s", rule.Type),
		}
	}

	values := handler(data)

	if Compare(values, rule.Check.Operator, rule.Check.Value){
		// if rule.ChaosTrigger != nil && rule.ChaosTrigger.Experiment == "simulate_brute_force_exposure" {
		// 	triggerBruteForceChaos(client, data)
		// }

		return RuleResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Status:      "FAIL",
			Message:     rule.Description,
			Remediation: rule.Remediation,
		}
	}

	return RuleResult{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Status:      "PASS",
	}
}

func Compare(values []interface{}, operator string, expected interface{}) bool {
	if len(values) == 0{
		return false
	}

	for _, actual := range values {
		if compareSingle(actual, operator, expected){
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

func triggerBruteForceChaos(client *awsec2.Client, data interface{}) {
	ec2Data, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return
	}

	for _, sg := range ec2Data.SecurityGroups {
		isOpen := false
		for _, perm := range sg.IpPermissions {
			for _, r := range perm.IpRanges {
				if r.CidrIp != nil && *r.CidrIp == "0.0.0.0/0" {
					isOpen = true
					break
				}
			}
			if isOpen {
				break
			}
		}

		if isOpen {
			for _, inst := range ec2Data.Instances {
				hasSg := false
				for _, isg := range inst.SecurityGroups {
					if *isg.GroupId == *sg.GroupId {
						hasSg = true
						break
					}
				}

				if hasSg && inst.InstanceId != nil {
					fmt.Printf("[Chaos Trigger] Starting brute force exposure on instance %s (SG: %s)\n", *inst.InstanceId, *sg.GroupId)
					exp := chaosec2.BruteForceExposure{
						Client:          client,
						SecurityGroupID: *sg.GroupId,
						InstanceID:      *inst.InstanceId,
					}
					res, err := exp.Run()
					if err != nil {
						fmt.Printf("[Chaos Trigger] Experiment failed: %v\n", err)
					} else {
						fmt.Printf("[Chaos Trigger] Experiment completed: Impact=%s, Status=%s\n", res.Impact, res.Status)
					}
				}
			}
		}
	}
}