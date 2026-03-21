package rules

import (
	"fmt"
	"strings"

	"github.com/adigajjar/security-audit/scanner"
)

type RuleResult struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}



func Evaluate(rules map[string]Rules, scannedData scanner.FullAuditResults) ([]RuleResult, error) {
	var results []RuleResult


	
	for service, ruleSet := range rules {
		if ruleSet.Rules == nil{
			continue
		}

		data := scannedData.Get(service)
		if data == nil {
			continue
		}

		for _, rule := range ruleSet.Rules {
			result := evaluateRule(rule, data)
			results = append(results, result)
		}
	}

	return results, nil
}

func evaluateRule(rule Rule, data interface{}) RuleResult{
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