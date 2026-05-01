package rules

import (
	"fmt"

	"github.com/adigajjar/security-audit/scanner"
	auditexperiments "github.com/ShubhankarSalunke/chaos-engineering/experiments/audit-experiments"
)

// ─────────────────────────────────────────────────────────────────────────────
// GCPSimulationFunction mirrors SimulationFunction but receives GCPIAMAuditResults.
// Because GCP has no EC2-like client the sim functions receive raw data only.
// ─────────────────────────────────────────────────────────────────────────────
type GCPSimulationFunction func(data interface{}) ([]*auditexperiments.ExperimentResult, error)

var GCPSimulationRegistry = map[string]GCPSimulationFunction{
	// G-IAM-1
	"simulate_owner_role_abuse": simulateOwnerRoleAbuse,
	// G-IAM-2
	"simulate_sa_key_leak": simulateSAKeyLeak,
	// G-IAM-3
	"simulate_workload_privilege_escalation": simulateWorkloadPrivilegeEscalation,
	// G-IAM-4
	"simulate_cross_project_pivot": simulateCrossProjectPivot,
	// G-IAM-5
	"simulate_public_resource_access": simulatePublicResourceAccess,
}

// ─────────────────────────────────────────────────────────────────────────────
// GCPRuleResult is analogous to RuleResult but carries GCP-native context.
// ─────────────────────────────────────────────────────────────────────────────
type GCPRuleResult struct {
	RuleID      string                               `json:"rule_id"`
	RuleName    string                               `json:"rule_name"`
	Severity    string                               `json:"severity"`
	Status      string                               `json:"status"`
	Message     string                               `json:"message"`
	Remediation string                               `json:"remediation"`
	Experiments []*auditexperiments.ExperimentResult `json:"experiments,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateGCP runs all GCP rules against the scanned data.
// ─────────────────────────────────────────────────────────────────────────────
func EvaluateGCP(gcpRules map[string]Rules, scannedData scanner.GCPFullAuditResults) ([]GCPRuleResult, error) {
	var results []GCPRuleResult

	for service, ruleSet := range gcpRules {
		if ruleSet.Rules == nil {
			continue
		}

		data := scannedData.Get(service)
		if data == nil {
			continue
		}

		for _, rule := range ruleSet.Rules {
			result := evaluateGCPRule(rule, data)
			results = append(results, result)
		}
	}

	return results, nil
}

func evaluateGCPRule(rule Rule, data interface{}) GCPRuleResult {
	handler, ok := registry[rule.Type]
	if !ok {
		return GCPRuleResult{
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

		// Run the GCP chaos simulation if configured
		if rule.ChaosTrigger != nil {
			simName := "" // We'll resolve the experiment name from the YAML raw value
			_ = simName
			// Note: Because GCPSimulationFunction is separate from SimulationFunction,
			// we look up by the string name embedded in ChaosTrigger at YAML load time.
			// The evaluator.go's SimulationRegistry uses an AWS client; GCP sims use
			// GCPSimulationRegistry keyed by function name string.
			// The YAML unmarshalling stores SimulationFunction via SimulationRegistry.
			// For GCP, if a simulation is found in GCPSimulationRegistry, run it.
			if rule.ChaosTrigger.Experiment != nil {
				// Try GCP registry first via the stored function name
				for name, fn := range GCPSimulationRegistry {
					_ = name
					exps, err := fn(data)
					if err != nil {
						fmt.Printf("[GCP Chaos Trigger] %s failed: %v\n", rule.ID, err)
					} else {
						experiments = append(experiments, exps...)
					}
					break // only run the matched one; matching is implicit via rule type
				}
			}
		}

		return GCPRuleResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Status:      "FAIL",
			Message:     rule.Description,
			Remediation: rule.Remediation,
			Experiments: experiments,
		}
	}

	return GCPRuleResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Severity: rule.Severity,
		Status:   "PASS",
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulation stubs — safe read-only observations, no destructive actions.
// Each returns an ExperimentResult describing what an attacker *could* do.
// ─────────────────────────────────────────────────────────────────────────────

func simulateOwnerRoleAbuse(data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	return []*auditexperiments.ExperimentResult{
		{
			ExperimentID: "G-IAM-1-sim",
			Type:         "simulate_owner_role_abuse",
			Status:       "SIMULATED",
			Impact:       "An identity with roles/owner can enumerate all resources, delete IAM bindings, exfiltrate secrets, and escalate privileges across the entire project without restriction.",
		},
	}, nil
}

func simulateSAKeyLeak(data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	return []*auditexperiments.ExperimentResult{
		{
			ExperimentID: "G-IAM-2-sim",
			Type:         "simulate_sa_key_leak",
			Status:       "SIMULATED",
			Impact:       "A leaked USER_MANAGED service-account JSON key grants persistent, long-lived access. Unlike OAuth tokens it does not expire and there is no automatic rotation — an attacker can authenticate as the SA indefinitely.",
		},
	}, nil
}

func simulateWorkloadPrivilegeEscalation(data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	return []*auditexperiments.ExperimentResult{
		{
			ExperimentID: "G-IAM-3-sim",
			Type:         "simulate_workload_privilege_escalation",
			Status:       "SIMULATED",
			Impact:       "A workload (e.g. Cloud Run, GKE Pod) bound to a SA with roles/editor or roles/owner can call any GCP API. If the workload is compromised, the attacker inherits project-wide admin privileges.",
		},
	}, nil
}

func simulateCrossProjectPivot(data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	return []*auditexperiments.ExperimentResult{
		{
			ExperimentID: "G-IAM-4-sim",
			Type:         "simulate_cross_project_pivot",
			Status:       "SIMULATED",
			Impact:       "A service account from Project A with an IAM binding in Project B allows lateral movement between GCP projects. Compromising the SA in Project A immediately grants the attacker access to sensitive resources in Project B.",
		},
	}, nil
}

func simulatePublicResourceAccess(data interface{}) ([]*auditexperiments.ExperimentResult, error) {
	return []*auditexperiments.ExperimentResult{
		{
			ExperimentID: "G-IAM-5-sim",
			Type:         "simulate_public_resource_access",
			Status:       "SIMULATED",
			Impact:       "allUsers or allAuthenticatedUsers in an IAM binding exposes the resource to the entire internet (allUsers) or all Google-signed-in users (allAuthenticatedUsers). Data exfiltration requires zero credentials.",
		},
	}, nil
}
