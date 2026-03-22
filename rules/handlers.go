package rules

import (
	"github.com/adigajjar/security-audit/scanner"
)

type ExtractorFunc func(data interface{}) []interface{}

var registry = map[string]ExtractorFunc{
	//EC2 handlers
	"open_ingress":    extractIngressCidrs,
	"imdsv2_enforced": extractImdsv2Status,
	// "ami_vulnerability_count": extractAmiVulnCount,
	"ebs_encrypted":   extractEbsEncryption,
	"snapshot_public": extractSnapshotPublic,
	// RDS handlers
	"network_exposure":        extractRdsPubliclyAccessible,
	"backup_recovery":         extractRdsBackupRetention,
	"snapshot_data_exposure":  extractRdsSnapshotEncryption,
	"availability_resilience": extractRdsMultiAZ,
	"lateral_movement":        extractRdsLateralAccess,
	"rds_snapshot_public":     extractRdsSnapshotPublic,
	//Lambda handlers
	"privilege_escalation":    extractLambdaPrivilegeEscalation,
	"secret_exposure":         extractLambdaSecretExposure,
	"unauthenticated_access":  extractLambdaUnauthenticatedAccess,
	"reliability_gap":         extractLambdaDLQConfig,
	"supply_chain_risk":       extractLambdaSupplyChainRisk,
}

// ===== EC2 Handlers =====
func extractIngressCidrs(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}

	for _, sg := range ec2.SecurityGroups {
		for _, perm := range sg.IpPermissions {
			for _, r := range perm.IpRanges {
				if r.CidrIp != nil {
					results = append(results, *r.CidrIp)
				}
			}
		}
	}
	return results
}

func extractImdsv2Status(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}

	for _, instance := range ec2.Instances {
		enforced := false
		if instance.MetadataOptions != nil {
			if string(instance.MetadataOptions.HttpTokens) == "required" {
				enforced = true
			}
		}
		results = append(results, enforced)
	}

	return results
}

func extractEbsEncryption(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}

	for _, volume := range ec2.Volumes {
		if volume.Encrypted != nil {
			results = append(results, *volume.Encrypted)
		} else {
			results = append(results, false)
		}
	}

	return results
}

func extractSnapshotPublic(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, snapshotId := range ec2.PublicSnapshots {
		results = append(results, snapshotId)
	}
	return results
}

// func extractAmiVulnCount(data interface{}) []interface{} {
// 	ec2, ok := data.(scanner.Ec2AuditResults)
// 	if !ok {
// 		return nil
// 	}

// 	var results []interface{}

// 	return results
// }

// ===== RDS Handlers =====
func extractRdsPubliclyAccessible(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, db := range rds.DBInstances {
		if db.PubliclyAccessible != nil {
			results = append(results, *db.PubliclyAccessible)
		} else {
			results = append(results, false)
		}
	}
	return results
}

func extractRdsBackupRetention(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, db := range rds.DBInstances {
		if db.BackupRetentionPeriod != nil {
			results = append(results, int(*db.BackupRetentionPeriod))
		} else {
			results = append(results, 0)
		}
	}
	return results
}

func extractRdsSnapshotEncryption(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, snapshot := range rds.DBSnapshots {
		if snapshot.Encrypted != nil {
			results = append(results, *snapshot.Encrypted)
		} else {
			results = append(results, false)
		}
	}
	return results
}

func extractRdsMultiAZ(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, db := range rds.DBInstances {
		if db.MultiAZ != nil {
			results = append(results, *db.MultiAZ)
		} else {
			results = append(results, false)
		}
	}
	return results
}

func extractRdsLateralAccess(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// For lateral movement, we check if DB is in VPC and not public
	// If it's accessible within VPC, it could allow lateral movement
	for _, db := range rds.DBInstances {
		lateralAccessPossible := false
		if db.PubliclyAccessible != nil && !*db.PubliclyAccessible {
			// If not public but in VPC, lateral access is possible
			if db.DBSubnetGroup != nil && db.DBSubnetGroup.VpcId != nil {
				lateralAccessPossible = true
			}
		}
		results = append(results, lateralAccessPossible)
	}
	return results
}

func extractRdsSnapshotPublic(data interface{}) []interface{} {
	rds, ok := data.(scanner.RdsAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for _, snapshotId := range rds.PublicSnapshots {
		results = append(results, snapshotId)
	}
	return results
}

// ===== Lambda Handlers =====
func extractLambdaPrivilegeEscalation(data interface{}) []interface{} {
	lambda, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// Return function names that have roles with sts:AssumeRole permission
	for range lambda.RolesWithAssumeRole {
		results = append(results, true)
	}

	// If no functions found, return at least one result for comparison
	if len(results) == 0 && len(lambda.Functions) > 0 {
		results = append(results, false)
	}

	return results
}

func extractLambdaSecretExposure(data interface{}) []interface{} {
	lambda, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// Return function names that have hardcoded secrets in environment variables
	for range lambda.FunctionsWithSecrets {
		results = append(results, true)
	}

	// If no functions found, return at least one result for comparison
	if len(results) == 0 && len(lambda.Functions) > 0 {
		results = append(results, false)
	}

	return results
}

func extractLambdaUnauthenticatedAccess(data interface{}) []interface{} {
	lambda, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// Check Lambda Function URL authentication type
	for _, authType := range lambda.FunctionUrlAuthTypes {
		results = append(results, authType)
	}
	return results
}

func extractLambdaDLQConfig(data interface{}) []interface{} {
	lambda, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// Check if DLQ is configured
	for _, hasDLQ := range lambda.HasDLQ {
		results = append(results, hasDLQ)
	}
	return results
}

func extractLambdaSupplyChainRisk(data interface{}) []interface{} {
	lambda, ok := data.(scanner.LambdaAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	// Check for deprecated/vulnerable runtimes
	for range lambda.DeprecatedRuntimes {
		results = append(results, true)
	}

	// If no functions found, return at least one result for comparison
	if len(results) == 0 && len(lambda.Functions) > 0 {
		results = append(results, false)
	}

	return results
}
