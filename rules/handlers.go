package rules

import (
	"strings"

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

	//IAM handlers
	"root_mfa_disabled": extractIamRootAccess,
	"wildcard_policy": extractIamWildcardPolicy,
	"privileged_user_mfa_disabled": extractIamMfaEnforced,
	"stale_access_key": extractIamAccessKeyRotation,
	"inline_policy_bypass": extractIamInlinePolicies,
	"cross_account_trust_misconfiguration": extractIamCrossAccountAccess,

	//Beanstalk handlers
	"no_https_on_load_balancer": extractBeanstalkPublicAccess,
	"excessive_instance_profile_permissions": extractBeanstalkInstanceProfile,
	"enhanced_health_reporting_disabled": extractBeanstalkEnhancedHealthReporting,
	"plaintext_secrets_in_env": extractBeanstalkEnvironmentVariables,
	"outdated_platform_version": extractBeanstalkVersionLifecycle,
	
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

// ===== IAM Handlers =====
func extractIamRootAccess(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	hasSecureMfa := false
	if val, ok := iamOut.AccountSummary["AccountMFAEnabled"]; ok {
		hasSecureMfa = val > 0
	}
	results = append(results, hasSecureMfa)
	return results
}

func extractIamWildcardPolicy(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, doc := range iamOut.PolicyDocuments {
		if strings.Contains(doc, "\"*\"") || strings.Contains(doc, "%22*%22") {
			results = append(results, true)
		}
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractIamMfaEnforced(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, u := range iamOut.Users {
		if u.UserName == nil {
			continue
		}
		uName := *u.UserName
		isAdmin := false
		if policies, ok := iamOut.AttachedUserPolicies[uName]; ok {
			for _, p := range policies {
				if p.PolicyName != nil && *p.PolicyName == "AdministratorAccess" {
					isAdmin = true
					break
				}
			}
		}
		if isAdmin {
			hasMFA := false
			if mfas, ok := iamOut.UserMFADevices[uName]; ok {
				hasMFA = len(mfas) > 0
			}
			results = append(results, hasMFA)
		}
	}
	if len(results) == 0 {
		results = append(results, true)
	}
	return results
}

func extractIamAccessKeyRotation(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	
	var results []interface{}
	for _, userKeys := range iamOut.AccessKeys {
		for _, ak := range userKeys {
			if string(ak.Status) == "Active" {
				hasStale := false
				if ak.CreateDate != nil && ak.CreateDate.Year() < 2026 { 
					hasStale = true
				}
				results = append(results, hasStale)
			}
		}
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractIamInlinePolicies(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, pols := range iamOut.UserPolicies {
		if len(pols) > 0 {
			results = append(results, true)
		}
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractIamCrossAccountAccess(data interface{}) []interface{} {
	iamOut, ok := data.(scanner.IamAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, r := range iamOut.Roles {
		hasWildcard := false
		if r.AssumeRolePolicyDocument != nil {
			docStr := *r.AssumeRolePolicyDocument
			if len(docStr) > 0 { 
				hasWildcard = true
			}
		}
		results = append(results, hasWildcard)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

// ===== Beanstalk Handlers =====

func extractBeanstalkPublicAccess(data interface{}) []interface{} {
	bs, ok := data.(scanner.BeanstalkAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, options := range bs.ConfigurationSettings {
		hasHttps := false
		for _, opt := range options {
			if opt.Namespace != nil && *opt.Namespace == "aws:elbv2:listener:443" {
				hasHttps = true
				break
			}
			if opt.Namespace != nil && *opt.Namespace == "aws:elb:listener:443" {
				hasHttps = true
				break
			}
		}
		results = append(results, hasHttps)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractBeanstalkInstanceProfile(data interface{}) []interface{} {
	bs, ok := data.(scanner.BeanstalkAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, options := range bs.ConfigurationSettings {
		hasProfile := false
		for _, opt := range options {
			if opt.OptionName != nil && *opt.OptionName == "IamInstanceProfile" {
				hasProfile = true
			}
		}
		results = append(results, hasProfile)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractBeanstalkEnhancedHealthReporting(data interface{}) []interface{} {
	bs, ok := data.(scanner.BeanstalkAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, options := range bs.ConfigurationSettings {
		hasEnhanced := false
		for _, opt := range options {
			if opt.Namespace != nil && *opt.Namespace == "aws:elasticbeanstalk:healthreporting:system" {
				if opt.OptionName != nil && *opt.OptionName == "SystemType" {
					if opt.Value != nil && *opt.Value == "enhanced" {
						hasEnhanced = true
					}
				}
			}
		}
		// Returns whether it is enhanced
		results = append(results, hasEnhanced)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractBeanstalkEnvironmentVariables(data interface{}) []interface{} {
	bs, ok := data.(scanner.BeanstalkAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, options := range bs.ConfigurationSettings {
		hasSecrets := false
		for _, opt := range options {
			if opt.Namespace != nil && *opt.Namespace == "aws:elasticbeanstalk:application:environment" {
				if opt.OptionName != nil {
					key := strings.ToUpper(*opt.OptionName)
					if strings.Contains(key, "SECRET") || strings.Contains(key, "PASSWORD") || strings.Contains(key, "TOKEN") || strings.Contains(key, "KEY") {
						hasSecrets = true
					}
				}
			}
		}
		results = append(results, hasSecrets)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

func extractBeanstalkVersionLifecycle(data interface{}) []interface{} {
	bs, ok := data.(scanner.BeanstalkAuditResults)
	if !ok {
		return nil
	}
	var results []interface{}
	for _, env := range bs.Environments {
		isOutdated := false
		if env.SolutionStackName != nil {
			if strings.Contains(*env.SolutionStackName, "Amazon Linux AMI") || strings.Contains(*env.SolutionStackName, "deprecated") {
				isOutdated = true
			}
		}
		results = append(results, isOutdated)
	}
	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}
