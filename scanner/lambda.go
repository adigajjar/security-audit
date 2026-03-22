package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

type LambdaAuditResults struct {
	Functions                []types.FunctionConfiguration `json:"Functions"`
	FunctionUrlAuthTypes     map[string]string             `json:"FunctionUrlAuthTypes"`
	RolesWithAssumeRole      []string                      `json:"RolesWithAssumeRole"`
	FunctionsWithSecrets     []string                      `json:"FunctionsWithSecrets"`
	HasDLQ                   map[string]bool               `json:"HasDLQ"`
	DeprecatedRuntimes       []string                      `json:"DeprecatedRuntimes"`
}

// AuditLambda gathers all required Lambda security findings.
func AuditLambda(ctx context.Context, cfg aws.Config) (LambdaAuditResults, error) {
	lambdaClient := lambda.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	var results LambdaAuditResults

	results.FunctionUrlAuthTypes = make(map[string]string)
	results.HasDLQ = make(map[string]bool)
	results.RolesWithAssumeRole = []string{}
	results.FunctionsWithSecrets = []string{}
	results.DeprecatedRuntimes = []string{}

	// Deprecated runtimes list
	deprecatedRuntimes := map[string]bool{
		"nodejs12.x": true, "nodejs10.x": true, "nodejs8.10": true,
		"python3.6": true, "python2.7": true,
		"ruby2.5": true, "ruby2.7": true,
		"dotnetcore2.1": true, "dotnetcore3.1": true,
		"go1.x": true,
	}

	// Secret patterns in environment variable keys
	secretPatterns := []string{"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "credential"}

	// Get all Lambda functions
	functions, _ := AuditLambdaFunctions(ctx, lambdaClient)
	results.Functions = functions

	checkedRoles := make(map[string]bool)

	// For each function, check security issues
	for _, fn := range functions {
		if fn.FunctionArn == nil {
			continue
		}

		functionName := *fn.FunctionName

		// 1. Check for Function URL authentication
		urlConfig, err := lambdaClient.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
			FunctionName: fn.FunctionName,
		})
		if err == nil && urlConfig != nil {
			authType := string(urlConfig.AuthType)
			results.FunctionUrlAuthTypes[functionName] = authType
			fmt.Printf("[DEBUG] Function %s has URL with auth type: %s\n", functionName, authType)
		} else if err != nil {
			// Log the error to see what's happening
			fmt.Printf("[DEBUG] Error getting function URL config for %s: %v\n", functionName, err)
		}

		// 2. Check IAM role for AssumeRole permissions
		if fn.Role != nil && *fn.Role != "" {
			roleName := extractRoleNameFromArn(*fn.Role)
			if roleName != "" && !checkedRoles[roleName] {
				checkedRoles[roleName] = true
				hasAssumeRole := checkRoleForAssumeRolePermission(ctx, iamClient, roleName)
				if hasAssumeRole {
					results.RolesWithAssumeRole = append(results.RolesWithAssumeRole, functionName)
				}
			}
		}

		// 3. Check environment variables for hardcoded secrets
		if fn.Environment != nil && fn.Environment.Variables != nil {
			for key := range fn.Environment.Variables {
				keyLower := strings.ToLower(key)
				for _, pattern := range secretPatterns {
					if strings.Contains(keyLower, pattern) {
						results.FunctionsWithSecrets = append(results.FunctionsWithSecrets, functionName)
						break
					}
				}
			}
		}

		// 4. Check if DLQ is configured
		hasDLQ := false
		if fn.DeadLetterConfig != nil && fn.DeadLetterConfig.TargetArn != nil {
			hasDLQ = true
		}
		results.HasDLQ[functionName] = hasDLQ

		// 5. Check for deprecated runtimes
		if fn.Runtime != "" {
			if deprecatedRuntimes[string(fn.Runtime)] {
				results.DeprecatedRuntimes = append(results.DeprecatedRuntimes, functionName)
			}
		}
	}

	return results, nil
}

// Extract role name from ARN (arn:aws:iam::123456789012:role/RoleName)
func extractRoleNameFromArn(roleArn string) string {
	parts := strings.Split(roleArn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// Check if IAM role has sts:AssumeRole permission
func checkRoleForAssumeRolePermission(ctx context.Context, iamClient *iam.Client, roleName string) bool {
	// Get attached policies
	attachedPolicies, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return false
	}

	// Check each attached policy
	for _, policy := range attachedPolicies.AttachedPolicies {
		if policy.PolicyArn == nil {
			continue
		}

		// Get policy version
		policyResult, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: policy.PolicyArn,
		})
		if err != nil || policyResult.Policy == nil || policyResult.Policy.DefaultVersionId == nil {
			continue
		}

		// Get policy document
		versionResult, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.PolicyArn,
			VersionId: policyResult.Policy.DefaultVersionId,
		})
		if err != nil || versionResult.PolicyVersion == nil || versionResult.PolicyVersion.Document == nil {
			continue
		}

		// Parse policy document and check for sts:AssumeRole
		if checkPolicyForAssumeRole(*versionResult.PolicyVersion.Document) {
			return true
		}
	}

	// Check inline policies
	inlinePolicies, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return false
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		policyResult, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil || policyResult.PolicyDocument == nil {
			continue
		}

		if checkPolicyForAssumeRole(*policyResult.PolicyDocument) {
			return true
		}
	}

	return false
}

// Parse policy document JSON and check for sts:AssumeRole action
func checkPolicyForAssumeRole(policyDocument string) bool {
	var policy map[string]interface{}
	err := json.Unmarshal([]byte(policyDocument), &policy)
	if err != nil {
		return false
	}

	statements, ok := policy["Statement"].([]interface{})
	if !ok {
		return false
	}

	for _, stmt := range statements {
		statement, ok := stmt.(map[string]interface{})
		if !ok {
			continue
		}

		// Check Effect is Allow
		effect, ok := statement["Effect"].(string)
		if !ok || effect != "Allow" {
			continue
		}

		// Check Action
		if checkActionsForAssumeRole(statement["Action"]) {
			return true
		}
	}

	return false
}

// Check if actions contain sts:AssumeRole or sts:*
func checkActionsForAssumeRole(action interface{}) bool {
	switch v := action.(type) {
	case string:
		return strings.Contains(strings.ToLower(v), "sts:assumerole") || v == "sts:*" || v == "*"
	case []interface{}:
		for _, a := range v {
			if str, ok := a.(string); ok {
				if strings.Contains(strings.ToLower(str), "sts:assumerole") || str == "sts:*" || str == "*" {
					return true
				}
			}
		}
	}
	return false
}

func AuditLambdaFunctions(ctx context.Context, client *lambda.Client) ([]types.FunctionConfiguration, error) {
	var audits []types.FunctionConfiguration

	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, err
		}
		audits = append(audits, page.Functions...)
	}

	return audits, nil
}
