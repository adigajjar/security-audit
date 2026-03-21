package scanner

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type PolicyDocument struct {
	Statement []PolicyStatement `json:"Statement"`
}

type PolicyStatement struct {
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Principal interface{} `json:"Principal,omitempty"`
}

type IamAuditResults struct {
	RootAccount    RootAccountAudit    `json:"root_account"`
	PasswordPolicy PasswordPolicyAudit `json:"password_policy"`
	User           []UserAudit         `json:"user"`
	Role           []RoleAudit         `json:"role"`
	Policy         []PolicyAudit       `json:"policy"`
}

type RootAccountAudit struct {
	MFAEnabled       bool  `json:"mfa_enabled"`
	ActiveAccessKeys bool  `json:"active_access_keys"`
	ErrorFetching    error `json:"-"`
}

type PasswordPolicyAudit struct {
	Exists                         bool   `json:"exists"`
	MinimumPasswordLength          *int32 `json:"minimum_password_length,omitempty"`
	PasswordExpiryEnabled          bool   `json:"password_expiry_enabled"`
	MaxPasswordAge                 *int32 `json:"max_password_age,omitempty"`
	PasswordReusePreventionEnabled bool   `json:"password_reuse_prevention_enabled"`
	PasswordReusePreventionCount   *int32 `json:"password_reuse_prevention_count,omitempty"`
	ErrorFetching                  error  `json:"-"`
}

type UserAudit struct {
	UserName                         string           `json:"user_name"`
	MFAEnabled                       bool             `json:"mfa_enabled"`
	LastPasswordUsed                 *time.Time       `json:"last_password_used,omitempty"`
	AdminPermissionsDirectlyAttached bool             `json:"admin_permissions_directly_attached"`
	InlinePolicies                   []string         `json:"inline_policies"`
	AccessKeys                       []AccessKeyAudit `json:"access_keys"`
}

type AccessKeyAudit struct {
	AccessKeyId     string     `json:"access_key_id"`
	Status          string     `json:"status"`
	OlderThan90Days bool       `json:"older_than_90_days"`
	LastUsed        *time.Time `json:"last_used,omitempty"`
}

type RoleAudit struct {
	RoleName                string `json:"role_name"`
	AssumableByAnyPrincipal bool   `json:"assumable_by_any_principal"`
}

type PolicyAudit struct {
	PolicyName             string `json:"policy_name"`
	AllowsWildcardAction   bool   `json:"allows_wildcard_action"`
	AllowsWildcardResource bool   `json:"allows_wildcard_resource"`
}

func AuditIAM(ctx context.Context, cfg aws.Config) (IamAuditResults, error) {
	client := iam.NewFromConfig(cfg)
	var results IamAuditResults

	rootAccount, _ := AuditRootAccount(ctx, client)
	results.RootAccount = rootAccount

	passwordPolicy, _ := AuditPasswordPolicy(ctx, client)
	results.PasswordPolicy = passwordPolicy

	users, err := AuditUsers(ctx, client)
	if err == nil {
		results.User = users
	}

	roles, err := AuditRoles(ctx, client)
	if err == nil {
		results.Role = roles
	}

	policies, err := AuditPolicies(ctx, client)
	if err == nil {
		results.Policy = policies
	}

	return results, nil
}

func AuditRootAccount(ctx context.Context, client *iam.Client) (RootAccountAudit, error) {
	var result RootAccountAudit

	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		result.ErrorFetching = err
		return result, err
	}

	if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok {
		result.MFAEnabled = val > 0
	}
	if val, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok {
		result.ActiveAccessKeys = val > 0
	}

	return result, nil
}

func AuditPasswordPolicy(ctx context.Context, client *iam.Client) (PasswordPolicyAudit, error) {
	var result PasswordPolicyAudit

	pwPolicy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchEntity") {
			result.Exists = false
			return result, nil
		}
		result.ErrorFetching = err
		return result, err
	}

	result.Exists = true
	p := pwPolicy.PasswordPolicy
	if p.MinimumPasswordLength != nil {
		result.MinimumPasswordLength = p.MinimumPasswordLength
	}
	if p.MaxPasswordAge != nil {
		result.PasswordExpiryEnabled = true
		result.MaxPasswordAge = p.MaxPasswordAge
	}
	if p.PasswordReusePrevention != nil {
		result.PasswordReusePreventionEnabled = true
		result.PasswordReusePreventionCount = p.PasswordReusePrevention
	}

	return result, nil
}

func AuditUsers(ctx context.Context, client *iam.Client) ([]UserAudit, error) {
	var users []UserAudit
	usersPag := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	ninetyDaysAgo := time.Now().Add(-90 * 24 * time.Hour)

	for usersPag.HasMorePages() {
		page, err := usersPag.NextPage(ctx)
		if err != nil {
			return users, err
		}
		for _, user := range page.Users {
			uAudit := UserAudit{
				UserName:         *user.UserName,
				LastPasswordUsed: user.PasswordLastUsed,
				InlinePolicies:   []string{},
				AccessKeys:       []AccessKeyAudit{},
			}

			// MFA
			mfaOut, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: user.UserName})
			if err == nil {
				uAudit.MFAEnabled = len(mfaOut.MFADevices) > 0
			}

			// Admin Permissions Directly Attached
			attachedPols, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
			if err == nil {
				for _, p := range attachedPols.AttachedPolicies {
					if p.PolicyName != nil && *p.PolicyName == "AdministratorAccess" {
						uAudit.AdminPermissionsDirectlyAttached = true
						break
					}
				}
			}

			// Inline policies
			inlinePols, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
			if err == nil {
				uAudit.InlinePolicies = inlinePols.PolicyNames
			}

			// Access Keys
			akOut, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
			if err == nil {
				for _, ak := range akOut.AccessKeyMetadata {
					akAudit := AccessKeyAudit{
						AccessKeyId: *ak.AccessKeyId,
						Status:      string(ak.Status),
					}

					if ak.CreateDate != nil && ak.CreateDate.Before(ninetyDaysAgo) {
						akAudit.OlderThan90Days = true
					}

					// Unused Check
					luOut, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: ak.AccessKeyId})
					if err == nil {
						if luOut.AccessKeyLastUsed != nil {
							akAudit.LastUsed = luOut.AccessKeyLastUsed.LastUsedDate
						}
					}

					uAudit.AccessKeys = append(uAudit.AccessKeys, akAudit)
				}
			}

			users = append(users, uAudit)
		}
	}

	return users, nil
}

func AuditRoles(ctx context.Context, client *iam.Client) ([]RoleAudit, error) {
	var roles []RoleAudit
	rolesPag := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for rolesPag.HasMorePages() {
		page, err := rolesPag.NextPage(ctx)
		if err != nil {
			return roles, err
		}
		for _, r := range page.Roles {
			if r.AssumeRolePolicyDocument == nil {
				continue
			}

			docStr, err := url.QueryUnescape(*r.AssumeRolePolicyDocument)
			if err != nil {
				continue
			}

			var doc PolicyDocument
			if err := json.Unmarshal([]byte(docStr), &doc); err == nil {
				hasWildcardPrincipal := false
				for _, stmt := range doc.Statement {
					if stmt.Effect == "Allow" && stmt.Principal != nil {
						switch p := stmt.Principal.(type) {
						case string:
							if p == "*" {
								hasWildcardPrincipal = true
							}
						case map[string]interface{}:
							if awsp, ok := p["AWS"]; ok {
								if awsStr, ok2 := awsp.(string); ok2 && awsStr == "*" {
									hasWildcardPrincipal = true
								}
								if awsSlice, ok2 := awsp.([]interface{}); ok2 {
									for _, el := range awsSlice {
										if strEl, ok3 := el.(string); ok3 && strEl == "*" {
											hasWildcardPrincipal = true
										}
									}
								}
							}
						}
					}
				}
				
				if hasWildcardPrincipal {
					roles = append(roles, RoleAudit{
						RoleName:                *r.RoleName,
						AssumableByAnyPrincipal: hasWildcardPrincipal,
					})
				}
			}
		}
	}

	return roles, nil
}

func AuditPolicies(ctx context.Context, client *iam.Client) ([]PolicyAudit, error) {
	var policies []PolicyAudit
	polsPag := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	})

	for polsPag.HasMorePages() {
		page, err := polsPag.NextPage(ctx)
		if err != nil {
			return policies, err
		}
		for _, p := range page.Policies {
			vOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: p.Arn,
				VersionId: p.DefaultVersionId,
			})
			if err != nil || vOut.PolicyVersion == nil || vOut.PolicyVersion.Document == nil {
				continue
			}

			docStr, err := url.QueryUnescape(*vOut.PolicyVersion.Document)
			if err != nil {
				continue
			}

			var doc PolicyDocument
			if err := json.Unmarshal([]byte(docStr), &doc); err == nil {
				allowsWildcardAction := false
				allowsWildcardResource := false

				for _, stmt := range doc.Statement {
					if stmt.Effect == "Allow" {
						switch a := stmt.Action.(type) {
						case string:
							if a == "*" {
								allowsWildcardAction = true
							}
						case []interface{}:
							for _, act := range a {
								if actStr, ok := act.(string); ok && actStr == "*" {
									allowsWildcardAction = true
								}
							}
						}

						switch r := stmt.Resource.(type) {
						case string:
							if r == "*" {
								allowsWildcardResource = true
							}
						case []interface{}:
							for _, res := range r {
								if resStr, ok := res.(string); ok && resStr == "*" {
									allowsWildcardResource = true
								}
							}
						}
					}
				}
				
				if allowsWildcardAction || allowsWildcardResource {
					policies = append(policies, PolicyAudit{
						PolicyName:             *p.PolicyName,
						AllowsWildcardAction:   allowsWildcardAction,
						AllowsWildcardResource: allowsWildcardResource,
					})
				}
			}
		}
	}

	return policies, nil
}