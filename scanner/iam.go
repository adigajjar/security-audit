package scanner

import (
	"context"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type IamAuditResults struct {
	AccountSummary       map[string]int32                    `json:"AccountSummary"`
	PasswordPolicy       *types.PasswordPolicy               `json:"PasswordPolicy"`
	Users                []types.User                        `json:"Users"`
	UserMFADevices       map[string][]types.MFADevice        `json:"UserMFADevices"`
	AttachedUserPolicies map[string][]types.AttachedPolicy   `json:"AttachedUserPolicies"`
	UserPolicies         map[string][]string                 `json:"UserPolicies"`
	AccessKeys           map[string][]types.AccessKeyMetadata `json:"AccessKeys"`
	AccessKeyLastUsed    map[string]*types.AccessKeyLastUsed `json:"AccessKeyLastUsed"`
	Roles                []types.Role                        `json:"Roles"`
	Policies             []types.Policy                      `json:"Policies"`
	PolicyDocuments      map[string]string                   `json:"PolicyDocuments"`
}

func AuditIAM(ctx context.Context, cfg aws.Config) (IamAuditResults, error) {
	client := iam.NewFromConfig(cfg)
	var results IamAuditResults

	summary, _ := AuditAccountSummary(ctx, client)
	results.AccountSummary = summary

	pwPolicy, _ := AuditPasswordPolicy(ctx, client)
	results.PasswordPolicy = pwPolicy

	users, mfas, attachedPols, userPols, keys, lastUsed, err := AuditUsers(ctx, client)
	if err == nil {
		results.Users = users
		results.UserMFADevices = mfas
		results.AttachedUserPolicies = attachedPols
		results.UserPolicies = userPols
		results.AccessKeys = keys
		results.AccessKeyLastUsed = lastUsed
	}

	roles, err := AuditRoles(ctx, client)
	if err == nil {
		results.Roles = roles
	}

	policies, docs, err := AuditPolicies(ctx, client)
	if err == nil {
		results.Policies = policies
		results.PolicyDocuments = docs
	}

	return results, nil
}

func AuditAccountSummary(ctx context.Context, client *iam.Client) (map[string]int32, error) {
	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	return summary.SummaryMap, nil
}

func AuditPasswordPolicy(ctx context.Context, client *iam.Client) (*types.PasswordPolicy, error) {
	pwPolicy, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		return nil, err
	}
	return pwPolicy.PasswordPolicy, nil
}

func AuditUsers(ctx context.Context, client *iam.Client) (
	[]types.User,
	map[string][]types.MFADevice,
	map[string][]types.AttachedPolicy,
	map[string][]string,
	map[string][]types.AccessKeyMetadata,
	map[string]*types.AccessKeyLastUsed,
	error,
) {
	var users []types.User
	mfas := make(map[string][]types.MFADevice)
	attachedPols := make(map[string][]types.AttachedPolicy)
	userPols := make(map[string][]string)
	keys := make(map[string][]types.AccessKeyMetadata)
	lastUsed := make(map[string]*types.AccessKeyLastUsed)

	usersPag := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})

	for usersPag.HasMorePages() {
		page, err := usersPag.NextPage(ctx)
		if err != nil {
			return users, mfas, attachedPols, userPols, keys, lastUsed, err
		}
		users = append(users, page.Users...)

		for _, user := range page.Users {
			uName := *user.UserName

			mfaOut, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: user.UserName})
			if err == nil {
				mfas[uName] = mfaOut.MFADevices
			}

			attOut, err := client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
			if err == nil {
				attachedPols[uName] = attOut.AttachedPolicies
			}

			polOut, err := client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: user.UserName})
			if err == nil {
				userPols[uName] = polOut.PolicyNames
			}

			akOut, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: user.UserName})
			if err == nil {
				keys[uName] = akOut.AccessKeyMetadata
				for _, ak := range akOut.AccessKeyMetadata {
					luOut, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: ak.AccessKeyId})
					if err == nil && luOut.AccessKeyLastUsed != nil {
						lastUsed[*ak.AccessKeyId] = luOut.AccessKeyLastUsed
					}
				}
			}
		}
	}

	return users, mfas, attachedPols, userPols, keys, lastUsed, nil
}

func AuditRoles(ctx context.Context, client *iam.Client) ([]types.Role, error) {
	var roles []types.Role
	rolesPag := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})

	for rolesPag.HasMorePages() {
		page, err := rolesPag.NextPage(ctx)
		if err != nil {
			return roles, err
		}
		roles = append(roles, page.Roles...)
	}

	return roles, nil
}

func AuditPolicies(ctx context.Context, client *iam.Client) ([]types.Policy, map[string]string, error) {
	var policies []types.Policy
	docs := make(map[string]string)

	polsPag := iam.NewListPoliciesPaginator(client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	})

	for polsPag.HasMorePages() {
		page, err := polsPag.NextPage(ctx)
		if err != nil {
			return policies, docs, err
		}
		policies = append(policies, page.Policies...)

		for _, p := range page.Policies {
			vOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: p.Arn,
				VersionId: p.DefaultVersionId,
			})
			if err == nil && vOut.PolicyVersion != nil && vOut.PolicyVersion.Document != nil {
				docStr, err := url.QueryUnescape(*vOut.PolicyVersion.Document)
				if err == nil {
					docs[*p.Arn] = docStr
				}
			}
		}
	}

	return policies, docs, nil
}