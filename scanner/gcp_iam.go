package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/ShubhankarSalunke/lucifer/connectors"
	"google.golang.org/api/cloudresourcemanager/v1"
	iamv1 "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// ─────────────────────────────────────────────
// Data model returned by AuditGCPIAM
// ─────────────────────────────────────────────

// GCPIAMBinding represents a single IAM binding (role → members) on the project.
type GCPIAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// GCPServiceAccountKey is a lightweight representation of a SA key.
type GCPServiceAccountKey struct {
	ServiceAccount string `json:"service_account"`
	KeyID          string `json:"key_id"`
	KeyType        string `json:"key_type"` // "USER_MANAGED" or "SYSTEM_MANAGED"
	ValidAfterTime string `json:"valid_after_time"`
}

// GCPIAMAuditResults is the aggregated output of the GCP IAM scanner.
type GCPIAMAuditResults struct {
	ProjectID string `json:"project_id"`

	// All IAM bindings at the project level.
	Bindings []GCPIAMBinding `json:"bindings"`

	// ServiceAccountKeys contains USER_MANAGED keys (i.e. exported JSON keys).
	ServiceAccountKeys []GCPServiceAccountKey `json:"service_account_keys"`

	// ServiceAccounts is a flat list of service account emails in the project.
	ServiceAccounts []string `json:"service_accounts"`
}

// ─────────────────────────────────────────────
// Primitives (basic roles) considered dangerous
// ─────────────────────────────────────────────
var primitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
}

// ─────────────────────────────────────────────
// Roles considered "admin/sensitive" for SA checks
// ─────────────────────────────────────────────
var sensitiveRoles = map[string]bool{
	"roles/owner":  true,
	"roles/editor": true,
	"roles/iam.serviceAccountAdmin":       true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/resourcemanager.projectIamAdmin": true,
}

// ─────────────────────────────────────────────
// Public IAM members
// ─────────────────────────────────────────────
var publicMembers = map[string]bool{
	"allUsers":              true,
	"allAuthenticatedUsers": true,
}

// ─────────────────────────────────────────────
// AuditGCPIAM – main entry point
// ─────────────────────────────────────────────

func AuditGCPIAM(ctx context.Context, client *connectors.GCPClient) (GCPIAMAuditResults, error) {
	var results GCPIAMAuditResults
	results.ProjectID = client.ProjectID

	// 1. Fetch project-level IAM policy
	bindings, err := fetchProjectIAMBindings(ctx, client.ProjectID, client.ClientOptions)
	if err != nil {
		fmt.Printf("[GCP IAM Scanner] Warning: could not fetch project IAM policy: %v\n", err)
	} else {
		results.Bindings = bindings
	}

	// 2. Fetch service accounts and their keys
	sas, keys, err := fetchServiceAccountKeys(ctx, client.ProjectID, client.ClientOptions)
	if err != nil {
		fmt.Printf("[GCP IAM Scanner] Warning: could not fetch service account keys: %v\n", err)
	} else {
		results.ServiceAccounts = sas
		results.ServiceAccountKeys = keys
	}

	return results, nil
}

// ─────────────────────────────────────────────
// fetchProjectIAMBindings
// ─────────────────────────────────────────────

func fetchProjectIAMBindings(ctx context.Context, projectID string, opts []option.ClientOption) ([]GCPIAMBinding, error) {
	crmSvc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating CRM service: %w", err)
	}

	policy, err := crmSvc.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("GetIamPolicy: %w", err)
	}

	var bindings []GCPIAMBinding
	for _, b := range policy.Bindings {
		bindings = append(bindings, GCPIAMBinding{
			Role:    b.Role,
			Members: b.Members,
		})
	}
	return bindings, nil
}

// ─────────────────────────────────────────────
// fetchServiceAccountKeys
// ─────────────────────────────────────────────

func fetchServiceAccountKeys(ctx context.Context, projectID string, opts []option.ClientOption) ([]string, []GCPServiceAccountKey, error) {
	iamSvc, err := iamv1.NewService(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating IAM service: %w", err)
	}

	// List all service accounts in the project
	saResp, err := iamSvc.Projects.ServiceAccounts.List("projects/" + projectID).Context(ctx).Do()
	if err != nil {
		return nil, nil, fmt.Errorf("listing service accounts: %w", err)
	}

	var saEmails []string
	var allKeys []GCPServiceAccountKey

	for _, sa := range saResp.Accounts {
		saEmails = append(saEmails, sa.Email)

		// List keys for each SA
		keysResp, err := iamSvc.Projects.ServiceAccounts.Keys.
			List("projects/" + projectID + "/serviceAccounts/" + sa.Email).
			Context(ctx).Do()
		if err != nil {
			fmt.Printf("[GCP IAM Scanner] Warning: could not list keys for %s: %v\n", sa.Email, err)
			continue
		}

		for _, k := range keysResp.Keys {
			// Only USER_MANAGED keys can be downloaded; SYSTEM_MANAGED are internal
			if k.KeyType == "USER_MANAGED" {
				// Extract just the key ID from the full resource name
				parts := strings.Split(k.Name, "/")
				keyID := parts[len(parts)-1]
				allKeys = append(allKeys, GCPServiceAccountKey{
					ServiceAccount: sa.Email,
					KeyID:          keyID,
					KeyType:        k.KeyType,
					ValidAfterTime: k.ValidAfterTime,
				})
			}
		}
	}

	return saEmails, allKeys, nil
}

// ─────────────────────────────────────────────
// GCPFullAuditResults — top-level aggregator for GCP scans
// ─────────────────────────────────────────────

type GCPFullAuditResults struct {
	IAM GCPIAMAuditResults `json:"iam"`
}

func (g GCPFullAuditResults) Get(key string) any {
	switch key {
	case "iam":
		return g.IAM
	default:
		return nil
	}
}

// ─────────────────────────────────────────────
// RunGCPAudit
// ─────────────────────────────────────────────

func RunGCPAudit(ctx context.Context, client *connectors.GCPClient, services ...string) (GCPFullAuditResults, error) {
	var results GCPFullAuditResults

	if len(services) == 0 {
		services = []string{"all"}
	}

	if stringInSlice("iam", services) {
		iamResults, err := AuditGCPIAM(ctx, client)
		if err == nil {
			results.IAM = iamResults
		} else {
			fmt.Printf("[GCP Audit] IAM scan error: %v\n", err)
		}
	}

	return results, nil
}
