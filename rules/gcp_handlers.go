package rules

import (
	"strings"

	"github.com/adigajjar/security-audit/scanner"
)

// ─────────────────────────────────────────────────────────────────────────────
// GCP IAM Handlers  (registered in init() below)
// These mirror the AWS handler pattern: each function receives the raw
// scanner output and returns a []interface{} that the evaluator compares
// against the rule's check.operator / check.value.
// ─────────────────────────────────────────────────────────────────────────────

func init() {
	// Register all GCP IAM handlers into the shared registry
	registry["gcp_primitive_role_assigned"]      = extractGCPPrimitiveRoles
	registry["gcp_sa_user_managed_key_exists"]   = extractGCPSAUserManagedKeys
	registry["gcp_sa_project_admin_role"]        = extractGCPSAProjectAdminRole
	registry["gcp_cross_project_iam_binding"]    = extractGCPCrossProjectBinding
	registry["gcp_public_resource_access"]       = extractGCPPublicMemberBinding
}

// ─────────────────────────────────────────────────────────────────────────────
// G-IAM-1  Primitive Roles (Owner/Editor) Assigned to Users
// Returns true for every binding where the role is roles/owner or roles/editor
// AND at least one member is a user: or serviceAccount: principal (not a group).
// ─────────────────────────────────────────────────────────────────────────────
func extractGCPPrimitiveRoles(data interface{}) []interface{} {
	iam, ok := data.(scanner.GCPIAMAuditResults)
	if !ok {
		return nil
	}

	primitives := map[string]bool{
		"roles/owner":  true,
		"roles/editor": true,
	}

	var results []interface{}
	for _, b := range iam.Bindings {
		if !primitives[b.Role] {
			continue
		}
		for _, member := range b.Members {
			// Flag user: and serviceAccount: members; skip group: / domain: bindings
			if strings.HasPrefix(member, "user:") || strings.HasPrefix(member, "serviceAccount:") {
				results = append(results, true)
			}
		}
	}

	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// G-IAM-2  Service Account Key File Downloaded and Stored
// Returns true for every USER_MANAGED (i.e. exported JSON) key found.
// ─────────────────────────────────────────────────────────────────────────────
func extractGCPSAUserManagedKeys(data interface{}) []interface{} {
	iam, ok := data.(scanner.GCPIAMAuditResults)
	if !ok {
		return nil
	}

	var results []interface{}
	for range iam.ServiceAccountKeys {
		// Each entry already filtered to USER_MANAGED by the scanner
		results = append(results, true)
	}

	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// G-IAM-3  Service Account Has Project-Level Admin Role
// Returns true when a serviceAccount: member holds roles/owner, roles/editor
// or another well-known admin role at project scope.
// ─────────────────────────────────────────────────────────────────────────────
func extractGCPSAProjectAdminRole(data interface{}) []interface{} {
	iam, ok := data.(scanner.GCPIAMAuditResults)
	if !ok {
		return nil
	}

	adminRoles := map[string]bool{
		"roles/owner":  true,
		"roles/editor": true,
		"roles/iam.serviceAccountAdmin":         true,
		"roles/iam.serviceAccountTokenCreator":  true,
		"roles/resourcemanager.projectIamAdmin": true,
	}

	var results []interface{}
	for _, b := range iam.Bindings {
		if !adminRoles[b.Role] {
			continue
		}
		for _, member := range b.Members {
			if strings.HasPrefix(member, "serviceAccount:") {
				results = append(results, true)
			}
		}
	}

	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// G-IAM-4  Cross-Project IAM Binding Without Justification
// Heuristic: a member whose email domain doesn't match the project's own
// service-account domain (*.iam.gserviceaccount.com belonging to a DIFFERENT
// project) is considered cross-project.
// ─────────────────────────────────────────────────────────────────────────────
func extractGCPCrossProjectBinding(data interface{}) []interface{} {
	iam, ok := data.(scanner.GCPIAMAuditResults)
	if !ok {
		return nil
	}

	// Own SA domain for this project: <name>@<projectID>.iam.gserviceaccount.com
	ownSADomain := "@" + iam.ProjectID + ".iam.gserviceaccount.com"

	var results []interface{}
	for _, b := range iam.Bindings {
		for _, member := range b.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				continue
			}
			email := strings.TrimPrefix(member, "serviceAccount:")
			// If it IS a GCP SA but NOT from this project → cross-project pivot
			if strings.HasSuffix(email, ".iam.gserviceaccount.com") &&
				!strings.HasSuffix(email, ownSADomain) {
				results = append(results, true)
			}
		}
	}

	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}

// ─────────────────────────────────────────────────────────────────────────────
// G-IAM-5  allUsers / allAuthenticatedUsers on Sensitive Resources
// Returns true for ANY binding whose member list contains either public token.
// ─────────────────────────────────────────────────────────────────────────────
func extractGCPPublicMemberBinding(data interface{}) []interface{} {
	iam, ok := data.(scanner.GCPIAMAuditResults)
	if !ok {
		return nil
	}

	publicTokens := map[string]bool{
		"allUsers":              true,
		"allAuthenticatedUsers": true,
	}

	var results []interface{}
	for _, b := range iam.Bindings {
		for _, member := range b.Members {
			if publicTokens[member] {
				results = append(results, true)
			}
		}
	}

	if len(results) == 0 {
		results = append(results, false)
	}
	return results
}
