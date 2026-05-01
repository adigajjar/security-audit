package connector

import (
	"context"

	"github.com/ShubhankarSalunke/lucifer/connectors"
)

// ConnectGCP connects to GCP using Application Default Credentials.
// projectID may be empty — the connector will fall back to the GCP_PROJECT_ID env var.
// credentialsFile may be empty — ADC resolution (GOOGLE_APPLICATION_CREDENTIALS) is used.
func ConnectGCP(ctx context.Context, projectID string, credentialsFile string) (*connectors.GCPClient, error) {
	gcpCfg := connectors.GCPConfig{
		ProjectID:       projectID,
		CredentialsFile: credentialsFile,
	}
	return connectors.ConnectGCP(ctx, gcpCfg)
}
