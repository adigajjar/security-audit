package connector

import (
	"context"

	"github.com/ShubhankarSalunke/lucifer/connectors"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func ConnectAws(ctx context.Context, roleArn string, externalId string) (aws.Config, error) {
	return connectors.ConnectAws(ctx, roleArn, externalId)
}