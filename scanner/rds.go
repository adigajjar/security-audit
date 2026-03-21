package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

type RdsAuditResults struct {
	DBInstances     []types.DBInstance `json:"DBInstances"`
	DBSnapshots     []types.DBSnapshot `json:"DBSnapshots"`
	PublicSnapshots []string           `json:"PublicSnapshots"`
}

// AuditRDS gathers all required RDS security findings.
func AuditRDS(ctx context.Context, cfg aws.Config) (RdsAuditResults, error) {
	client := rds.NewFromConfig(cfg)
	var results RdsAuditResults

	instances, _ := AuditDBInstances(ctx, client)
	results.DBInstances = instances

	snapshots, publicSnapshots, _ := AuditDBSnapshots(ctx, client)
	results.DBSnapshots = snapshots
	results.PublicSnapshots = publicSnapshots

	return results, nil
}

func AuditDBInstances(ctx context.Context, client *rds.Client) ([]types.DBInstance, error) {
	var audits []types.DBInstance

	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, err
		}
		audits = append(audits, page.DBInstances...)
	}

	return audits, nil
}

func AuditDBSnapshots(ctx context.Context, client *rds.Client) ([]types.DBSnapshot, []string, error) {
	var audits []types.DBSnapshot
	var publicSnapshots []string

	paginator := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, publicSnapshots, err
		}
		audits = append(audits, page.DBSnapshots...)
	}

	// Check each snapshot for public access
	for _, snapshot := range audits {
		if snapshot.DBSnapshotIdentifier == nil {
			continue
		}

		attr, err := client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
			DBSnapshotIdentifier: snapshot.DBSnapshotIdentifier,
		})
		if err != nil {
			continue
		}

		// Check if snapshot has public restore permissions
		if attr.DBSnapshotAttributesResult != nil {
			for _, attrVal := range attr.DBSnapshotAttributesResult.DBSnapshotAttributes {
				if attrVal.AttributeName != nil && *attrVal.AttributeName == "restore" {
					for _, val := range attrVal.AttributeValues {
						if val == "all" {
							publicSnapshots = append(publicSnapshots, *snapshot.DBSnapshotIdentifier)
							break
						}
					}
				}
			}
		}
	}

	return audits, publicSnapshots, nil
}
