package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type FullAuditResults struct {
	EC2 Ec2AuditResults `json:"ec2"`
}

func (f FullAuditResults) Get(key string) any {
	switch key {
	case "ec2":
		return f.EC2
	default:
		return nil
	}
}

func RunAudit(ctx context.Context, cfg aws.Config) (FullAuditResults, error) {
	var results FullAuditResults

	ec2Results, err := AuditEC2(ctx, cfg)
	if err != nil {
		return results, err
	}
	results.EC2 = ec2Results

	return results, nil
}