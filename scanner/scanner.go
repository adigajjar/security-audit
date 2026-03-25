package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type FullAuditResults struct {
	EC2    Ec2AuditResults    `json:"ec2"`
	RDS    RdsAuditResults    `json:"rds"`
	Lambda    LambdaAuditResults    `json:"lambda"`
	IAM       IamAuditResults       `json:"iam"`
	Beanstalk BeanstalkAuditResults `json:"beanstalk"`
}

func (f FullAuditResults) Get(key string) any {
	switch key {
	case "ec2":
		return f.EC2
	case "rds":
		return f.RDS
	case "lambda":
		return f.Lambda
	case "iam":
		return f.IAM
	case "beanstalk":
		return f.Beanstalk
	default:
		return nil
	}
}

func RunAudit(ctx context.Context, cfg aws.Config) (FullAuditResults, error) {
	var results FullAuditResults

	ec2Results, err := AuditEC2(ctx, cfg)
	if err == nil {
		results.EC2 = ec2Results
	}

	rdsResults, err := AuditRDS(ctx, cfg)
	if err == nil {
		results.RDS = rdsResults
	}

	lambdaResults, err := AuditLambda(ctx, cfg)
	if err == nil {
		results.Lambda = lambdaResults
	}

	iamResults, err := AuditIAM(ctx, cfg)
	if err == nil {
		results.IAM = iamResults
	}

	beanstalkResults, err := AuditBeanstalk(ctx, cfg)
	if err == nil {
		results.Beanstalk = beanstalkResults
	}

	return results, nil
}
