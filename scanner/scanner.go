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
	S3        S3AuditResults        `json:"s3"`
	// Beanstalk BeanstalkAuditResults `json:"beanstalk"`
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
	case "s3":
		return f.S3
	// case "beanstalk":
	// 	return f.Beanstalk
	default:
		return nil
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a || b == "all" {
			return true
		}
	}
	return false
}

func RunAudit(ctx context.Context, cfg aws.Config, services ...string) (FullAuditResults, error) {
	var results FullAuditResults

	if len(services) == 0 {
		services = []string{"all"}
	}

	if stringInSlice("ec2", services) {
		ec2Results, err := AuditEC2(ctx, cfg)
		if err == nil {
			results.EC2 = ec2Results
		}
	}

	if stringInSlice("rds", services) {
		rdsResults, err := AuditRDS(ctx, cfg)
		if err == nil {
			results.RDS = rdsResults
		}
	}

	if stringInSlice("lambda", services) {
		lambdaResults, err := AuditLambda(ctx, cfg)
		if err == nil {
			results.Lambda = lambdaResults
		}
	}

	if stringInSlice("iam", services) {
		iamResults, err := AuditIAM(ctx, cfg)
		if err == nil {
			results.IAM = iamResults
		}
	}

	if stringInSlice("s3", services) {
		s3Results, err := AuditS3(ctx, cfg)
		if err == nil {
			results.S3 = s3Results
		}
	}

	// if stringInSlice("beanstalk", services) {
	// 	beanstalkResults, err := AuditBeanstalk(ctx, cfg)
	// 	if err == nil {
	// 		results.Beanstalk = beanstalkResults
	// 	}
	// }

	return results, nil
}
