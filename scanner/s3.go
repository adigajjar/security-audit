package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3AuditResults struct {
	Buckets            []types.Bucket `json:"Buckets"`
	PublicAccessBlocks map[string]bool
	EncryptionEnabled  map[string]bool
	VersioningEnabled  map[string]bool
	MFADeleteEnabled   map[string]bool
	PolicyAllowsPublic map[string]bool
	LoggingEnabled     map[string]bool
}

func AuditS3(ctx context.Context, cfg aws.Config) (S3AuditResults, error) {
	client := s3.NewFromConfig(cfg)
	var results S3AuditResults
	results.PublicAccessBlocks = make(map[string]bool)
	results.EncryptionEnabled = make(map[string]bool)
	results.VersioningEnabled = make(map[string]bool)
	results.MFADeleteEnabled = make(map[string]bool)
	results.PolicyAllowsPublic = make(map[string]bool)
	results.LoggingEnabled = make(map[string]bool)

	buckets, _ := AuditBuckets(ctx, client)
	results.Buckets = buckets

	for _, bucket := range buckets {
		if bucket.Name == nil {
			continue
		}
		bName := *bucket.Name

		// Public Access Block
		bpaOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bName})
		if err == nil && bpaOut.PublicAccessBlockConfiguration != nil {
			conf := bpaOut.PublicAccessBlockConfiguration
			results.PublicAccessBlocks[bName] = *conf.BlockPublicAcls && *conf.BlockPublicPolicy && *conf.IgnorePublicAcls && *conf.RestrictPublicBuckets
		} else {
			results.PublicAccessBlocks[bName] = false
		}

		// Encryption
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bName})
		results.EncryptionEnabled[bName] = err == nil && enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0

		// Versioning
		vers, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bName})
		if err == nil {
			results.VersioningEnabled[bName] = vers.Status == types.BucketVersioningStatusEnabled
			results.MFADeleteEnabled[bName] = vers.MFADelete == types.MFADeleteStatusEnabled
		} else {
			results.VersioningEnabled[bName] = false
			results.MFADeleteEnabled[bName] = false
		}

		// Policy
		polStatus, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: &bName})
		if err == nil && polStatus.PolicyStatus != nil {
			results.PolicyAllowsPublic[bName] = polStatus.PolicyStatus.IsPublic != nil && *polStatus.PolicyStatus.IsPublic
		} else {
			results.PolicyAllowsPublic[bName] = false
		}

		// Logging
		logOut, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &bName})
		results.LoggingEnabled[bName] = err == nil && logOut.LoggingEnabled != nil
	}

	return results, nil
}

func AuditBuckets(ctx context.Context, client *s3.Client) ([]types.Bucket, error) {
	var audits []types.Bucket

	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return audits, err
	}

	audits = append(audits, output.Buckets...)

	return audits, nil
}