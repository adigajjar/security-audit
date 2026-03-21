package scanner

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3AuditResults struct {
	Bucket            []BucketAudit            `json:"bucket"`
	PublicAccessBlock []PublicAccessBlockAudit `json:"public_access_block"`
}

type PublicAccessBlockAudit struct {
	BucketName        string `json:"bucket_name"`
	BlockPublicAcls   bool   `json:"BlockPublicAcls"`
	BlockPublicPolicy bool   `json:"BlockPublicPolicy"`
	IgnorePublicAcls  bool   `json:"IgnorePublicAcls"`
	RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
}

type BucketAudit struct {
	BucketName              string          `json:"bucket_name"`
	Region                  string          `json:"region"`
	IsInCorrectRegion       bool            `json:"is_in_correct_region"`
	BlockPublicAccess       bool            `json:"block_public_access"`
	ACLAllowsPublicRead     bool            `json:"acl_allows_public_read"`
	ACLAllowsPublicWrite    bool            `json:"acl_allows_public_write"`
	PolicyAllowsPublic      bool            `json:"policy_allows_public"`
	VersioningEnabled       bool            `json:"versioning_enabled"`
	MfaDeleteEnabled        bool            `json:"mfa_delete_enabled"`
	Encryption              EncryptionAudit `json:"encryption"`
	Logging                 LoggingAudit    `json:"logging"`
	IndividuallyPublicObjs  []string        `json:"individually_public_objects"`
}

type EncryptionAudit struct {
	Enabled bool `json:"enabled"`
}

type LoggingAudit struct {
	Enabled bool `json:"enabled"`
}

func AuditS3(ctx context.Context, cfg aws.Config) (S3AuditResults, error) {
	client := s3.NewFromConfig(cfg)
	var results S3AuditResults

	output, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return results, err
	}

	for _, bucket := range output.Buckets {
		bName := *bucket.Name
		audit := BucketAudit{
			BucketName: bName,
		}

		// 1. Region
		locStr := "us-east-1"
		locOut, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &bName})
		if err == nil && locOut.LocationConstraint != "" {
			locStr = string(locOut.LocationConstraint)
		}
		audit.Region = locStr
		audit.IsInCorrectRegion = (locStr == cfg.Region)

		// 2. Block Public Access
		bpaOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bName})
		if err == nil && bpaOut.PublicAccessBlockConfiguration != nil {
			conf := bpaOut.PublicAccessBlockConfiguration
			audit.BlockPublicAccess = *conf.BlockPublicAcls && *conf.BlockPublicPolicy && *conf.IgnorePublicAcls && *conf.RestrictPublicBuckets
			
			results.PublicAccessBlock = append(results.PublicAccessBlock, PublicAccessBlockAudit{
				BucketName: bName,
				BlockPublicAcls: *conf.BlockPublicAcls,
				BlockPublicPolicy: *conf.BlockPublicPolicy,
				IgnorePublicAcls: *conf.IgnorePublicAcls,
				RestrictPublicBuckets: *conf.RestrictPublicBuckets,
			})
		} else {
			results.PublicAccessBlock = append(results.PublicAccessBlock, PublicAccessBlockAudit{
				BucketName: bName,
				BlockPublicAcls: false,
				BlockPublicPolicy: false,
				IgnorePublicAcls: false,
				RestrictPublicBuckets: false,
			})
		}

		// 3. Bucket ACL
		aclOut, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &bName})
		if err == nil {
			for _, grant := range aclOut.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					uri := *grant.Grantee.URI
					if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
						switch grant.Permission {
						case types.PermissionRead:
							audit.ACLAllowsPublicRead = true
						case types.PermissionWrite, types.PermissionFullControl:
							audit.ACLAllowsPublicWrite = true
						}
					}
				}
			}
		}

		// 4. Policy Allows Public
		polStatus, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: &bName})
		if err == nil && polStatus.PolicyStatus != nil {
			audit.PolicyAllowsPublic = polStatus.PolicyStatus.IsPublic != nil && *polStatus.PolicyStatus.IsPublic
		}

		// 5. Versioning
		vers, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &bName})
		if err == nil {
			audit.VersioningEnabled = vers.Status == types.BucketVersioningStatusEnabled
			audit.MfaDeleteEnabled = vers.MFADelete == types.MFADeleteStatusEnabled
		}

		// 6. Encryption
		enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bName})
		if err == nil && enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0 {
			audit.Encryption = EncryptionAudit{Enabled: true}
		}

		// 7. Logging
		logOut, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &bName})
		if err == nil {
			audit.Logging = LoggingAudit{Enabled: logOut.LoggingEnabled != nil}
		}

		// 8. Individually public objects check (sample up to 50 objects to limit API calls)
		var publicObjs []string
		listOut, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  &bName,
			MaxKeys: aws.Int32(50),
		})
		if err == nil {
			for _, obj := range listOut.Contents {
				objAcl, err := client.GetObjectAcl(ctx, &s3.GetObjectAclInput{Bucket: &bName, Key: obj.Key})
				if err == nil {
					isObjPublic := false
					for _, g := range objAcl.Grants {
						if g.Grantee != nil && g.Grantee.URI != nil {
							uri := *g.Grantee.URI
							if strings.Contains(uri, "AllUsers") || strings.Contains(uri, "AuthenticatedUsers") {
								isObjPublic = true
								break
							}
						}
					}
					if isObjPublic {
						publicObjs = append(publicObjs, *obj.Key)
					}
				}
			}
			audit.IndividuallyPublicObjs = publicObjs
		}

		results.Bucket = append(results.Bucket, audit)
	}

	return results, nil
}