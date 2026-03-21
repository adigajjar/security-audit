package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Ec2AuditResults struct {
	Instances      []types.Instance      `json:"Instances"`
	SecurityGroups []types.SecurityGroup `json:"SecurityGroups"`
	Volumes        []types.Volume        `json:"Volumes"`
	Images         []types.Image         `json:"Images"`
	Snapshots      []types.Snapshot      `json:"Snapshots"`
	PublicSnapshots []string             `json:"PublicSnapshots"`
}

// AuditEC2 gathers all required EC2 security findings.
func AuditEC2(ctx context.Context, cfg aws.Config) (Ec2AuditResults, error) {
	client := ec2.NewFromConfig(cfg)
	var results Ec2AuditResults

	// Volumes
	volumes, _ := AuditVolumes(ctx, client)
	results.Volumes = volumes

	// Instances
	instances, _ := AuditInstances(ctx, client)
	results.Instances = instances

	// SGs
	sgs, _ := AuditSecurityGroups(ctx, client)
	results.SecurityGroups = sgs

	// AMIs
	amis, _ := AuditImages(ctx, client)
	results.Images = amis

	// Snapshots
	snapshots, publicSnapshots, _ := AuditSnapshots(ctx, client)
	results.Snapshots = snapshots
	results.PublicSnapshots = publicSnapshots

	return results, nil
}

// func getPublicSubnets(ctx context.Context, client *ec2.Client) map[string]bool {
// 	publicSubnets := make(map[string]bool)
// 	subnetExplicitRT := make(map[string]string)
// 	rtIsPublic := make(map[string]bool)
// 	vpcMainRT := make(map[string]string)

// 	out, err := client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{})
// 	if err == nil {
// 		for _, rt := range out.RouteTables {
// 			isPub := false
// 			for _, r := range rt.Routes {
// 				if r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "igw-") {
// 					isPub = true
// 					break
// 				}
// 			}
// 			rtIsPublic[*rt.RouteTableId] = isPub

// 			for _, assoc := range rt.Associations {
// 				if assoc.Main != nil && *assoc.Main {
// 					if rt.VpcId != nil {
// 						vpcMainRT[*rt.VpcId] = *rt.RouteTableId
// 					}
// 				} else if assoc.SubnetId != nil {
// 					subnetExplicitRT[*assoc.SubnetId] = *rt.RouteTableId
// 				}
// 			}
// 		}
// 	}

// 	subOut, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
// 	if err == nil {
// 		for _, sub := range subOut.Subnets {
// 			subId := *sub.SubnetId
// 			rtId, ok := subnetExplicitRT[subId]
// 			if !ok {
// 				if sub.VpcId != nil {
// 					rtId = vpcMainRT[*sub.VpcId]
// 				}
// 			}
// 			publicSubnets[subId] = rtIsPublic[rtId]
// 		}
// 	}

// 	return publicSubnets
// }

func AuditVolumes(ctx context.Context, client *ec2.Client) ([]types.Volume, error) {
	var audits []types.Volume

	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, err
		}
		audits = append(audits, page.Volumes...)
	}

	return audits, nil
}

func AuditInstances(ctx context.Context, client *ec2.Client) ([]types.Instance, error) {
	var audits []types.Instance

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, err
		}
		for _, res := range page.Reservations {
			audits = append(audits, res.Instances...)
		}
	}

	return audits, nil
}

func AuditSecurityGroups(ctx context.Context, client *ec2.Client) ([]types.SecurityGroup, error) {
	var audits []types.SecurityGroup

	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, err
		}
		audits = append(audits, page.SecurityGroups...)
	}

	return audits, nil
}

func AuditImages(ctx context.Context, client *ec2.Client) ([]types.Image, error) {
	var audits []types.Image

	// DescribeImages doesn't have a paginator since it usually returns a big list in one go if requested by owner.
	out, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return audits, err
	}

	audits = append(audits, out.Images...)

	return audits, nil
}

func AuditSnapshots(ctx context.Context, client *ec2.Client) ([]types.Snapshot, []string, error) {
	var audits []types.Snapshot
	var publicSnapshots []string

	paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return audits, publicSnapshots, err
		}
		audits = append(audits, page.Snapshots...)
	}

	for _, snapshot := range audits {
		attr, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: snapshot.SnapshotId,
			Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
		})
		if err != nil {
			continue
		}
		for _, perm := range attr.CreateVolumePermissions {
			if perm.Group == types.PermissionGroupAll {
				publicSnapshots = append(publicSnapshots, *snapshot.SnapshotId)
				break
			}
		}
	}

	return audits, publicSnapshots, nil
}