package rules

import (
	"github.com/adigajjar/security-audit/scanner"
)

type ExtractorFunc func(data interface{}) []interface{}

var registry = map[string]ExtractorFunc{
	"open_ingress": extractIngressCidrs,
	"imdsv2_enforced": extractImdsv2Status,
	// "ami_vulnerability_count": extractAmiVulnCount,
	"ebs_encrypted": extractEbsEncryption,
	"snapshot_public": extractSnapshotPublic,
}

func extractIngressCidrs(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok{
		return nil
	}

	var results []interface{}

	for _, sg := range ec2.SecurityGroups{
		for _, perm := range sg.IpPermissions{
			for _, r := range perm.IpRanges{
				if r.CidrIp != nil{
					results = append(results, *r.CidrIp)
				}
			}
		}
	}
	return results
}

func extractImdsv2Status(data interface{}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}

	for _, instance := range ec2.Instances {
		enforced := false
		if instance.MetadataOptions != nil {
			if string(instance.MetadataOptions.HttpTokens) == "required" {
				enforced = true
			}
		}
		results = append(results, enforced)
	}

	return results
}


func extractEbsEncryption(data interface {}) []interface{} {
	ec2, ok := data.(scanner.Ec2AuditResults)
	if !ok {
		return nil
	}

	var results []interface{}

	for _, volume := range ec2.Volumes {
		if volume.Encrypted != nil {
			results = append(results, *volume.Encrypted)
		} else {
			results = append(results, false)
		}
	}

	return results
}

func extractSnapshotPublic(data interface{}) []interface{} {
    ec2, ok := data.(scanner.Ec2AuditResults)
    if !ok {
        return nil
    }

    var results []interface{}
    for _, snapshotId := range ec2.PublicSnapshots {
        results = append(results, snapshotId)
    }
    return results
}



// func extractAmiVulnCount(data interface{}) []interface{} {
// 	ec2, ok := data.(scanner.Ec2AuditResults)
// 	if !ok {
// 		return nil
// 	}

// 	var results []interface{}


// 	return results
// }